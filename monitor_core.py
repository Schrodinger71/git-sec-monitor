import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import aiohttp


ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SECURITY_THRESHOLD = 0.45


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_github_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, ISO_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def to_github_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(ISO_FORMAT)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def truncate(text: str, limit: int) -> str:
    compact = re.sub(r"\s+", " ", text or "").strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3].rstrip() + "..."


@dataclass
class SecurityFinding:
    item_uid: str
    repo: str
    item_type: str
    title: str
    url: str
    summary: str
    severity: str
    score: float
    matched_terms: List[str]
    reason: str
    updated_at: Optional[str]


@dataclass
class RepoScanSummary:
    repo: str
    scanned_items: int
    alerts_sent: int
    initialized: bool


@dataclass
class ScanResult:
    started_at: datetime
    finished_at: datetime
    findings: List[SecurityFinding]
    summaries: List[RepoScanSummary]
    errors: List[str]


class GitHubFetcher:
    def __init__(self, session: aiohttp.ClientSession, token: Optional[str] = None):
        self.session = session
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "git-sec-monitor-bot",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def _fetch_paginated(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        stop_before: Optional[datetime] = None,
        time_fields: Sequence[str] = (),
        max_pages: int = 5,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        next_url = url
        next_params = params
        pages = 0

        while next_url and pages < max_pages:
            async with self.session.get(next_url, headers=self.headers, params=next_params) as response:
                if response.status >= 400:
                    message = await response.text()
                    raise RuntimeError(f"GitHub API {response.status}: {message}")

                data = await response.json()
                page_items = data if isinstance(data, list) else data.get("items", [])
                items.extend(page_items)
                pages += 1

                if stop_before and time_fields:
                    oldest_value = self._oldest_time(page_items, time_fields)
                    if oldest_value and oldest_value < stop_before:
                        break

                next_url = self._get_next_link(response.headers.get("Link", ""))
                next_params = None

        return items

    def _oldest_time(self, items: Iterable[Dict[str, Any]], time_fields: Sequence[str]) -> Optional[datetime]:
        oldest: Optional[datetime] = None
        for item in items:
            value = self._extract_first_time(item, time_fields)
            if value and (oldest is None or value < oldest):
                oldest = value
        return oldest

    def _extract_first_time(self, item: Dict[str, Any], time_fields: Sequence[str]) -> Optional[datetime]:
        for field in time_fields:
            value: Any = item
            for part in field.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if value:
                parsed = parse_github_datetime(value)
                if parsed:
                    return parsed
        return None

    def _get_next_link(self, header: str) -> Optional[str]:
        if not header:
            return None
        for part in header.split(","):
            if 'rel="next"' in part:
                start = part.find("<") + 1
                end = part.find(">")
                if start > 0 and end > start:
                    return part[start:end]
        return None

    async def get_issues(self, repo: str, since: Optional[datetime]) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"state": "all", "sort": "updated", "direction": "desc", "per_page": 100}
        if since:
            params["since"] = to_github_datetime(since)
        return await self._fetch_paginated(
            f"https://api.github.com/repos/{repo}/issues",
            params=params,
            stop_before=since,
            time_fields=("updated_at",),
        )

    async def get_pull_requests(self, repo: str, since: Optional[datetime]) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"state": "all", "sort": "updated", "direction": "desc", "per_page": 100}
        pulls = await self._fetch_paginated(
            f"https://api.github.com/repos/{repo}/pulls",
            params=params,
            stop_before=since,
            time_fields=("updated_at",),
        )
        if since is None:
            return pulls
        return [
            item
            for item in pulls
            if self._extract_first_time(item, ("updated_at",))
            and self._extract_first_time(item, ("updated_at",)) >= since
        ]

    async def get_commits(self, repo: str, since: Optional[datetime]) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"per_page": 100}
        if since:
            params["since"] = to_github_datetime(since)
        return await self._fetch_paginated(
            f"https://api.github.com/repos/{repo}/commits",
            params=params,
            stop_before=since,
            time_fields=("commit.committer.date",),
        )

    async def get_security_advisories(self, repo: str) -> List[Dict[str, Any]]:
        try:
            return await self._fetch_paginated(
                f"https://api.github.com/repos/{repo}/security-advisories",
                params={"per_page": 100},
                max_pages=2,
            )
        except RuntimeError as exc:
            message = str(exc)
            if "404" in message or "403" in message:
                return []
            raise


class SecurityAnalyzer:
    HIGH_CONFIDENCE_TERMS = {
        "cve-": 0.45,
        "ghsa-": 0.45,
        "remote code execution": 0.45,
        "arbitrary code execution": 0.45,
        "authentication bypass": 0.40,
        "auth bypass": 0.40,
        "privilege escalation": 0.40,
        "sql injection": 0.40,
        "command injection": 0.40,
        "path traversal": 0.40,
        "directory traversal": 0.40,
        "deserialization": 0.35,
        "cross-site scripting": 0.35,
        "xss": 0.35,
        "csrf": 0.35,
        "ssrf": 0.35,
        "rce": 0.35,
        "hardcoded secret": 0.35,
        "token leak": 0.35,
        "sandbox escape": 0.45,
        "cwe-": 0.35,
    }
    MEDIUM_CONFIDENCE_TERMS = {
        "security": 0.15,
        "vulnerability": 0.20,
        "exploit": 0.20,
        "attack": 0.15,
        "inject": 0.15,
        "sanitize": 0.10,
        "validate": 0.10,
        "unsafe": 0.10,
        "permission": 0.10,
        "secret": 0.12,
        "credential": 0.15,
        "denial of service": 0.20,
        "dos": 0.10,
        "redos": 0.20,
        "buffer overflow": 0.30,
        "overflow": 0.15,
        "oob": 0.15,
    }
    SECURITY_LABEL_TERMS = ("security", "vulnerability", "cve", "ghsa", "exploit")
    NEGATIVE_TERMS = ("docs", "documentation", "readme", "comment", "typo", "refactor", "test only")
    FIX_TERMS = ("fix", "patch", "mitigate", "prevent", "protect", "harden", "sanitize")

    def analyze(self, repo: str, item_type: str, item: Dict[str, Any]) -> Optional[SecurityFinding]:
        title = self.extract_title(item, item_type)
        url = self.extract_url(repo, item_type, item)
        text = self.extract_text(item)
        lowered = text.lower()

        score = 0.0
        matched_terms: List[str] = []
        reasons: List[str] = []

        if item_type == "security_advisory":
            score += 0.95
            reasons.append("official GitHub security advisory")

        for term, value in self.HIGH_CONFIDENCE_TERMS.items():
            if term in lowered:
                score += value
                matched_terms.append(term)

        for term, value in self.MEDIUM_CONFIDENCE_TERMS.items():
            if term in lowered:
                score += value
                matched_terms.append(term)

        labels = [label.get("name", "") for label in item.get("labels", []) if isinstance(label, dict)]
        if any(any(term in label.lower() for term in self.SECURITY_LABEL_TERMS) for label in labels):
            score += 0.25
            reasons.append("security-related label")

        if any(term in lowered for term in self.FIX_TERMS) and any(term in lowered for term in ("security", "vulnerability", "cve", "ghsa", "exploit")):
            score += 0.15
            reasons.append("security fix wording")

        if any(term in lowered for term in self.NEGATIVE_TERMS) and not matched_terms:
            score -= 0.10

        score = max(0.0, min(score, 1.0))
        if score < SECURITY_THRESHOLD:
            return None

        matched_terms = sorted(set(matched_terms))
        severity = self.severity_from_score(item_type, item, score, matched_terms)
        summary = truncate(text, 350) or title
        reason = ", ".join(reasons) if reasons else "matched security terminology"
        updated_at = self.extract_updated_at(item, item_type)
        item_uid = f"{item_type}:{self.extract_item_id(item, item_type)}"

        return SecurityFinding(
            item_uid=item_uid,
            repo=repo,
            item_type=item_type,
            title=title,
            url=url,
            summary=summary,
            severity=severity,
            score=score,
            matched_terms=matched_terms,
            reason=reason,
            updated_at=updated_at,
        )

    def extract_text(self, item: Dict[str, Any]) -> str:
        parts = [
            item.get("title", ""),
            item.get("body", ""),
            item.get("description", ""),
            item.get("summary", ""),
            item.get("advisory", ""),
        ]
        commit = item.get("commit", {})
        if isinstance(commit, dict):
            parts.append(commit.get("message", ""))
        labels = [label.get("name", "") for label in item.get("labels", []) if isinstance(label, dict)]
        parts.extend(labels)
        return "\n".join(part for part in parts if part)

    def compute_fingerprint(self, repo: str, item_type: str, item: Dict[str, Any]) -> str:
        payload = {
            "repo": repo,
            "type": item_type,
            "id": self.extract_item_id(item, item_type),
            "title": self.extract_title(item, item_type),
            "body": item.get("body", ""),
            "description": item.get("description", ""),
            "summary": item.get("summary", ""),
            "labels": [label.get("name", "") for label in item.get("labels", []) if isinstance(label, dict)],
            "state": item.get("state", ""),
            "updated_at": self.extract_updated_at(item, item_type),
            "commit_message": item.get("commit", {}).get("message", "") if isinstance(item.get("commit"), dict) else "",
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def extract_item_id(self, item: Dict[str, Any], item_type: str) -> str:
        if item_type == "commit":
            return item.get("sha", "")
        if item_type == "security_advisory":
            return item.get("ghsa_id", "") or str(item.get("id", ""))
        return str(item.get("id", ""))

    def extract_title(self, item: Dict[str, Any], item_type: str) -> str:
        if item_type == "commit":
            message = item.get("commit", {}).get("message", "")
            first_line = message.splitlines()[0] if message else "Untitled commit"
            return truncate(first_line, 120)
        if item_type == "security_advisory":
            return item.get("summary") or item.get("title") or item.get("ghsa_id") or "GitHub Security Advisory"
        return item.get("title") or "Untitled item"

    def extract_url(self, repo: str, item_type: str, item: Dict[str, Any]) -> str:
        if item_type == "commit":
            return f"https://github.com/{repo}/commit/{item.get('sha', '')}"
        return item.get("html_url") or item.get("url") or f"https://github.com/{repo}"

    def extract_updated_at(self, item: Dict[str, Any], item_type: str) -> Optional[str]:
        if item_type == "commit":
            commit = item.get("commit", {})
            if isinstance(commit, dict):
                committer = commit.get("committer", {})
                if isinstance(committer, dict):
                    return committer.get("date")
        for field in ("updated_at", "published_at", "created_at"):
            if item.get(field):
                return item.get(field)
        return None

    def severity_from_score(
        self,
        item_type: str,
        item: Dict[str, Any],
        score: float,
        matched_terms: Sequence[str],
    ) -> str:
        advisory_severity = str(item.get("severity", "")).lower()
        if advisory_severity in {"critical", "high", "medium", "low"}:
            return advisory_severity
        if item_type == "security_advisory":
            return "high"
        if any(term in matched_terms for term in ("cve-", "ghsa-", "remote code execution", "arbitrary code execution", "authentication bypass", "privilege escalation")):
            return "critical"
        if score >= 0.75:
            return "high"
        if score >= 0.55:
            return "medium"
        return "low"


class MonitorStorage:
    def __init__(self, db_path: str):
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._setup()

    def _setup(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS repo_state (
                repo TEXT PRIMARY KEY,
                initialized INTEGER NOT NULL DEFAULT 0,
                last_scan_at TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS item_state (
                item_uid TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                item_type TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                last_score REAL NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_alerted_at TEXT,
                url TEXT,
                title TEXT
            )
            """
        )
        self.conn.commit()

    def get_repo_state(self, repo: str) -> Dict[str, Any]:
        row = self.conn.execute("SELECT initialized, last_scan_at FROM repo_state WHERE repo = ?", (repo,)).fetchone()
        if row is None:
            return {"initialized": False, "last_scan_at": None}
        return {"initialized": bool(row["initialized"]), "last_scan_at": row["last_scan_at"]}

    def update_repo_state(self, repo: str, initialized: bool, last_scan_at: datetime) -> None:
        self.conn.execute(
            """
            INSERT INTO repo_state (repo, initialized, last_scan_at)
            VALUES (?, ?, ?)
            ON CONFLICT(repo) DO UPDATE SET
                initialized = excluded.initialized,
                last_scan_at = excluded.last_scan_at
            """,
            (repo, 1 if initialized else 0, iso_utc(last_scan_at)),
        )
        self.conn.commit()

    def get_item_state(self, item_uid: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT fingerprint, last_score, last_alerted_at FROM item_state WHERE item_uid = ?",
            (item_uid,),
        ).fetchone()

    def upsert_item_state(
        self,
        item_uid: str,
        repo: str,
        item_type: str,
        fingerprint: str,
        score: float,
        title: str,
        url: str,
        alerted: bool,
    ) -> None:
        now = iso_utc(utcnow())
        last_alerted_at = now if alerted else None
        self.conn.execute(
            """
            INSERT INTO item_state (
                item_uid, repo, item_type, fingerprint, last_score, last_seen_at, last_alerted_at, url, title
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(item_uid) DO UPDATE SET
                repo = excluded.repo,
                item_type = excluded.item_type,
                fingerprint = excluded.fingerprint,
                last_score = excluded.last_score,
                last_seen_at = excluded.last_seen_at,
                last_alerted_at = CASE
                    WHEN excluded.last_alerted_at IS NOT NULL THEN excluded.last_alerted_at
                    ELSE item_state.last_alerted_at
                END,
                url = excluded.url,
                title = excluded.title
            """,
            (item_uid, repo, item_type, fingerprint, score, now, last_alerted_at, url, title),
        )
        self.conn.commit()

    def get_statistics(self) -> Dict[str, int]:
        repos = self.conn.execute("SELECT COUNT(*) FROM repo_state").fetchone()[0]
        tracked_items = self.conn.execute("SELECT COUNT(*) FROM item_state").fetchone()[0]
        alerted_items = self.conn.execute("SELECT COUNT(*) FROM item_state WHERE last_alerted_at IS NOT NULL").fetchone()[0]
        return {"repos": repos, "tracked_items": tracked_items, "alerted_items": alerted_items}


class SecurityMonitor:
    def __init__(
        self,
        repositories: Sequence[str],
        fetcher: GitHubFetcher,
        storage: MonitorStorage,
        analyzer: Optional[SecurityAnalyzer] = None,
        alert_on_first_run: bool = False,
    ):
        self.repositories = list(dict.fromkeys(repo.strip() for repo in repositories if repo.strip()))
        self.fetcher = fetcher
        self.storage = storage
        self.analyzer = analyzer or SecurityAnalyzer()
        self.alert_on_first_run = alert_on_first_run

    async def scan_once(self) -> ScanResult:
        started_at = utcnow()
        findings: List[SecurityFinding] = []
        summaries: List[RepoScanSummary] = []
        errors: List[str] = []

        for repo in self.repositories:
            try:
                repo_findings, summary = await self.scan_repo(repo)
                findings.extend(repo_findings)
                summaries.append(summary)
            except Exception as exc:
                errors.append(f"{repo}: {exc}")

        finished_at = utcnow()
        return ScanResult(
            started_at=started_at,
            finished_at=finished_at,
            findings=findings,
            summaries=summaries,
            errors=errors,
        )

    async def scan_repo(self, repo: str) -> Tuple[List[SecurityFinding], RepoScanSummary]:
        state = self.storage.get_repo_state(repo)
        last_scan_at = self.parse_iso_datetime(state["last_scan_at"])
        initialized = state["initialized"]

        findings: List[SecurityFinding] = []
        scanned_items = 0

        issues = [item for item in await self.fetcher.get_issues(repo, last_scan_at) if "pull_request" not in item]
        pulls = await self.fetcher.get_pull_requests(repo, last_scan_at)
        commits = await self.fetcher.get_commits(repo, last_scan_at)
        advisories = await self.fetcher.get_security_advisories(repo)

        item_stream: List[Tuple[str, Dict[str, Any]]] = []
        item_stream.extend(("issue", item) for item in issues)
        item_stream.extend(("pull_request", item) for item in pulls)
        item_stream.extend(("commit", item) for item in commits)
        item_stream.extend(("security_advisory", item) for item in advisories)

        for item_type, item in item_stream:
            if item_type == "security_advisory" and last_scan_at:
                published_at = parse_github_datetime(item.get("published_at") or item.get("updated_at"))
                if published_at and published_at < last_scan_at:
                    continue

            scanned_items += 1
            finding = self.process_item(repo, item_type, item, initialized)
            if finding:
                findings.append(finding)

        self.storage.update_repo_state(repo, True, utcnow())
        summary = RepoScanSummary(
            repo=repo,
            scanned_items=scanned_items,
            alerts_sent=len(findings),
            initialized=initialized,
        )
        return findings, summary

    def process_item(
        self,
        repo: str,
        item_type: str,
        item: Dict[str, Any],
        initialized: bool,
    ) -> Optional[SecurityFinding]:
        title = self.analyzer.extract_title(item, item_type)
        url = self.analyzer.extract_url(repo, item_type, item)
        fingerprint = self.analyzer.compute_fingerprint(repo, item_type, item)
        item_uid = f"{item_type}:{self.analyzer.extract_item_id(item, item_type)}"
        previous = self.storage.get_item_state(item_uid)

        if previous and previous["fingerprint"] == fingerprint:
            return None

        finding = self.analyzer.analyze(repo, item_type, item)
        score = finding.score if finding else 0.0
        was_security = bool(previous and float(previous["last_score"]) >= SECURITY_THRESHOLD)
        should_alert = bool(finding and (self.alert_on_first_run or initialized) and not was_security)

        self.storage.upsert_item_state(
            item_uid=item_uid,
            repo=repo,
            item_type=item_type,
            fingerprint=fingerprint,
            score=score,
            title=title,
            url=url,
            alerted=should_alert,
        )

        if should_alert:
            return finding
        return None

    def get_statistics(self) -> Dict[str, int]:
        stats = self.storage.get_statistics()
        stats["repositories"] = len(self.repositories)
        return stats

    def parse_iso_datetime(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
