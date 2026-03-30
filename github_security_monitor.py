import os
import time
import sqlite3
import requests
from datetime import datetime
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Список репозиториев для отслеживания (owner/repo)
REPOSITORIES = [
    "space-wizards/RobustToolbox",
    # добавь ещё репозитории по необходимости
]


class GitHubFetcher:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        })

    def _fetch_paginated(self, url: str) -> List[Dict[str, Any]]:
        """Получить все страницы по URL, возвращает список элементов."""
        items = []
        while url:
            resp = self.session.get(url)
            if resp.status_code != 200:
                print(f"Ошибка API: {resp.status_code} - {resp.text}")
                break
            data = resp.json()
            if isinstance(data, list):
                items.extend(data)
            else:
                # некоторые эндпоинты возвращают объект с ключом 'items'
                items.extend(data.get("items", []))
            # Пагинация: ссылка 'next' в заголовке Link
            next_link = self._get_next_link(resp.headers.get("Link", ""))
            url = next_link
            # Соблюдаем лимиты
            time.sleep(0.5)
        return items

    def _get_next_link(self, link_header: str) -> Optional[str]:
        """Извлечь URL следующей страницы из заголовка Link."""
        if not link_header:
            return None
        parts = link_header.split(",")
        for part in parts:
            if 'rel="next"' in part:
                start = part.find("<") + 1
                end = part.find(">")
                if start > 0 and end > 0:
                    return part[start:end]
        return None

    def get_issues(self, repo: str) -> List[Dict[str, Any]]:
        """Получить все открытые issues (включая PR, если не фильтровать)."""
        url = f"https://api.github.com/repos/{repo}/issues?state=all&per_page=100"
        return self._fetch_paginated(url)

    def get_pull_requests(self, repo: str) -> List[Dict[str, Any]]:
        """Получить все пул-реквесты."""
        url = f"https://api.github.com/repos/{repo}/pulls?state=all&per_page=100"
        return self._fetch_paginated(url)

    def get_security_advisories(self, repo: str) -> List[Dict[str, Any]]:
        """Получить Security Advisories репозитория (требуется доступ)."""
        url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100"
        return self._fetch_paginated(url)

    def get_commits(self, repo: str) -> List[Dict[str, Any]]:
        """Получить последние коммиты (для простоты только последние 30)."""
        url = f"https://api.github.com/repos/{repo}/commits?per_page=30"
        return self._fetch_paginated(url)


class SecurityClassifier:
    def __init__(self, use_openai: bool = False, openai_key: Optional[str] = None):
        self.use_openai = use_openai
        if use_openai:
            if not openai_key:
                raise ValueError("OPENAI_API_KEY is required for OpenAI mode")
            import openai
            self.openai = openai
            self.openai.api_key = openai_key
        else:
            # Локальная zero-shot классификация
            from transformers import pipeline
            self.classifier = pipeline("zero-shot-classification",
                                        model="facebook/bart-large-mnli")

    def classify(self, text: str) -> Dict[str, float]:
        """
        Возвращает словарь с вероятностями для меток:
        'security_vulnerability', 'bug_fix', 'feature', 'other'
        """
        candidate_labels = [
            "security vulnerability",
            "security improvement",
            "bug fix",
            "feature",
            "other"
        ]
        if self.use_openai:
            # Используем OpenAI API
            prompt = f"""
            Classify the following GitHub issue/PR text into one of these categories:
            - security vulnerability
            - bug fix
            - feature
            - other

            Text: {text[:2000]}

            Category:
            """
            response = self.openai.Completion.create(
                model="text-davinci-003",
                prompt=prompt,
                max_tokens=10,
                temperature=0,
                logprobs=5
            )
            predicted = response.choices[0].text.strip().lower()
            scores = {label: 1.0 if label == predicted else 0.0 for label in candidate_labels}
        else:
            # Локальная zero-shot
            result = self.classifier(text, candidate_labels)
            scores = {label: score for label, score in zip(result['labels'], result['scores'])}
        return scores

class Deduplicator:
    def __init__(self, db_path: str = "github_monitor.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS processed (
                id TEXT PRIMARY KEY,
                repo TEXT,
                type TEXT,
                processed_at TIMESTAMP
            )
        """)

    def is_processed(self, item_id: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM processed WHERE id = ?", (item_id,))
        return cur.fetchone() is not None

    def mark_processed(self, item_id: str, repo: str, item_type: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO processed (id, repo, type, processed_at) VALUES (?, ?, ?, ?)",
            (item_id, repo, item_type, datetime.utcnow())
        )
        self.conn.commit()


class DiscordNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, message: str, embeds: List[Dict] = None):
        payload = {"content": message}
        if embeds:
            payload["embeds"] = embeds
        resp = requests.post(self.webhook_url, json=payload)
        if resp.status_code != 204:
            print(f"Ошибка отправки в Discord: {resp.status_code} {resp.text}")


class SecurityMonitor:
    def __init__(self, github_token: str, discord_webhook: str,
                 repositories: List[str], openai_key: Optional[str] = None,
                 use_openai: bool = False):
        self.fetcher = GitHubFetcher(github_token)
        self.deduplicator = Deduplicator()
        self.notifier = DiscordNotifier(discord_webhook)
        self.classifier = SecurityClassifier(use_openai=use_openai, openai_key=openai_key)
        self.repositories = repositories

    def _extract_text(self, item: Dict[str, Any]) -> str:
        """Извлекает текст для классификации из issue/PR/commit."""
        # Для issue/PR: title + body
        title = item.get("title", "")
        body = item.get("body", "")
        # Для commit
        commit = item.get("commit", {})
        message = commit.get("message", "")
        # Если есть description (security advisory)
        description = item.get("description", "")
        return f"{title}\n{body}\n{message}\n{description}".strip()

    def _get_item_id(self, item: Dict[str, Any], item_type: str) -> str:
        """Возвращает уникальный идентификатор элемента."""
        if item_type == "commit":
            # для commit используем sha
            return item.get("sha", "")
        elif item_type == "security_advisory":
            return item.get("ghsa_id", "")
        else:
            return str(item.get("id", ""))

    def _format_discord_message(self, item: Dict[str, Any], repo: str, item_type: str,
                                scores: Dict[str, float]) -> Dict:
        """Создаёт embed для Discord."""

        if item_type == "commit":
            url = f"https://github.com/{repo}/commit/{item.get('sha', '')}"
        else:
            url = item.get("html_url", "")

        # Определяем приоритет
        vuln_score = scores.get("security vulnerability", 0)
        if vuln_score > 0.7:
            priority = "🔴 CRITICAL"
        elif vuln_score > 0.3:
            priority = "🟡 HIGH"
        else:
            priority = "🟢 LOW"

        title = item.get("title", "")
        if not title and item_type == "commit":
            title = item.get("commit", {}).get("message", "").split("\n")[0][:100]

        description = self._extract_text(item)[:500]  # ограничим длину

        embed = {
            "title": f"{priority} {item_type.replace('_', ' ').title()}: {title}",
            "url": url,
            "description": description,
            "color": 0xff0000 if vuln_score > 0.3 else 0x00ff00,
            "fields": [
                {"name": "Репозиторий", "value": repo, "inline": True},
                {"name": "Тип", "value": item_type, "inline": True},
                {"name": "Score (vuln)", "value": f"{vuln_score:.2f}", "inline": True},
                {"name": "Детали классификации", "value": str(scores), "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
        return embed

    def process_item(self, item: Dict[str, Any], repo: str, item_type: str):
        item_id = self._get_item_id(item, item_type)
        if self.deduplicator.is_processed(item_id):
            return

        text = self._extract_text(item)
        # Сначала быстрая фильтрация по ключевым словам, чтобы не нагружать NLP
        keywords = ["security", "vulnerability", "cve", "xss", "rce", "sqli", "sanitize", "validate", "exploit", "attack", "vuln", "patch"]
        text_lower = text.lower()
        if not any(kw in text_lower for kw in keywords):
            return  # не похоже на безопасность

        # NLP-анализ
        scores = self.classifier.classify(text)
        if scores.get("security vulnerability", 0) < 0.2:
            # низкая вероятность уязвимости, пропускаем
            return

        # Отправляем уведомление
        embed = self._format_discord_message(item, repo, item_type, scores)
        self.notifier.send("⚠️ Обнаружена возможная уязвимость!", embeds=[embed])

        # Помечаем как обработанное
        self.deduplicator.mark_processed(item_id, repo, item_type)

    def run(self):
        for repo in self.repositories:
            print(f"Обрабатываю репозиторий {repo}")

            # Issues (включая PR, но PR будут дублироваться в отдельной выборке)
            issues = self.fetcher.get_issues(repo)
            for issue in issues:
                # Пропускаем PR, так как обработаем их отдельно
                if "pull_request" in issue:
                    continue
                self.process_item(issue, repo, "issue")

            prs = self.fetcher.get_pull_requests(repo)
            for pr in prs:
                self.process_item(pr, repo, "pull_request")

            commits = self.fetcher.get_commits(repo)
            for commit in commits:
                self.process_item(commit, repo, "commit")

            try:
                advisories = self.fetcher.get_security_advisories(repo)
                for adv in advisories:
                    self.process_item(adv, repo, "security_advisory")
            except Exception as e:
                print(f"Не удалось получить Security Advisories для {repo}: {e}")

            print(f"Репозиторий {repo} обработан.")


if __name__ == "__main__":
    monitor = SecurityMonitor(
        github_token=GITHUB_TOKEN,
        discord_webhook=DISCORD_WEBHOOK_URL,
        repositories=REPOSITORIES,
        openai_key=OPENAI_API_KEY,
        use_openai=bool(OPENAI_API_KEY)  # если ключ есть, используем OpenAI
    )
    monitor.run()
