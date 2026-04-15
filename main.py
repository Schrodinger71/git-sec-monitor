import asyncio
import os
from typing import Optional

import aiohttp
import disnake
from disnake.ext import commands, tasks
from dotenv import load_dotenv

from monitor_core import GitHubFetcher, MonitorStorage, ScanResult, SecurityFinding, SecurityMonitor


load_dotenv()


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_repositories(raw_value: Optional[str]) -> list[str]:
    if not raw_value:
        return []
    normalized = raw_value.replace("\n", ",")
    return [item.strip() for item in normalized.split(",") if item.strip()]


def parse_int(value: Optional[str], default: int = 0) -> int:
    if value is None:
        return default
    normalized = value.strip()
    if not normalized:
        return default
    return int(normalized)


DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
CHANNEL_ID = parse_int(os.getenv("CHANNEL_ID"), default=0)
MENTION_USER_ID = parse_int(os.getenv("MENTION_USER_ID"), default=0)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORIES = parse_repositories(os.getenv("GITHUB_REPOSITORIES"))
CHECK_INTERVAL_MINUTES = parse_int(os.getenv("CHECK_INTERVAL_MINUTES"), default=15)
DB_PATH = os.getenv("MONITOR_DB_PATH", "data/github_monitor.db")
ALERT_ON_FIRST_RUN = parse_bool(os.getenv("ALERT_ON_FIRST_RUN"), default=False)


if not DISCORD_TOKEN:
    raise ValueError("DISCORD_TOKEN is required")
if not CHANNEL_ID:
    raise ValueError("CHANNEL_ID is required")
if not GITHUB_REPOSITORIES:
    raise ValueError("GITHUB_REPOSITORIES is required")


class MonitorBot(commands.InteractionBot):
    async def close(self) -> None:
        await close_resources()
        await super().close()


intents = disnake.Intents.default()
bot = MonitorBot(intents=intents)
scan_lock = asyncio.Lock()
monitor: Optional[SecurityMonitor] = None
http_session: Optional[aiohttp.ClientSession] = None
last_scan_result: Optional[ScanResult] = None


async def ensure_monitor() -> SecurityMonitor:
    global monitor, http_session

    if monitor is not None:
        return monitor

    timeout = aiohttp.ClientTimeout(total=30)
    http_session = aiohttp.ClientSession(timeout=timeout)
    fetcher = GitHubFetcher(session=http_session, token=GITHUB_TOKEN)
    storage = MonitorStorage(DB_PATH)
    monitor = SecurityMonitor(
        repositories=GITHUB_REPOSITORIES,
        fetcher=fetcher,
        storage=storage,
        alert_on_first_run=ALERT_ON_FIRST_RUN,
    )
    return monitor


async def get_target_channel() -> disnake.abc.Messageable:
    channel = bot.get_channel(CHANNEL_ID)
    if channel is None:
        channel = await bot.fetch_channel(CHANNEL_ID)
    return channel


def build_embed(finding: SecurityFinding) -> disnake.Embed:
    colors = {
        "critical": 0xD7263D,
        "high": 0xF46036,
        "medium": 0xF6AE2D,
        "low": 0x2E86AB,
    }
    embed = disnake.Embed(
        title=f"[{finding.severity.upper()}] {finding.item_type.replace('_', ' ')} in {finding.repo}",
        description=finding.summary,
        color=colors.get(finding.severity, 0x2E86AB),
    )
    embed.add_field(name="Title", value=finding.title[:1024], inline=False)
    embed.add_field(name="Repository", value=finding.repo, inline=True)
    embed.add_field(name="Score", value=f"{finding.score:.2f}", inline=True)
    embed.add_field(name="Type", value=finding.item_type, inline=True)
    embed.add_field(name="Reason", value=finding.reason[:1024], inline=False)
    terms = ", ".join(finding.matched_terms[:20]) if finding.matched_terms else "security pattern"
    embed.add_field(name="Matched terms", value=terms[:1024], inline=False)
    embed.add_field(name="Link", value=finding.url[:1024], inline=False)
    if finding.updated_at:
        embed.timestamp = disnake.utils.parse_time(finding.updated_at)
    return embed


def scan_summary_text(result: ScanResult) -> str:
    total_items = sum(summary.scanned_items for summary in result.summaries)
    total_repos = len(result.summaries)
    total_alerts = len(result.findings)
    duration = (result.finished_at - result.started_at).total_seconds()
    return (
        f"Repos: {total_repos}\n"
        f"Items scanned: {total_items}\n"
        f"New alerts: {total_alerts}\n"
        f"Duration: {duration:.1f}s"
    )


async def run_monitor_scan(trigger: str, send_empty_summary: bool = False) -> ScanResult:
    global last_scan_result

    service = await ensure_monitor()

    async with scan_lock:
        result = await service.scan_once()
        last_scan_result = result

    channel = await get_target_channel()
    mention_prefix = f"<@{MENTION_USER_ID}> " if MENTION_USER_ID else ""

    for finding in result.findings:
        await channel.send(content=f"{mention_prefix}New security signal detected", embed=build_embed(finding))

    if send_empty_summary or result.errors:
        details = [f"Trigger: {trigger}", scan_summary_text(result)]
        if result.errors:
            details.append("Errors:\n" + "\n".join(result.errors[:10]))
        await channel.send("\n\n".join(details))

    return result


@tasks.loop(minutes=CHECK_INTERVAL_MINUTES)
async def monitor_loop() -> None:
    try:
        result = await run_monitor_scan(trigger="scheduled", send_empty_summary=False)
        print(scan_summary_text(result))
        for error in result.errors:
            print(f"Monitor error: {error}")
    except Exception as exc:
        print(f"Scheduled scan failed: {exc}")


@monitor_loop.before_loop
async def before_monitor_loop() -> None:
    await bot.wait_until_ready()
    await ensure_monitor()


@bot.event
async def on_ready() -> None:
    print(f"Logged in as {bot.user}")
    if not monitor_loop.is_running():
        monitor_loop.start()


@bot.slash_command(description="Run GitHub security scan right now")
async def scan_now(inter: disnake.ApplicationCommandInteraction) -> None:
    if scan_lock.locked():
        await inter.response.send_message("Scan is already running.", ephemeral=True)
        return

    await inter.response.defer(ephemeral=True)
    result = await run_monitor_scan(trigger="manual", send_empty_summary=True)
    await inter.edit_original_response(f"Manual scan complete.\n\n{scan_summary_text(result)}")


@bot.slash_command(description="Show monitor status and counters")
async def monitor_status(inter: disnake.ApplicationCommandInteraction) -> None:
    service = await ensure_monitor()
    stats = service.get_statistics()
    lines = [
        f"Repositories configured: {stats['repositories']}",
        f"Repositories initialized: {stats['repos']}",
        f"Tracked items: {stats['tracked_items']}",
        f"Alerted items: {stats['alerted_items']}",
        f"Check interval: {CHECK_INTERVAL_MINUTES} min",
        f"Loop running: {'yes' if monitor_loop.is_running() else 'no'}",
    ]
    if last_scan_result is not None:
        lines.append(f"Last scan alerts: {len(last_scan_result.findings)}")
        lines.append(f"Last scan errors: {len(last_scan_result.errors)}")
    await inter.response.send_message("\n".join(lines), ephemeral=True)


@bot.slash_command(description="List repositories currently monitored")
async def monitor_repositories(inter: disnake.ApplicationCommandInteraction) -> None:
    await inter.response.send_message("\n".join(f"- {repo}" for repo in GITHUB_REPOSITORIES), ephemeral=True)


async def close_resources() -> None:
    global http_session
    if http_session and not http_session.closed:
        await http_session.close()


if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)
