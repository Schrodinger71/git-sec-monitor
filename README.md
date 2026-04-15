# git-sec-monitor

Discord bot for GitHub security monitoring.

## Features

- Monitors issues, pull requests, commits, and GitHub security advisories
- Detects new security-related items with heuristic analysis
- Stores state in SQLite to avoid duplicate alerts
- Sends notifications to a Discord channel
- Supports manual scans with slash commands
- Ready for Docker deployment

## Environment

Copy `.env.example` to `.env` and fill in:

- `DISCORD_TOKEN`
- `CHANNEL_ID`
- `GITHUB_REPOSITORIES`
- `GITHUB_TOKEN` recommended for higher GitHub API limits

Optional:

- `MENTION_USER_ID`
- `CHECK_INTERVAL_MINUTES`
- `MONITOR_DB_PATH`
- `ALERT_ON_FIRST_RUN`

## Run locally

```bash
pip install -r requirements.txt
python main.py
```

## Run with Docker

```bash
docker compose up -d --build
```

## Slash commands

- `/scan_now`
- `/monitor_status`
- `/monitor_repositories`
