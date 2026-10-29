# bbwatch

Watches HackerOne, Bugcrowd, Intigriti and YesWeHack **public** programs for changes and alerts on:

| Kind | Why it matters for breadth hunting |
|---|---|
| `NEW_PROGRAM` | Zero prior reports. Low-hanging fruit is still there. |
| `NEW_ASSET` | New surface on a program that already triages and pays. Usually the best signal. |
| `BOUNTY_UP` | Same surface, more money. Old dupes don't matter, but more competition is coming. |
| `REOPENED` | A paused program is back, often with code shipped while it was closed. |

Items tagged `[AI]` are HackerOne `AI_MODEL` assets or names/hosts matching llm/chat/agent/mcp/copilot/etc.

Data source: [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data), refreshed every 30 min.

## Setup

See **[SETUP.md](SETUP.md)**. It covers everything from zero accounts to phone push via ntfy and an hourly GitHub Actions run.

Alert channels (set any as repo secrets): `NTFY_TOPIC` (phone push, recommended), `DISCORD_WEBHOOK`,
`TELEGRAM_TOKEN` + `TELEGRAM_CHAT_ID`.

Snapshots (`state.json`) and daily reports (`reports/YYYY-MM-DD.md`) are committed back to the repo, so the git history doubles as a log.

## Local run

```
python bbwatch.py               # diff and alert
python bbwatch.py --test-alert  # just send a test push
```
