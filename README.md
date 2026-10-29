# bbwatch

Watches HackerOne, Bugcrowd, Intigriti and YesWeHack **public** programs for changes and alerts on:

**Positive signals:** one push per program, with sound. Tapping it opens the program.

| Kind | Platforms | Why it matters for breadth hunting |
|---|---|---|
| `NEW_PROGRAM` | all | Zero prior public reports (includes private → public launches). |
| `VDP_TO_PAID` | all | Starts paying. VDP testers were few, so plenty is left. |
| `OOS_TO_IN_SCOPE` | all | Previously excluded surface, never tested on this program. |
| `NEW_WILDCARD` | all | A whole subdomain space opens. |
| `NEW_ASSET_TYPE` | all | First API / mobile app / repo / AI model on the program. |
| `REOPENED` | all | Back after a pause. Code shipped while nobody was testing. |
| `ASSET_NOW_PAID` | H1, Intigriti | Same host, now pays. |
| `NEW_ASSET` | all | New surface on a program that already triages and pays. |
| `OOS_REMOVED` | all | An exclusion was dropped. |
| `ASSET_TIER_UP` | Intigriti | Asset moved to a better-paying tier. |
| `BOUNTY_UP` | not H1 | Same surface, more money. |

**Negative signals:** one silent digest push per run. `PAUSED_OR_REMOVED`, `PAID_TO_VDP`,
`BOUNTY_DOWN`, `ASSET_REMOVED`, `ASSET_NO_LONGER_PAID`, `ASSET_TIER_DOWN`, `OOS_ADDED`.

The feed only lists open programs, so a paused program just disappears. bbwatch remembers it,
reports `PAUSED_OR_REMOVED` after it's been gone for 3 hours (to ignore feed glitches), and `REOPENED` if it comes back.

Items tagged `[AI]` are HackerOne `AI_MODEL` assets or names/hosts matching llm/chat/agent/mcp/copilot/etc.
They always push at high priority.

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
