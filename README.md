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

**Policy signals:**

| Kind | Platforms | Why |
|---|---|---|
| `EXCLUSION_REMOVED` | YesWeHack | A non-qualifying bug class now pays. You can find it everywhere on that program. |
| `QUALIFYING_ADDED` | YesWeHack | New accepted vulnerability class. |
| `REWARD_UP` | YesWeHack | A reward grid cell went up, e.g. `default.critical: 5000 -> 7500`. |
| `POLICY_CHANGED` | YesWeHack | Rules or account-access text changed. The push shows the added lines. |
| `PROGRAM_UPDATED` | Intigriti | The program was edited. The public API doesn't say what, so open it and look. |

`[BONUS]` marks policy text that mentions bonuses, promotions, multipliers or campaigns.

**Negative signals:** one silent digest push per run. `PAUSED`, `PAUSED_OR_REMOVED`, `PAID_TO_VDP`,
`BOUNTY_DOWN`, `ASSET_REMOVED`, `ASSET_NO_LONGER_PAID`, `ASSET_TIER_DOWN`, `OOS_ADDED`,
`EXCLUSION_ADDED`, `QUALIFYING_REMOVED`, `REWARD_DOWN`.

## Sources

| Source | Gives |
|---|---|
| bounty-targets-data feed (all 4) | scope, out of scope, max bounty |
| Intigriti public program list | real open/suspended status, `lastUpdatedAt`, ~50 public programs the feed skips (login- or T&C-gated) |
| YesWeHack public API | status, full policy (rules, (non-)qualifying vulns, reward grids), fetched only when `last_update_at` changes |

The feed only lists open programs, so a paused program just disappears. On HackerOne and Bugcrowd bbwatch
remembers it, reports `PAUSED_OR_REMOVED` after 3 hours missing (to ignore feed glitches), and `REOPENED` if it
comes back. On Intigriti and YesWeHack the platform list reports status directly.

Not covered yet: Intigriti policy contents and scope of the feed-skipped programs (needs the Intigriti
researcher API token), HackerOne and Bugcrowd policy text.

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
