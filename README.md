# bbwatch

Watches every **public** program on HackerOne, Bugcrowd, Intigriti and YesWeHack every 30 minutes and pushes
scope and policy changes to your phone.

**Positive signals:** one push per program, with sound. Tapping it opens the program.

| Kind | Platforms | Why it matters for breadth hunting |
|---|---|---|
| `NEW_PROGRAM` | all | Zero prior public reports (includes private → public launches). |
| `VDP_TO_PAID` | all | Starts paying. VDP testers were few, so plenty is left. |
| `OOS_TO_IN_SCOPE` | all | Previously excluded surface, never tested on this program. |
| `NEW_WILDCARD` | all | A whole subdomain space opens. |
| `NEW_ASSET_TYPE` | all | First API / mobile app / repo / AI model on the program. |
| `REOPENED` | all | Back after a pause. Code shipped while nobody was testing. |
| `ASSET_NOW_PAID` | all | Same asset, now pays: H1 bounty flag, Intigriti tier, Bugcrowd moved out of an unpaid reward group, YesWeHack asset value now maps to a paid grid. |
| `NEW_ASSET` | all | New surface on a program that already triages and pays. |
| `OOS_REMOVED` | all | An exclusion was dropped. |
| `ASSET_TIER_UP` | Intigriti, Bugcrowd, YesWeHack | Asset moved to a better-paying tier / reward group / asset value, e.g. `api.x.com  LOW (max 500) -> HIGH (max 3000)`. |
| `BOUNTY_UP` | not H1 | Same surface, more money. |

**Policy signals:**

| Kind | Platforms | Why |
|---|---|---|
| `EXCLUSION_REMOVED` | YesWeHack, HackerOne, Bugcrowd (VRT rules) | A non-qualifying bug class now pays. You can find it everywhere on that program. |
| `QUALIFYING_ADDED` | YesWeHack | New accepted vulnerability class. |
| `REWARD_UP` | YesWeHack, Bugcrowd | A reward cell went up, e.g. `default.critical: 5000 -> 7500` or `Primary Target Group.P1: 4500 -> 8000`. |
| `POLICY_CHANGED` | all (Intigriti with token) | Policy text changed. The push shows added (`+`) **and removed (`-`) lines**: exclusions are often bullet points that just disappear. Intigriti also reports testing requirement changes (rate limit, user agent, safe harbour). Bugcrowd pushes open Bugcrowd's own changelog page for that version, which shows the full diff. |
| `ANNOUNCEMENT` | Bugcrowd | New program announcement (went public, reward changes, promotions). |
| `PROGRAM_UPDATED` | Intigriti (no token) | The program was edited. The public list doesn't say what, so open it and look. |

`[BONUS]` marks policy text that mentions bonuses, promotions, multipliers or campaigns. `[AI]` marks HackerOne
`AI_MODEL` assets or names/hosts/text matching llm/chat/agent/mcp/copilot/etc. Both always push at high priority.

**Negative signals:** one silent digest push per run. `PAUSED`, `PAUSED_OR_REMOVED`, `PAID_TO_VDP`,
`BOUNTY_DOWN`, `ASSET_REMOVED`, `ASSET_NO_LONGER_PAID`, `ASSET_TIER_DOWN`, `OOS_ADDED`,
`EXCLUSION_ADDED`, `QUALIFYING_REMOVED`, `REWARD_DOWN`.

**`WARNING` pushes** mean bbwatch itself needs attention: a source failing several runs in a row, an expired
token, Bugcrowd answering 403/429, or the fallback feed not changing for a day. Without these, a dead source would
look exactly like "no changes".

## Sources

Every program is checked on every run. Each platform is read from its own API; the
[bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) feed is only the fallback when a direct
source fails. Switching source (either way) re-baselines that platform silently.

| Platform | Source | Gives |
|---|---|---|
| HackerOne | Hacker API (`H1_USERNAME` + `H1_TOKEN`) | ~600 public programs incl. paused ones, open/paused status and policy text every run; structured scopes of open programs; scope exclusions when the policy text changed, else every 6h. H1 answers 429 well below its documented 600 reads/min, so requests go at 1/s within a 5-minute budget per run and stop at the first 429: programs whose feed scope just changed go first, then the least recently refreshed (40-100 programs per run observed, so every open program is re-read every few hours; programs without a fresh read keep their last API scope). |
| Bugcrowd | public engagement JSON (no account) | bug bounties **and ~220 VDPs** (the feed has no VDPs), latest brief version per engagement (targets per reward group, reward ranges, VRT exclusion rules, brief text, safe harbor), announcements. A version is only fetched when its changelog id moves. Stops and warns on 403/429. |
| Intigriti | researcher API (`INTIGRITI_TOKEN`) | every program your account can see (~230), scope with tiers, rules of engagement + testing requirements, real status. Its activity log means only changed programs are re-fetched. Falls back to the public list without a token. |
| YesWeHack | public API (no account) | every program's detail each run: scope with asset value levels (and per-scope report counts), rules, (non-)qualifying vulns, reward grids |

Intigriti and HackerOne programs that flip suspended → open after less than 3 days (report caps resetting; some
do it daily) are logged as `REOPENED_BRIEF` in the report only. After a longer suspension they push `REOPENED`.

Bugcrowd's public data has no pause status: a Bugcrowd program that disappears is reported as `PAUSED_OR_REMOVED`
after 3 hours (to ignore glitches), and as `REOPENED` if it comes back.

Not covered: HackerOne and Intigriti bounty tables (not in their APIs), structured promotions/campaigns (only
caught as `[BONUS]` text).

## Setup

See **[SETUP.md](SETUP.md)**: phone push via ntfy, secrets, and the reliable 30-minute trigger.

Alert channels (set any as repo secrets): `NTFY_TOPIC` (phone push, recommended), `DISCORD_WEBHOOK`,
`TELEGRAM_TOKEN` + `TELEGRAM_CHAT_ID`.

State and daily reports are kept in the Actions cache, never in git: the repo is public and some program data is
login-only. When a run has more changes than fit in pushes, the full report is attached to a push.

## Local run

```
python bbwatch.py               # diff and alert
python bbwatch.py --test-alert  # just send a test push
```
