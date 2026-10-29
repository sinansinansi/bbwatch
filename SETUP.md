# bbwatch setup

This repo is **public**, so nothing secret or account-restricted lives in it:
- Tokens, the ntfy topic and webhooks are **repository secrets**.
- Program state and reports live in the **Actions cache**, which only this repo's workflows can read.
  Some of that data (e.g. Intigriti programs visible only to logged-in researchers) must not be published.
- Never commit `state.json`, `data/` or `reports/`. `.gitignore` already excludes them.

## 1. Phone: ntfy (no account)

1. Install **ntfy** from the Play Store / App Store (publisher: Philipp Heckel).
2. Make a random topic name. Anyone who knows it can read and send to it, so keep it out of the repo:

   ```powershell
   "bbwatch-" + -join ((1..24) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
   ```

3. In the app: **+** → paste the topic → server `ntfy.sh` → Subscribe. Allow notifications
   (Android: also set battery usage for ntfy to *Unrestricted*).

## 2. Secrets

Repo → **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Value | Needed for |
|---|---|---|
| `NTFY_TOPIC` | your topic from step 1 | phone pushes |
| `INTIGRITI_TOKEN` | Intigriti → Settings → Personal access tokens | Intigriti scope/policy for every program you can see |
| `H1_USERNAME`, `H1_TOKEN` | HackerOne → Settings → API Token (identifier + token) | HackerOne policy, exclusions, paused programs |

YesWeHack and Bugcrowd need nothing.

Optional **Variables** (same page, Variables tab): `BBWATCH_BOUNTY_ONLY=1` skips VDPs, and
`BBWATCH_MIN_BOUNTY=500` skips low-max programs (except HackerOne, whose data has no amounts).

## 3. Reliable 30-minute schedule

GitHub's own `schedule:` is best-effort (runs are often late or skipped, especially on new repos). It stays in
the workflow as a backup. The reliable trigger is an external cron that starts the workflow through GitHub's API.

**a. A token that can only start this workflow.** GitHub → your avatar → **Settings → Developer settings →
Personal access tokens → Fine-grained tokens → Generate new token**:
- Name `bbwatch-trigger`, expiration up to 1 year (put a reminder in your calendar)
- Repository access: **Only select repositories** → `bbwatch`
- Permissions → Repository → **Actions: Read and write** (everything else stays "No access")

**b. cron-job.org** (free): create an account → **Create cronjob**:
- URL: `https://api.github.com/repos/<your-username>/bbwatch/actions/workflows/bbwatch.yml/dispatches`
- Schedule: every 30 minutes, at minutes **10 and 40** (just after the scope feed refreshes)
- **Advanced** tab:
  - Request method: **POST**
  - Headers:
    - `Authorization`: `Bearer <the token from step a>`
    - `Accept`: `application/vnd.github+json`
    - `X-GitHub-Api-Version`: `2022-11-28`
    - `Content-Type`: `application/json`
  - Request body: `{"ref":"main"}`
- Notifications: turn on **notify on failure**, so you hear about it when the token expires.
- Save, then **Test run**. A `204 No Content` response means it worked, and a new run appears in the Actions tab.

## 4. First runs

Actions → **bbwatch** → *Run workflow*:
1. With **Only send a test notification** ticked → your phone gets "Test alert".
2. Unticked → saves the baseline silently. After that every run pushes only what changed.

## Notes

- Tapping a notification opens that program's page.
- `[AI]` marks GenAI-looking assets/text and `[BONUS]` marks bonus or promotion text. Both ring loudly.
- Max 15 pushes per run. Beyond that you get one push with the full report attached (ntfy.sh keeps
  attachments for about 3 hours).
- `WARNING` pushes mean bbwatch itself needs attention, e.g. an expired token.
- To stop it: disable the cron-job.org job and Actions → bbwatch → ⋯ → *Disable workflow*.
- Losing the cache (e.g. after 7 days without runs) just means the next run re-baselines silently.
