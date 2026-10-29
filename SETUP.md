# bbwatch setup, from zero accounts

Total time: about 20 minutes. You need **one account (GitHub)** and **one phone app (ntfy)**.
The bug bounty platform accounts are separate (step 5), and the monitor does not need them.

Your ntfy topic (keep it private, since anyone who knows it can read and send to it):

```
bbwatch-7cd86d7d6af4d0ca540d667c
```

---

## 1. Phone: install ntfy (no account)

1. Install **ntfy** from the Play Store / App Store (publisher: Philipp Heckel).
2. Tap **+** → *Subscribe to topic* → paste the topic above → leave server as `ntfy.sh` → Subscribe.
3. Android: open the topic's settings and allow notifications. iOS: allow notifications when prompted.

Test it now from PowerShell on your PC:

```powershell
Invoke-RestMethod -Method Post -Uri https://ntfy.sh/bbwatch-7cd86d7d6af4d0ca540d667c -Body "hello from my PC"
```

Your phone should buzz within a few seconds.

## 2. GitHub account

1. Sign up at https://github.com/signup and verify your email.
2. Turn on 2FA (Settings → Password and authentication). You'll want this anyway, and so will the bounty platforms.
3. Settings → Emails → tick **Keep my email addresses private**. Copy the `...@users.noreply.github.com`
   address shown there. You'll use it in step 3.

## 3. Create the repo and push the code

1. On GitHub: **+** (top right) → *New repository* → name `bbwatch` → **Private** → do NOT add a README → Create.
2. In PowerShell, run this once to tell git who you are (use your GitHub username and the noreply email):

```powershell
git config --global user.name "YOUR_GITHUB_USERNAME"
git config --global user.email "YOUR_ID+YOUR_USERNAME@users.noreply.github.com"
```

3. Push the code (replace `YOUR_GITHUB_USERNAME`):

```powershell
cd $HOME\bugbountybd\bbwatch
git init -b main
git add .
git commit -m "bbwatch initial"
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/bbwatch.git
git push -u origin main
```

A browser window opens asking you to sign in to GitHub. That's Git Credential Manager, and you only do it once.

## 4. Connect the repo to your phone

1. Repo → **Settings** → *Secrets and variables* → **Actions** → *New repository secret*:
   - Name `NTFY_TOPIC`, value `bbwatch-7cd86d7d6af4d0ca540d667c`
2. Optional, on the **Variables** tab of the same page:
   - `BBWATCH_BOUNTY_ONLY` = `1` to skip VDPs (no-pay programs). Recommended once you have a few
     VDP points for reputation.
   - `BBWATCH_MIN_BOUNTY` = e.g. `500` to skip low-max programs (not applied to HackerOne, whose feed has no amounts).
3. Repo → **Actions** tab → enable workflows if asked → **bbwatch** → *Run workflow*:
   - First with **Only send a test notification** ticked. Your phone should get a "Test alert".
   - Then once with it unticked. This saves the baseline. From then on it runs every hour on its
     own and pushes only what changed.

Notes:
- Tapping a notification opens that program's page.
- `[AI]` in the title marks GenAI-looking assets. They get higher priority, so they ring louder.
- At most 15 pushes per run, then one "+N more" summary. The full list is in `reports/` in the repo.
- GitHub may delay scheduled runs by 5–20 min at busy times. That's normal.
- To stop it: Actions → bbwatch → ⋯ → *Disable workflow*.

## 5. Bug bounty platform accounts (for hunting, not for the monitor)

Sign up on each and turn on 2FA:

| Platform | Signup | Notes |
|---|---|---|
| HackerOne | https://hackerone.com/users/sign_up | Do the Hacker101 CTF for your first private invites. Also set up an API token later (Settings → API Token) for private-program monitoring. |
| Bugcrowd | https://bugcrowd.com/user/sign_up | Complete profile + "Bugcrowd University" to start getting invites. |
| Intigriti | https://login.intigriti.com/account/register | Requires ID verification before payouts. Personal access token available in settings. |
| YesWeHack | https://yeswehack.com/auth/register | KYC needed for payouts. |

Set up payout methods (PayPal/bank) and tax forms on each **before** your first valid report, since some
platforms hold payouts until that's done. Use a single password manager and unique passwords throughout.
