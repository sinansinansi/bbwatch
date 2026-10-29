#!/usr/bin/env python3
"""
bbwatch - breadth-first bug bounty change monitor.

Pulls the public scope dumps from arkadiyt/bounty-targets-data (refreshed ~every 30 min)
for HackerOne, Bugcrowd, Intigriti and YesWeHack, diffs them against the last snapshot,
and reports what changed, ranked by how useful each change is for a fast first pass:

  1. NEW_PROGRAM      - nobody has touched it yet
  2. NEW_ASSET        - new attack surface on an existing program (often the best signal:
                        the program is already triaging, the asset is not yet picked over)
  3. BOUNTY_UP        - more money for the same surface, invites renewed attention
  4. REOPENED         - program went from paused/closed back to open
  (REMOVED_* changes are logged but not alerted)

Anything that looks GenAI-related (HackerOne AI_MODEL assets, chat/llm/agent/copilot keywords)
is tagged [AI] so the LLM-testing track can filter on it.

Stdlib only. Config through env vars:
  BBWATCH_STATE        path to snapshot file          (default: state.json next to script)
  BBWATCH_REPORT_DIR   where markdown reports go      (default: reports/ next to script)
  BBWATCH_MIN_BOUNTY   ignore programs whose max bounty is below this (default 0; VDPs are
                       still included when 0 so you can choose)
  BBWATCH_BOUNTY_ONLY  "1" to drop programs that pay nothing
  NTFY_TOPIC           ntfy.sh topic for phone push (optional, no account needed)
  NTFY_SERVER          self-hosted ntfy server        (default: https://ntfy.sh)
  NTFY_MAX             max pushes per run             (default 15)
  DISCORD_WEBHOOK      Discord webhook URL (optional)
  TELEGRAM_TOKEN / TELEGRAM_CHAT_ID   Telegram bot alerts (optional)
"""
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEED = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{}_data.json"
PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack"]

STATE = Path(os.environ.get("BBWATCH_STATE", HERE / "state.json"))
REPORT_DIR = Path(os.environ.get("BBWATCH_REPORT_DIR", HERE / "reports"))
MIN_BOUNTY = float(os.environ.get("BBWATCH_MIN_BOUNTY", "0"))
BOUNTY_ONLY = os.environ.get("BBWATCH_BOUNTY_ONLY") == "1"
# Local testing: point at a directory of already-downloaded <platform>.json files.
LOCAL_FEED_DIR = os.environ.get("BBWATCH_LOCAL_FEED")
# Cap pushes per run so a big scope dump doesn't bury your phone.
NTFY_MAX = int(os.environ.get("NTFY_MAX", "15"))

AI_RE = re.compile(
    r"(?<![a-z])(ai|llm|gpt|genai|chat(bot)?|copilot|assistant|agent(s|ic)?|mcp|rag|"
    r"openai|anthropic|claude|gemini|prompt|ml|model)(?![a-z])",
    re.I,
)

PRIORITY = {"NEW_PROGRAM": 1, "NEW_ASSET": 2, "BOUNTY_UP": 3, "REOPENED": 4,
            "BOUNTY_DOWN": 8, "REMOVED_ASSET": 9, "REMOVED_PROGRAM": 9}
ALERT_KINDS = {"NEW_PROGRAM", "NEW_ASSET", "BOUNTY_UP", "REOPENED"}


# --------------------------------------------------------------------------- fetch

def fetch(platform):
    if LOCAL_FEED_DIR:
        with open(Path(LOCAL_FEED_DIR) / f"{platform}.json", encoding="utf-8") as f:
            return json.load(f)
    req = urllib.request.Request(FEED.format(platform), headers={"User-Agent": "bbwatch"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


# --------------------------------------------------------------------------- normalize
# Every program becomes:
#   key -> {platform, name, url, max_bounty, open, assets: {asset_id: asset_type}}

def _money(v):
    if isinstance(v, dict):
        v = v.get("value")
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def norm_hackerone(p):
    assets = {}
    for t in p["targets"]["in_scope"]:
        if not t.get("eligible_for_submission", True):
            continue
        typ = t["asset_type"] + ("" if t.get("eligible_for_bounty") else ":nobounty")
        assets[t["asset_identifier"]] = typ
    return p["handle"], {
        "name": p["name"], "url": p["url"],
        # H1 dump has no amounts; use 1 as "pays something" marker.
        "max_bounty": 1.0 if p.get("offers_bounties") else 0.0,
        "open": p.get("submission_state") == "open",
        "assets": assets,
    }


def norm_bugcrowd(p):
    assets = {(t.get("target") or t.get("uri") or t.get("name")): t.get("type", "")
              for t in p["targets"]["in_scope"]}
    return p["url"], {
        "name": p["name"], "url": p["url"],
        "max_bounty": _money(p.get("max_payout")),
        "open": True,
        "assets": {k: v for k, v in assets.items() if k},
    }


def norm_intigriti(p):
    assets = {}
    for t in p["targets"]["in_scope"]:
        ep = (t.get("endpoint") or "").strip()
        if ep:
            assets[ep] = (t.get("type") or "") + (":nobounty" if t.get("impact") == "No Bounty" else "")
    return f'{p["company_handle"]}/{p["handle"]}', {
        "name": p["name"], "url": p["url"],
        "max_bounty": _money(p.get("max_bounty")),
        "open": p.get("status") == "open",
        "assets": assets,
    }


def norm_yeswehack(p):
    return p["id"], {
        "name": p["name"], "url": f'https://yeswehack.com/programs/{p["id"]}',
        "max_bounty": _money(p.get("max_bounty")),
        "open": not p.get("disabled", False),
        "assets": {t["target"]: t.get("type", "") for t in p["targets"]["in_scope"] if t.get("target")},
    }


NORMALIZERS = {"hackerone": norm_hackerone, "bugcrowd": norm_bugcrowd,
               "intigriti": norm_intigriti, "yeswehack": norm_yeswehack}


def snapshot():
    snap = {}
    for plat in PLATFORMS:
        try:
            raw = fetch(plat)
        except Exception as e:  # one platform failing shouldn't kill the run
            print(f"[!] {plat}: {e}", file=sys.stderr)
            continue
        for p in raw:
            try:
                key, prog = NORMALIZERS[plat](p)
            except (KeyError, TypeError) as e:
                print(f"[!] {plat}: skipped malformed program ({e})", file=sys.stderr)
                continue
            prog["platform"] = plat
            snap[f"{plat}:{key}"] = prog
    return snap


# --------------------------------------------------------------------------- diff

def is_ai(text, asset_type=""):
    return "AI_MODEL" in asset_type or bool(AI_RE.search(text or ""))


def wanted(prog):
    if prog["max_bounty"] <= 0:
        return not BOUNTY_ONLY
    # H1 dump has no amounts, so MIN_BOUNTY can't be applied there
    return prog["platform"] == "hackerone" or prog["max_bounty"] >= MIN_BOUNTY


def diff(old, new):
    changes = []

    def add(kind, key, prog, detail="", ai=False):
        changes.append({"kind": kind, "key": key, "platform": prog["platform"], "name": prog["name"],
                        "url": prog["url"], "max_bounty": prog["max_bounty"], "detail": detail,
                        "ai": ai})

    for key, prog in new.items():
        if not wanted(prog):
            continue
        before = old.get(key)
        if before is None:
            ai = is_ai(prog["name"]) or any(is_ai(a, t) for a, t in prog["assets"].items())
            add("NEW_PROGRAM", key, prog, f'{len(prog["assets"])} assets', ai)
            continue
        for asset, typ in prog["assets"].items():
            if asset not in before["assets"]:
                add("NEW_ASSET", key, prog, f"{asset}  ({typ})", is_ai(asset, typ))
        for asset in before["assets"]:
            if asset not in prog["assets"]:
                add("REMOVED_ASSET", key, prog, asset)
        if prog["max_bounty"] > before["max_bounty"]:
            add("BOUNTY_UP", key, prog, f'{before["max_bounty"]:g} -> {prog["max_bounty"]:g}')
        elif prog["max_bounty"] < before["max_bounty"]:
            add("BOUNTY_DOWN", key, prog, f'{before["max_bounty"]:g} -> {prog["max_bounty"]:g}')
        if prog["open"] and not before["open"]:
            add("REOPENED", key, prog)

    for key, prog in old.items():
        if key not in new and wanted(prog):
            add("REMOVED_PROGRAM", key, prog)

    # AI-tagged first within each priority band, then by bounty
    changes.sort(key=lambda c: (PRIORITY[c["kind"]], not c["ai"], -c["max_bounty"]))
    return changes


# --------------------------------------------------------------------------- output

def fmt(c):
    tag = "[AI] " if c["ai"] else ""
    if c["max_bounty"] == 0:
        money = " VDP"
    elif c["platform"] == "hackerone":
        money = " $"
    else:
        money = f' max={c["max_bounty"]:g}'
    detail = f' - {c["detail"]}' if c["detail"] else ""
    return f'{tag}{c["kind"]} [{c["platform"]}] {c["name"]}{money}{detail}\n    {c["url"]}'


def write_report(changes, now):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / f"{now:%Y-%m-%d}.md"
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n## {now:%H:%M} UTC - {len(changes)} changes\n\n")
        for c in changes:
            f.write("- " + fmt(c).replace("\n    ", "  \n  ") + "\n")
    return path


def post_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "bbwatch"})
    urllib.request.urlopen(req, timeout=30).read()


def chunks(lines, limit):
    buf = ""
    for line in lines:
        if len(buf) + len(line) + 1 > limit:
            yield buf
            buf = ""
        buf += line + "\n"
    if buf:
        yield buf


def ntfy(changes):
    """One phone push per program, so tapping it opens that program's page."""
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        return
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    groups = {}
    for c in changes:
        if c["kind"] in ALERT_KINDS:
            groups.setdefault((c["kind"], c["key"]), []).append(c)
    items = list(groups.values())
    overflow = items[NTFY_MAX:]
    for group in items[:NTFY_MAX]:
        c = group[0]
        ai = any(g["ai"] for g in group)
        lines = [g["detail"] for g in group if g["detail"]]
        body = "\n".join(lines[:20]) + (f"\n+{len(lines) - 20} more" if len(lines) > 20 else "")
        money = "VDP" if c["max_bounty"] == 0 else ("bounty" if c["platform"] == "hackerone"
                                                     else f'max {c["max_bounty"]:g}')
        payload = {
            "topic": topic,
            "title": f'{"[AI] " if ai else ""}{c["kind"].replace("_", " ").title()}: {c["name"]}',
            "message": f'{c["platform"]} - {money}\n{body}'.strip(),
            "click": c["url"],
            "tags": ["robot"] if ai else ["mag"],
            "priority": 4 if c["kind"] == "NEW_PROGRAM" or ai else 3,
        }
        try:
            post_json(server, payload)
        except Exception as e:
            print(f"[!] ntfy failed: {e}", file=sys.stderr)
    if overflow:
        try:
            post_json(server, {"topic": topic, "title": f"+{len(overflow)} more programs changed",
                               "message": "See the reports/ folder in your GitHub repo.", "priority": 2})
        except Exception as e:
            print(f"[!] ntfy failed: {e}", file=sys.stderr)


def alert(changes):
    ntfy(changes)
    hot = [fmt(c) for c in changes if c["kind"] in ALERT_KINDS]
    if not hot:
        return
    hook = os.environ.get("DISCORD_WEBHOOK")
    tg_token, tg_chat = os.environ.get("TELEGRAM_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    for msg in chunks(hot, 1900):
        try:
            if hook:
                post_json(hook, {"content": msg})
            if tg_token and tg_chat:
                post_json(f"https://api.telegram.org/bot{tg_token}/sendMessage",
                          {"chat_id": tg_chat, "text": msg, "disable_web_page_preview": True})
        except Exception as e:
            print(f"[!] alert failed: {e}", file=sys.stderr)


# --------------------------------------------------------------------------- main

def save(snap):
    # sorted + one item per line so git stores small diffs between runs
    STATE.write_text(json.dumps(snap, sort_keys=True, indent=0), encoding="utf-8")


def test_alert():
    alert([{"kind": "NEW_PROGRAM", "key": "test", "platform": "bbwatch", "name": "Test alert",
            "url": "https://github.com/arkadiyt/bounty-targets-data", "max_bounty": 1000,
            "detail": "If you can read this on your phone, alerts work.", "ai": False}])
    print("[+] test alert sent to every configured channel")


def main():
    if "--test-alert" in sys.argv:
        return test_alert()
    now = datetime.now(timezone.utc)
    new = snapshot()
    if not new:
        sys.exit("[!] no data fetched")
    if not STATE.exists():
        save(new)
        print(f"[+] baseline saved: {len(new)} programs. Next run reports changes.")
        return
    old = json.loads(STATE.read_text(encoding="utf-8"))
    # Platforms that failed this run keep their old data so they don't look "removed".
    fetched = {k.split(":", 1)[0] for k in new}
    for k, v in old.items():
        if k.split(":", 1)[0] not in fetched:
            new[k] = v
    changes = diff(old, new)
    save(new)
    if not changes:
        print("[=] no changes")
        return
    path = write_report(changes, now)
    for c in changes:
        if c["kind"] in ALERT_KINDS:
            print(fmt(c))
    print(f"[+] {len(changes)} changes -> {path}")
    alert(changes)


if __name__ == "__main__":
    main()
