#!/usr/bin/env python3
"""
bbwatch - breadth-first bug bounty change monitor.

Pulls the public scope dumps from arkadiyt/bounty-targets-data (refreshed ~every 30 min)
for HackerOne, Bugcrowd, Intigriti and YesWeHack, diffs them against the last snapshot,
and pushes what changed, most useful first.

Positive signals (pushed with sound):
  NEW_PROGRAM       new public program (includes private -> public launches)
  VDP_TO_PAID       program starts paying
  OOS_TO_IN_SCOPE   something that was out of scope is now in scope
  NEW_WILDCARD      new *.domain asset
  NEW_ASSET_TYPE    first asset of a type the program never had (first API, first mobile app...)
  REOPENED          program came back after being paused/removed
  ASSET_NOW_PAID    existing asset became bounty-eligible (H1, Intigriti)
  NEW_ASSET         any other new in-scope asset
  OOS_REMOVED       out-of-scope exclusion dropped
  ASSET_TIER_UP     Intigriti asset moved to a better-paying tier
  BOUNTY_UP         max bounty raised (not H1: its feed has no amounts)

Negative signals (one silent digest push per run):
  PAUSED_OR_REMOVED, PAID_TO_VDP, BOUNTY_DOWN, ASSET_REMOVED, ASSET_NO_LONGER_PAID,
  ASSET_TIER_DOWN, OOS_ADDED

The feed only lists open programs, so a paused program simply disappears. Disappeared
programs are remembered in state["gone"]; they are reported after GONE_GRACE_HOURS (to ride
out feed glitches) and reported as REOPENED if they come back after that.

Anything that looks GenAI-related (HackerOne AI_MODEL assets, chat/llm/agent/copilot keywords)
is tagged [AI] so the LLM-testing track can filter on it.

Stdlib only. Config through env vars:
  BBWATCH_STATE        path to snapshot file          (default: state.json next to script)
  BBWATCH_REPORT_DIR   where markdown reports go      (default: reports/ next to script)
  BBWATCH_MIN_BOUNTY   ignore programs whose max bounty is below this (default 0)
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEED = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{}_data.json"
PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack"]
STATE_VERSION = 2

STATE = Path(os.environ.get("BBWATCH_STATE", HERE / "state.json"))
REPORT_DIR = Path(os.environ.get("BBWATCH_REPORT_DIR", HERE / "reports"))
MIN_BOUNTY = float(os.environ.get("BBWATCH_MIN_BOUNTY", "0"))
BOUNTY_ONLY = os.environ.get("BBWATCH_BOUNTY_ONLY") == "1"
# Local testing: point at a directory of already-downloaded <platform>.json files.
LOCAL_FEED_DIR = os.environ.get("BBWATCH_LOCAL_FEED")
# Cap pushes per run so a big scope dump doesn't bury your phone.
NTFY_MAX = int(os.environ.get("NTFY_MAX", "15"))
# How long a program must be missing before it counts as paused/removed.
GONE_GRACE = timedelta(hours=float(os.environ.get("BBWATCH_GONE_GRACE_HOURS", "3")))
# Forget programs that have been gone this long (after that a return counts as NEW_PROGRAM).
GONE_FORGET = timedelta(days=365)
# A platform whose program count drops by more than this in one run is treated as a feed glitch.
GLITCH_DROP = 0.2

AI_RE = re.compile(
    r"(?<![a-z])(ai|llm|gpt|genai|chat(bot)?|copilot|assistant|agent(s|ic)?|mcp|rag|"
    r"openai|anthropic|claude|gemini|prompt|ml|model)(?![a-z])",
    re.I,
)

# kind -> (sort rank, ntfy priority). ntfy priority 1 = silent.
KINDS = {
    "NEW_PROGRAM": (1, 5),
    "VDP_TO_PAID": (2, 5),
    "OOS_TO_IN_SCOPE": (2, 5),
    "NEW_WILDCARD": (3, 5),
    "NEW_ASSET_TYPE": (3, 4),
    "REOPENED": (3, 4),
    "ASSET_NOW_PAID": (4, 4),
    "NEW_ASSET": (5, 3),
    "OOS_REMOVED": (5, 3),
    "ASSET_TIER_UP": (6, 3),
    "BOUNTY_UP": (6, 3),
    "PAUSED_OR_REMOVED": (9, 1),
    "PAID_TO_VDP": (9, 1),
    "BOUNTY_DOWN": (9, 1),
    "ASSET_REMOVED": (9, 1),
    "ASSET_NO_LONGER_PAID": (9, 1),
    "ASSET_TIER_DOWN": (9, 1),
    "OOS_ADDED": (9, 1),
}
NEGATIVE = {k for k, (rank, _) in KINDS.items() if rank == 9}


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
#   key -> {platform, name, url, paid, max_bounty, assets, oos}
#   assets: {identifier: {"type": str, "bounty": True/False/None, "tier": int/None}}
#     bounty None = the feed doesn't say per asset (Bugcrowd, YesWeHack)
#   oos: sorted list of out-of-scope identifiers
#   max_bounty: None when the platform doesn't publish amounts (H1)

def _money(v):
    if isinstance(v, dict):
        v = v.get("value")
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _asset(typ, bounty=None, tier=None):
    return {"type": (typ or "").lower(), "bounty": bounty, "tier": tier}


def norm_hackerone(p):
    t = p["targets"]
    assets = {a["asset_identifier"]: _asset(a["asset_type"], bool(a.get("eligible_for_bounty")))
              for a in t["in_scope"] if a.get("eligible_for_submission", True)}
    oos = [a["asset_identifier"] for a in t["out_of_scope"]]
    oos += [a["asset_identifier"] for a in t["in_scope"] if not a.get("eligible_for_submission", True)]
    return p["handle"], {
        "name": p["name"], "url": p["url"],
        "paid": bool(p.get("offers_bounties")), "max_bounty": None,
        "assets": assets, "oos": oos,
    }


def _bc_id(a):
    return a.get("target") or a.get("uri") or a.get("name")


def norm_bugcrowd(p):
    t = p["targets"]
    top = _money(p.get("max_payout"))
    return p["url"], {
        "name": p["name"].strip(), "url": p["url"],
        "paid": top > 0, "max_bounty": top,
        "assets": {_bc_id(a): _asset(a.get("type")) for a in t["in_scope"] if _bc_id(a)},
        "oos": [_bc_id(a) for a in t["out_of_scope"] if _bc_id(a)],
    }


def _intigriti_tier(impact):
    """'Tier 2' -> (True, 2), 'No Bounty' -> (False, None), missing -> (None, None)."""
    if not impact:
        return None, None
    m = re.match(r"tier\s*(\d+)", impact, re.I)
    if m:
        return True, int(m.group(1))
    return (False, None) if impact.lower() == "no bounty" else (None, None)


def norm_intigriti(p):
    t = p["targets"]
    assets, oos = {}, []
    for a in t["in_scope"]:
        ep = (a.get("endpoint") or "").strip()
        if not ep:
            continue
        if (a.get("impact") or "").lower() == "out of scope":
            oos.append(ep)
            continue
        bounty, tier = _intigriti_tier(a.get("impact"))
        assets[ep] = _asset(a.get("type"), bounty, tier)
    oos += [(a.get("endpoint") or "").strip() for a in t["out_of_scope"] if a.get("endpoint")]
    top = _money(p.get("max_bounty"))
    return f'{p["company_handle"]}/{p["handle"]}', {
        "name": p["name"], "url": p["url"],
        "paid": top > 0, "max_bounty": top,
        "assets": assets, "oos": oos,
    }


def norm_yeswehack(p):
    t = p["targets"]
    top = _money(p.get("max_bounty"))
    return p["id"], {
        "name": p["name"], "url": f'https://yeswehack.com/programs/{p["id"]}',
        "paid": top > 0, "max_bounty": top,
        "assets": {a["target"]: _asset(a.get("type")) for a in t["in_scope"] if a.get("target")},
        "oos": [a["target"] for a in t["out_of_scope"] if a.get("target")],
    }


NORMALIZERS = {"hackerone": norm_hackerone, "bugcrowd": norm_bugcrowd,
               "intigriti": norm_intigriti, "yeswehack": norm_yeswehack}


def snapshot():
    """Returns ({key: program}, set of platforms fetched successfully)."""
    snap, ok = {}, set()
    for plat in PLATFORMS:
        try:
            raw = fetch(plat)
        except Exception as e:  # one platform failing shouldn't kill the run
            print(f"[!] {plat}: {e}", file=sys.stderr)
            continue
        ok.add(plat)
        for p in raw:
            try:
                key, prog = NORMALIZERS[plat](p)
            except (KeyError, TypeError, AttributeError) as e:
                print(f"[!] {plat}: skipped malformed program ({e})", file=sys.stderr)
                continue
            prog["platform"] = plat
            prog["oos"] = sorted(set(prog["oos"]))
            snap[f"{plat}:{key}"] = prog
    return snap, ok


# --------------------------------------------------------------------------- state

def migrate(raw):
    """v1 state was a flat {key: program} with assets as {id: "type[:nobounty]"} and no oos."""
    if raw.get("version") == STATE_VERSION:
        return raw
    programs = {}
    for key, p in raw.items():
        plat = p["platform"]
        per_asset = plat in ("hackerone", "intigriti")
        assets = {}
        for a, typ in p["assets"].items():
            base, _, flag = typ.partition(":")
            # v1 couldn't tell "No Bounty" from "missing" on Intigriti, so only trust H1
            bounty = (flag != "nobounty") if plat == "hackerone" else None
            assets[a] = _asset(base, bounty if per_asset else None)
        programs[key] = {
            "name": p["name"], "url": p["url"], "platform": plat,
            "paid": p["max_bounty"] > 0,
            "max_bounty": None if plat == "hackerone" else p["max_bounty"],
            "assets": assets,
            "oos": None,  # unknown: skip OOS diff until next run
        }
    return {"version": STATE_VERSION, "programs": programs, "gone": {}}


def save(state):
    # sorted + one item per line so git stores small diffs between runs
    STATE.write_text(json.dumps(state, sort_keys=True, indent=0), encoding="utf-8")


# --------------------------------------------------------------------------- diff

def is_ai(text, asset_type=""):
    return "ai_model" in (asset_type or "").lower() or bool(AI_RE.search(text or ""))


def is_wildcard(identifier, typ):
    return "*" in identifier or "wildcard" in typ


def wanted(prog):
    if not prog["paid"]:
        return not BOUNTY_ONLY
    # H1 dump has no amounts, so MIN_BOUNTY can't be applied there
    return prog["max_bounty"] is None or prog["max_bounty"] >= MIN_BOUNTY


class Changes(list):
    def add(self, kind, key, prog, detail="", ai=False):
        self.append({"kind": kind, "key": key, "platform": prog["platform"], "name": prog["name"],
                     "url": prog["url"], "paid": prog["paid"], "max_bounty": prog["max_bounty"],
                     "detail": detail, "ai": ai})


def diff_program(key, o, n, out):
    add = lambda kind, detail="", ai=False: out.add(kind, key, n, detail, ai)

    # money
    became_paid = n["paid"] and not o["paid"]
    if became_paid:
        add("VDP_TO_PAID", f'max {n["max_bounty"]:g}' if n["max_bounty"] else "")
    elif o["paid"] and not n["paid"]:
        add("PAID_TO_VDP")
    elif n["max_bounty"] and o["max_bounty"]:
        if n["max_bounty"] > o["max_bounty"]:
            add("BOUNTY_UP", f'{o["max_bounty"]:g} -> {n["max_bounty"]:g}')
        elif n["max_bounty"] < o["max_bounty"]:
            add("BOUNTY_DOWN", f'{o["max_bounty"]:g} -> {n["max_bounty"]:g}')

    # out of scope (None = unknown after migration)
    moved_in = set()
    if o.get("oos") is not None:
        old_oos, new_oos = set(o["oos"]), set(n["oos"])
        for x in sorted(old_oos - new_oos):
            if x in n["assets"]:
                moved_in.add(x)
                add("OOS_TO_IN_SCOPE", x, is_ai(x, n["assets"][x]["type"]))
            else:
                add("OOS_REMOVED", x[:200])
        for x in sorted(new_oos - old_oos):
            add("OOS_ADDED", x[:200])

    # assets
    old_types = {a["type"] for a in o["assets"].values()}
    for a, info in n["assets"].items():
        typ = info["type"]
        before = o["assets"].get(a)
        if before is None:
            if a in moved_in:
                continue
            kind = ("NEW_WILDCARD" if is_wildcard(a, typ)
                    else "NEW_ASSET_TYPE" if old_types and typ not in old_types
                    else "NEW_ASSET")
            add(kind, f"{a}  ({typ})", is_ai(a, typ))
            continue
        if info["bounty"] is True and before["bounty"] is False and not became_paid:
            add("ASSET_NOW_PAID", a, is_ai(a, typ))
        elif info["bounty"] is False and before["bounty"] is True:
            add("ASSET_NO_LONGER_PAID", a)
        elif info["tier"] and before["tier"] and info["tier"] != before["tier"]:
            # Intigriti: Tier 1 pays most
            up = info["tier"] < before["tier"]
            add("ASSET_TIER_UP" if up else "ASSET_TIER_DOWN",
                f'{a}  tier {before["tier"]} -> {info["tier"]}', up and is_ai(a, typ))
    for a in o["assets"]:
        if a not in n["assets"]:
            add("ASSET_REMOVED", a)


def program_is_ai(prog):
    return is_ai(prog["name"]) or any(is_ai(a, i["type"]) for a, i in prog["assets"].items())


def diff(state, new, fetched, now):
    """Mutates state["gone"]; returns Changes."""
    old = state["programs"]
    gone = state["gone"]
    out = Changes()

    for key, n in new.items():
        if key in old:
            if wanted(n) or wanted(old[key]):
                diff_program(key, old[key], n, out)
        elif key in gone:
            g = gone.pop(key)
            if wanted(n):
                if g["alerted"]:
                    out.add("REOPENED", key, n, f'gone since {g["since"][:10]}', program_is_ai(n))
                diff_program(key, g["prog"], n, out)  # catch scope changes made while away
        elif wanted(n):
            out.add("NEW_PROGRAM", key, n, f'{len(n["assets"])} assets', program_is_ai(n))

    for key, o in old.items():
        if key not in new and o["platform"] in fetched:
            gone[key] = {"since": now.isoformat(timespec="seconds"), "alerted": False, "prog": o}

    for key, g in list(gone.items()):
        since = datetime.fromisoformat(g["since"])
        if now - since > GONE_FORGET:
            del gone[key]
        elif not g["alerted"] and now - since >= GONE_GRACE:
            g["alerted"] = True
            if wanted(g["prog"]):
                out.add("PAUSED_OR_REMOVED", key, g["prog"], "no longer listed (paused, closed or made private)")

    out.sort(key=lambda c: (KINDS[c["kind"]][0], not c["ai"], -(c["max_bounty"] or 0)))
    return out


# --------------------------------------------------------------------------- output

def money(c):
    if not c["paid"]:
        return "VDP"
    return f'max {c["max_bounty"]:g}' if c["max_bounty"] else "bounty"


def fmt(c):
    tag = "[AI] " if c["ai"] else ""
    detail = f' - {c["detail"]}' if c["detail"] else ""
    name = c["name"] if money(c) in c["name"] else f'{c["name"]} ({money(c)})'
    return f'{tag}{c["kind"]} [{c["platform"]}] {name}{detail}\n    {c["url"]}'


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


def _label(kind):
    return kind.replace("_", " ").title().replace("Oos", "OOS").replace("Vdp", "VDP")


def ntfy(changes):
    """One push per program for positive changes (tap opens the program), one silent digest
    for negative ones."""
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        return
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")

    def send(payload):
        try:
            post_json(server, {"topic": topic, **payload})
        except Exception as e:
            print(f"[!] ntfy failed: {e}", file=sys.stderr)

    groups = {}
    for c in changes:
        if c["kind"] not in NEGATIVE:
            groups.setdefault(c["key"], []).append(c)  # changes are pre-sorted, so first = best
    items = list(groups.values())
    for group in items[:NTFY_MAX]:
        top = group[0]
        ai = any(g["ai"] for g in group)
        lines = [f'{"[AI] " if g["ai"] else ""}{_label(g["kind"])}: {g["detail"]}'.rstrip(": ")
                 for g in group]
        body = "\n".join(lines[:20]) + (f"\n+{len(lines) - 20} more" if len(lines) > 20 else "")
        prio = KINDS[top["kind"]][1]
        if top["kind"] == "NEW_PROGRAM" and not top["paid"]:
            prio = 4
        send({
            "title": f'{"[AI] " if ai else ""}{_label(top["kind"])}: {top["name"]}',
            "message": f'{top["platform"]} - {money(top)}\n{body}',
            "click": top["url"],
            "tags": ["robot"] if ai else ["mag"],
            "priority": max(prio, 4) if ai else prio,
        })
    if len(items) > NTFY_MAX:
        send({"title": f"+{len(items) - NTFY_MAX} more programs changed",
              "message": "See the reports/ folder in your GitHub repo.", "priority": 2})

    neg = [c for c in changes if c["kind"] in NEGATIVE]
    if neg:
        lines = [f'{_label(c["kind"])}: {c["name"]} [{c["platform"]}] {c["detail"]}'.strip() for c in neg]
        body = "\n".join(lines[:25]) + (f"\n+{len(lines) - 25} more" if len(lines) > 25 else "")
        send({"title": f"{len(neg)} negative changes", "message": body[:3900],
              "tags": ["small_red_triangle_down"], "priority": 1})


def alert(changes):
    ntfy(changes)
    pos = [fmt(c) for c in changes if c["kind"] not in NEGATIVE]
    neg = [fmt(c) for c in changes if c["kind"] in NEGATIVE]
    lines = pos + (["--- negative ---"] + neg if neg else [])
    if not lines:
        return
    hook = os.environ.get("DISCORD_WEBHOOK")
    tg_token, tg_chat = os.environ.get("TELEGRAM_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    for msg in chunks(lines, 1900):
        try:
            if hook:
                post_json(hook, {"content": msg})
            if tg_token and tg_chat:
                post_json(f"https://api.telegram.org/bot{tg_token}/sendMessage",
                          {"chat_id": tg_chat, "text": msg, "disable_web_page_preview": True})
        except Exception as e:
            print(f"[!] alert failed: {e}", file=sys.stderr)


# --------------------------------------------------------------------------- main

def test_alert():
    alert([{"kind": "NEW_PROGRAM", "key": "test", "platform": "bbwatch", "name": "Test alert",
            "url": "https://github.com/arkadiyt/bounty-targets-data", "paid": True,
            "max_bounty": 1000, "detail": "If you can read this on your phone, alerts work.",
            "ai": False}])
    print("[+] test alert sent to every configured channel")


def main():
    # program names contain odd unicode; never let a console encoding kill a run
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
    if "--test-alert" in sys.argv:
        return test_alert()
    now = datetime.now(timezone.utc)
    new, fetched = snapshot()
    if not new:
        sys.exit("[!] no data fetched")
    if not STATE.exists():
        save({"version": STATE_VERSION, "programs": new, "gone": {}})
        print(f"[+] baseline saved: {len(new)} programs. Next run reports changes.")
        return
    state = migrate(json.loads(STATE.read_text(encoding="utf-8")))
    old = state["programs"]

    # A platform that failed, or whose program count collapsed (feed glitch), keeps its old
    # data so its programs don't look paused.
    for plat in PLATFORMS:
        before = sum(1 for p in old.values() if p["platform"] == plat)
        after = sum(1 for p in new.values() if p["platform"] == plat)
        if plat in fetched and before >= 20 and after < before * (1 - GLITCH_DROP):
            print(f"[!] {plat}: {before} -> {after} programs, treating as feed glitch", file=sys.stderr)
            fetched.discard(plat)
            new = {k: v for k, v in new.items() if v["platform"] != plat}
        if plat not in fetched:
            new.update({k: v for k, v in old.items() if v["platform"] == plat})

    changes = diff(state, new, fetched, now)
    state["programs"] = new
    save(state)
    if not changes:
        print("[=] no changes")
        return
    path = write_report(changes, now)
    alert(changes)
    for c in changes:
        print(fmt(c))
    print(f"[+] {len(changes)} changes -> {path}")


if __name__ == "__main__":
    main()
