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

  Policy (YesWeHack, from its public API):
  EXCLUSION_REMOVED a non-qualifying vulnerability class was dropped (it pays now)
  QUALIFYING_ADDED  new qualifying vulnerability class
  REWARD_UP         a cell of the reward grid went up
  POLICY_CHANGED    rules / account-access text changed (shows added lines)
  PROGRAM_UPDATED   Intigriti says the program was edited, but the public API doesn't say what

Negative signals (one silent digest push per run):
  PAUSED, PAUSED_OR_REMOVED, PAID_TO_VDP, BOUNTY_DOWN, ASSET_REMOVED, ASSET_NO_LONGER_PAID,
  ASSET_TIER_DOWN, OOS_ADDED, EXCLUSION_ADDED, QUALIFYING_REMOVED, REWARD_DOWN

The feed only lists open programs, so a paused program simply disappears. Disappeared
programs are remembered in state["gone"]; they are reported after GONE_GRACE_HOURS (to ride
out feed glitches) and reported as REOPENED if they come back after that.

Intigriti and YesWeHack also have public program lists (no account needed). Those are read
directly every run. They give the real open/suspended status, programs the feed skips
(Intigriti programs that need login or T&C acceptance) and, for YesWeHack, the full policy,
fetched only when a program's last_update_at changes. For those two platforms the list is
the authority on pauses, so the feed's disappearance guess is not alerted.

Tags: [AI] for GenAI-looking assets/text, [BONUS] for policy text mentioning bonuses or
promotions. Both always push at high priority.

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
  BBWATCH_DIRECT       "0" to skip the direct platform APIs (default on, off with LOCAL_FEED)
"""
import base64
import difflib
import html
import json
import os
import re
import sys
import time
import urllib.error
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
    "EXCLUSION_REMOVED": (4, 4),
    "QUALIFYING_ADDED": (5, 3),
    "REWARD_UP": (6, 3),
    "POLICY_CHANGED": (6, 3),
    "PROGRAM_UPDATED": (7, 3),
    "ANNOUNCEMENT": (4, 4),
    "PAUSED": (9, 1),
    "EXCLUSION_ADDED": (9, 1),
    "QUALIFYING_REMOVED": (9, 1),
    "REWARD_DOWN": (9, 1),
    "PAUSED_OR_REMOVED": (9, 1),
    "REOPENED_BRIEF": (10, 0),  # report file only
    "WARNING": (0, 4),          # bbwatch itself needs attention
    "PAID_TO_VDP": (9, 1),
    "BOUNTY_DOWN": (9, 1),
    "ASSET_REMOVED": (9, 1),
    "ASSET_NO_LONGER_PAID": (9, 1),
    "ASSET_TIER_DOWN": (9, 1),
    "OOS_ADDED": (9, 1),
}
NEGATIVE = {k for k, (rank, _) in KINDS.items() if rank == 9}
QUIET = {k for k, (rank, _) in KINDS.items() if rank == 10}


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


def load():
    state = migrate(json.loads(STATE.read_text(encoding="utf-8")))
    state.setdefault("lists", {})
    state.setdefault("policy", {})
    # before "seen" existed, everything already in the snapshot had been seen
    state["seen"] = set(state.get("seen") or (list(state["programs"]) + list(state["gone"])))
    return state


def save(state):
    # sorted + one item per line so git stores small diffs between runs
    out = {**state, "seen": sorted(state["seen"])}
    STATE.write_text(json.dumps(out, sort_keys=True, indent=0), encoding="utf-8")


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
    def add(self, kind, key, prog, detail="", ai=False, bonus=False):
        self.append({"kind": kind, "key": key, "platform": prog["platform"], "name": prog["name"],
                     "url": prog["url"], "paid": prog["paid"], "max_bounty": prog["max_bounty"],
                     "detail": " ".join(str(detail).split()), "ai": ai, "bonus": bonus})


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


def diff(state, new, fetched, now, authoritative=frozenset()):
    """Feed diff. Mutates state["gone"] and state["seen"]; returns Changes.
    authoritative: platforms whose direct list reports pauses, so disappearances aren't alerted."""
    old = state["programs"]
    gone = state["gone"]
    seen = state["seen"]
    out = Changes()

    for key, n in new.items():
        if key in old:
            if wanted(n) or wanted(old[key]):
                diff_program(key, old[key], n, out)
        elif key in gone:
            g = gone.pop(key)
            if wanted(n):
                if g["alerted"] and n["platform"] not in authoritative:
                    out.add("REOPENED", key, n, f'gone since {g["since"][:10]}', program_is_ai(n))
                diff_program(key, g["prog"], n, out)  # catch scope changes made while away
        elif key not in seen and wanted(n):
            out.add("NEW_PROGRAM", key, n, f'{len(n["assets"])} assets', program_is_ai(n))
        seen.add(key)

    for key, o in old.items():
        if key not in new and o["platform"] in fetched:
            gone[key] = {"since": now.isoformat(timespec="seconds"), "alerted": False, "prog": o}

    for key, g in list(gone.items()):
        since = datetime.fromisoformat(g["since"])
        if now - since > GONE_FORGET:
            del gone[key]
        elif not g["alerted"] and now - since >= GONE_GRACE:
            g["alerted"] = True
            if wanted(g["prog"]) and g["prog"]["platform"] not in authoritative:
                out.add("PAUSED_OR_REMOVED", key, g["prog"], "no longer listed (paused, closed or made private)")
    return out


def sort_changes(out):
    out.sort(key=lambda c: (KINDS[c["kind"]][0], not (c["ai"] or c["bonus"]), -(c["max_bounty"] or 0)))


# --------------------------------------------------------------------------- direct sources
# Public, unauthenticated program APIs. Fresher than the feed, include programs it skips,
# and (YesWeHack) carry the policy text.

IG_LIST = "https://app.intigriti.com/api/core/public/programs"
YWH_LIST = "https://api.yeswehack.com/programs?page={}&resultsPerPage=100"
YWH_DETAIL = "https://api.yeswehack.com/programs/{}"
DIRECT = os.environ.get("BBWATCH_DIRECT", "0" if LOCAL_FEED_DIR else "1") == "1"
IG_OPEN, IG_SUSPENDED = 3, 4
IG_REGISTERED = 2  # confidentialityLevel: visible to logged-in researchers only (4 = public)

BONUS_RE = re.compile(r"bonus|promotion|multiplier|double bount|\b2x\b|\bx2\b|limited[- ]time|campaign", re.I)


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "bbwatch", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def list_intigriti():
    out = {}
    for p in get_json(IG_LIST):
        if p.get("status") not in (IG_OPEN, IG_SUSPENDED):
            continue
        top = _money(p.get("maxBounty"))
        out[f'intigriti:{p["companyHandle"]}/{p["handle"]}'] = {
            "platform": "intigriti", "name": p["name"],
            "url": f'https://www.intigriti.com/programs/{p["companyHandle"]}/{p["handle"]}/detail',
            "paid": top > 0, "max_bounty": top, "open": p["status"] == IG_OPEN,
            "updated": str(p.get("lastUpdatedAt")),
            "login": p.get("confidentialityLevel") == IG_REGISTERED,
            "tac": bool(p.get("tacRequired")),
        }
    return out


def list_yeswehack():
    out, page = {}, 1
    while True:
        j = get_json(YWH_LIST.format(page))
        for p in j["items"]:
            top = _money(p.get("bounty_reward_max"))
            out[f'yeswehack:{p["slug"]}'] = {
                "platform": "yeswehack", "name": p["title"], "slug": p["slug"],
                "url": f'https://yeswehack.com/programs/{p["slug"]}',
                "paid": bool(p.get("bounty")) and top > 0, "max_bounty": top,
                "open": not (p.get("disabled") or p.get("archived")),
                "updated": p.get("last_update_at") or "", "login": False, "tac": False,
            }
        if page >= j["pagination"]["nb_pages"]:
            return out
        page += 1


def ywh_policy(slug):
    d = get_json(YWH_DETAIL.format(slug))
    rewards = {}
    for k, grid in d.items():
        if k.startswith("reward_grid_") and isinstance(grid, dict):
            for sev, amount in grid.items():
                if amount:
                    rewards[f'{k[len("reward_grid_"):]}.{sev.replace("bounty_", "")}'] = float(amount)
    return {
        "rules": d.get("rules") or "",
        "account_access": d.get("account_access") or "",
        "qualifying": sorted(set(d.get("qualifying_vulnerability") or [])),
        "non_qualifying": sorted(set(d.get("non_qualifying_vulnerability") or [])),
        "rewards": rewards,
    }


def added_lines(a, b):
    """Lines present in b but not a, or None if the texts are identical."""
    if a == b:
        return None
    diff_ = difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0)
    return [l[1:].strip(" #*-") for l in diff_
            if l.startswith("+") and not l.startswith("+++") and l[1:].strip(" #*-")]


def diff_policy(key, prog, o, n, out):
    """Policy dicts may carry: qualifying / non_qualifying (lists), rewards (cell -> amount),
    rules / account_access (text), testing (setting -> value). Missing fields are skipped."""
    def add(kind, detail, ai=False, bonus=False):
        out.add(kind, key, prog, detail[:300], ai, bonus)

    # list fields only compare when both sides have them (H1 exclusions arrive gradually)
    has = lambda f: f in o and f in n
    old_nq, new_nq = (set(o["non_qualifying"]), set(n["non_qualifying"])) if has("non_qualifying") else (set(), set())
    for x in sorted(old_nq - new_nq):
        add("EXCLUSION_REMOVED", x, is_ai(x))
    for x in sorted(new_nq - old_nq):
        add("EXCLUSION_ADDED", x)
    old_q, new_q = (set(o["qualifying"]), set(n["qualifying"])) if has("qualifying") else (set(), set())
    for x in sorted(new_q - old_q):
        add("QUALIFYING_ADDED", x, is_ai(x))
    for x in sorted(old_q - new_q):
        add("QUALIFYING_REMOVED", x)
    o_rw, n_rw = o.get("rewards", {}), n.get("rewards", {})
    for cell in sorted(set(o_rw) | set(n_rw)):
        a, b = o_rw.get(cell, 0), n_rw.get(cell, 0)
        if a != b:
            add("REWARD_UP" if b > a else "REWARD_DOWN", f"{cell}: {a:g} -> {b:g}")
    for field in ("rules", "account_access"):
        lines = added_lines(o.get(field, ""), n.get(field, ""))
        if lines is None:
            continue
        detail = " | ".join(lines[:3]) if lines else "text removed or reworded"
        add("POLICY_CHANGED", f"{field}: {detail}",
            any(is_ai(l) for l in lines), any(BONUS_RE.search(l) for l in lines))
    o_t, n_t = o.get("testing", {}), n.get("testing", {})
    for k in sorted(set(o_t) | set(n_t)):
        if o_t.get(k) != n_t.get(k):
            add("POLICY_CHANGED", f'testing {k}: {o_t.get(k) or "-"} -> {n_t.get(k) or "-"}')


# Intigriti researcher API (personal access token). Superset of the public list: adds
# application/invite programs, full scope with tiers, rules of engagement, and an activity log
# that says which programs got a new scope or rules version.

IG_API = "https://api.intigriti.com/external/researcher/v1"
IG_TOKEN = os.environ.get("INTIGRITI_TOKEN")
IG_ACCESS_NOTES = {"Registered": "login required", "Application": "apply to join",
                   "InviteOnly": "invite only"}
IG_DENIED_RETRY = timedelta(hours=24)
# Status flips shorter than this (report caps resetting) aren't pushed as REOPENED.
REOPEN_MIN = timedelta(hours=float(os.environ.get("BBWATCH_REOPEN_MIN_HOURS", "72")))
WARNINGS = []


def ig_api(path):
    req = urllib.request.Request(IG_API + path, headers={
        "Authorization": f"Bearer {IG_TOKEN}", "Accept": "application/json", "User-Agent": "bbwatch"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def list_intigriti_api():
    out, offset = {}, 0
    while True:
        j = ig_api(f"/programs?limit=500&offset={offset}")
        for p in j["records"]:
            m = re.search(r"/programs/([^/]+)/([^/]+)/detail", (p.get("webLinks") or {}).get("detail", ""))
            if not m or p["status"]["id"] not in (IG_OPEN, IG_SUSPENDED):
                continue
            company, handle = m.groups()
            top = _money(p.get("maxBounty"))
            access = p["confidentialityLevel"]["value"]
            out[f"intigriti:{company}/{handle}"] = {
                "platform": "intigriti", "name": p["name"], "id": p["id"],
                "url": f"https://www.intigriti.com/programs/{company}/{handle}/detail",
                "paid": top > 0, "max_bounty": top, "open": p["status"]["id"] == IG_OPEN,
                "updated": "", "login": access == "Registered", "tac": False, "access": access,
            }
        offset += len(j["records"])
        if not j["records"] or offset >= j["maxCount"]:
            return out


def ig_changed_programs(since):
    """Program ids with a new scope or rules version after `since` (epoch), and the newest
    activity time seen."""
    ids, newest, offset = set(), since, 0
    while offset < 5000:
        j = ig_api(f"/programs/activities?limit=100&offset={offset}")
        for a in j["records"]:
            if a["createdAt"] <= since:
                return ids, newest
            newest = max(newest, a["createdAt"])
            if a["type"]["id"] != 3:  # 3 = status change; the list already covers status
                ids.add(a["programId"])
        offset += len(j["records"])
        if not j["records"] or offset >= j["maxCount"]:
            break
    return ids, newest


def ig_detail(pid):
    d = ig_api(f"/programs/{pid}")
    assets, oos = {}, []
    for a in (d.get("domains") or {}).get("content") or []:
        ep = (a.get("endpoint") or "").strip()
        tier = (a.get("tier") or {}).get("value") or ""
        if not ep:
            continue
        if tier.lower() == "out of scope":
            oos.append(ep)
            continue
        bounty, t = _intigriti_tier(tier)
        assets[ep] = _asset((a.get("type") or {}).get("value"), bounty, t)
    roe = (d.get("rulesOfEngagement") or {}).get("content") or {}
    testing = {k: str(v) for k, v in (roe.get("testingRequirements") or {}).items() if v not in (None, "")}
    testing["safeHarbour"] = str(roe.get("safeHarbour"))
    return assets, sorted(set(oos)), {"rules": roe.get("description") or "", "testing": testing}


def intigriti_programs(state, ig_list, now):
    """Builds Intigriti programs from the researcher API, re-fetching only programs that are
    new, had scope/rules activity, or were access-denied over a day ago.
    Returns ({key: program}, [(key, old_policy, new_policy)])."""
    cache = state.setdefault("ig_detail", {})
    policy = state["policy"]
    since = state.get("ig_cursor", 0)
    try:
        changed, cursor = ig_changed_programs(since) if since else (set(), int(now.timestamp()))
    except Exception as e:
        print(f"[!] intigriti activities: {e}", file=sys.stderr)
        changed, cursor = None, since  # unknown: refetch everything this run
    policy_diffs = []
    for key, n in ig_list.items():
        c = cache.get(key)
        stale = (c is None or changed is None or n["id"] in changed
                 or (c.get("denied") and now - datetime.fromisoformat(c["fetched"]) > IG_DENIED_RETRY))
        if not stale:
            continue
        try:
            assets, oos, pol = ig_detail(n["id"])
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):  # no access yet (application/invite programs)
                cache[key] = {"denied": True, "fetched": now.isoformat(timespec="seconds")}
            else:
                print(f"[!] intigriti detail {n['name']}: {e}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[!] intigriti detail {n['name']}: {e}", file=sys.stderr)
            continue
        time.sleep(0.2)
        cache[key] = {"assets": assets, "oos": oos, "fetched": now.isoformat(timespec="seconds")}
        if key in policy:
            policy_diffs.append((key, policy[key], pol))
        policy[key] = pol
    state["ig_cursor"] = cursor
    programs = {}
    for key, n in ig_list.items():
        c = cache.get(key)
        if c and not c.get("denied"):
            programs[key] = {"platform": "intigriti", "name": n["name"], "url": n["url"],
                             "paid": n["paid"], "max_bounty": n["max_bounty"],
                             "assets": c["assets"], "oos": c["oos"]}
    return programs, policy_diffs


# HackerOne Hacker API (API identifier + token, basic auth). The program list carries the full
# policy text and the real open/paused status; the feed only lists open programs. Scope stays
# from the feed (same data). Scope exclusions need one call per program, so they're refreshed
# round-robin plus immediately for programs whose policy text changed.

H1_API = "https://api.hackerone.com/v1/hackers"
H1_USER, H1_TOKEN = os.environ.get("H1_USERNAME"), os.environ.get("H1_TOKEN")
H1_EXCL_PER_RUN = int(os.environ.get("BBWATCH_H1_EXCLUSIONS_PER_RUN", "60"))
H1_POLICIES = {}  # filled by list_hackerone for this run: key -> policy text


def h1_api(url):
    auth = base64.b64encode(f"{H1_USER}:{H1_TOKEN}".encode()).decode()
    req = urllib.request.Request(url if url.startswith("http") else H1_API + url, headers={
        "Authorization": f"Basic {auth}", "Accept": "application/json", "User-Agent": "bbwatch"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def list_hackerone():
    out, url = {}, "/programs?page%5Bsize%5D=100"
    H1_POLICIES.clear()
    while url:
        j = h1_api(url)
        for p in j["data"]:
            a = p["attributes"]
            if a.get("state") != "public_mode":
                continue
            key = f'hackerone:{a["handle"]}'
            out[key] = {
                "platform": "hackerone", "name": a["name"], "handle": a["handle"],
                "url": f'https://hackerone.com/{a["handle"]}',
                "paid": bool(a.get("offers_bounties")), "max_bounty": None,
                "open": a.get("submission_state") == "open",
                "updated": "", "login": False, "tac": False,
            }
            H1_POLICIES[key] = a.get("policy") or ""
        url = (j.get("links") or {}).get("next")
    return out


def h1_exclusions(handle):
    cats, url = [], f"/programs/{handle}/scope_exclusions?page%5Bsize%5D=100"
    while url:
        j = h1_api(url)
        cats += [e["attributes"].get("category") or "" for e in j["data"]]
        url = (j.get("links") or {}).get("next")
    return sorted({c for c in cats if c})


def h1_policy_diff(state, new, out):
    """Diffs H1 policy text for every listed program, and scope exclusions for a rotating
    slice plus programs whose text just changed."""
    policy = state["policy"]
    changed_text = set()
    for key in new:
        text = H1_POLICIES.get(key, "")
        prev = policy.get(key)
        if prev is not None and prev.get("rules") != text:
            changed_text.add(key)
    keys = sorted(new)
    start = state.get("h1_excl_cursor", 0) % max(len(keys), 1)
    rotation = (keys[start:] + keys[:start])[:H1_EXCL_PER_RUN]
    state["h1_excl_cursor"] = start + len(rotation)
    refresh = changed_text | set(rotation)
    for key in keys:
        prev = policy.get(key)
        pol = {"rules": H1_POLICIES.get(key, "")}
        if prev and "non_qualifying" in prev:
            pol["non_qualifying"] = prev["non_qualifying"]
        if key in refresh:
            try:
                pol["non_qualifying"] = h1_exclusions(new[key]["handle"])
            except Exception as e:
                print(f"[!] hackerone exclusions {new[key]['handle']}: {e}", file=sys.stderr)
        policy[key] = pol
        if prev is not None and wanted(new[key]):
            diff_policy(key, new[key], prev, pol, out)


# Bugcrowd public engagement JSON (no account). Each engagement has a versioned changelog; a
# version holds the brief text, reward ranges per target group, and VRT scope rules (bug-class
# exclusions). There's no change timestamp in the list, so programs are checked round-robin,
# plus immediately when the feed shows a change. The full version is only fetched when the
# latest changelog id moved.

BC = "https://bugcrowd.com"
BC_PER_RUN = int(os.environ.get("BBWATCH_BC_PER_RUN", "40"))


class Blocked(Exception):
    pass


def bc_get(path):
    req = urllib.request.Request(BC + path, headers={"User-Agent": "bbwatch", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            raise Blocked(f"HTTP {e.code}") from e
        raise


def html_text(s):
    s = re.sub(r"<\s*(br|/p|/li|/h\d|/div|/tr)[^>]*>", "\n", s or "", flags=re.I)
    return html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


def bc_latest_changelog(code):
    cl = bc_get(f"/engagements/{code}/changelog.json").get("changelogs") or []
    latest = [c for c in cl if c.get("changelogState") == "Latest"] or sorted(
        cl, key=lambda c: c.get("publishedAt") or "", reverse=True)
    return latest[0]["id"] if latest else None


def bc_version(code, cid):
    d = bc_get(f"/engagements/{code}/changelog/{cid}.json")["data"]
    brief = d.get("brief") or {}
    rewards, excl = {}, []
    for g in d.get("scope") or []:
        if not g.get("inScope"):
            continue
        for prio, r in (g.get("rewardRangeData") or {}).items():
            name = g.get("name") or "group"
            if isinstance(r, dict) and r.get("max"):
                rewards[f"{name}.P{prio}"] = float(r["max"])
            elif isinstance(r, (int, float)) and r:  # e.g. "programMax": 10000
                rewards[f"{name}.{prio}"] = float(r)
    for rule in d.get("vrtScopeRules") or []:
        where = "" if rule.get("allTargets") else " (some targets)"
        for ids in (rule.get("vrtIds") or {}).values():
            for v in ids if isinstance(ids, list) else []:
                excl.append(f'{v.get("id", "").replace("_", " ")}: {rule.get("exclusionType", "")}{where}')
    text = "\n".join(html_text(brief.get(k)) for k in ("description", "targetsOverview", "additionalInformation"))
    return {"rules": text, "non_qualifying": sorted(set(excl)), "rewards": rewards,
            "testing": {"safeHarbor": (brief.get("safeHarborStatus") or {}).get("status") or ""}}


def bc_announcements(code):
    return [{"id": a["id"], "title": a.get("title") or "", "body": html_text(a.get("body"))}
            for a in bc_get(f"/engagements/{code}/announcements.json").get("announcements") or []]


def bugcrowd_diff(state, programs, out):
    """Checks a rotating slice of Bugcrowd programs (plus ones with feed changes this run) for a
    new brief version and new announcements."""
    if not DIRECT:
        return
    track = state.setdefault("bc", {})
    policy = state["policy"]
    keys = sorted(k for k, p in programs.items() if p["platform"] == "bugcrowd")
    if not keys:
        return
    start = state.get("bc_cursor", 0) % len(keys)
    rotation = (keys[start:] + keys[:start])[:BC_PER_RUN]
    state["bc_cursor"] = start + len(rotation)
    urgent = [k for k in keys if k not in track] + sorted({c["key"] for c in out if c["platform"] == "bugcrowd"})
    todo = list(dict.fromkeys([k for k in urgent if k in programs][:BC_PER_RUN] + rotation))
    for key in todo:
        prog = programs[key]
        code = prog["url"].rstrip("/").rsplit("/", 1)[1]
        t = track.get(key, {})
        try:
            cid = bc_latest_changelog(code)
            anns = bc_announcements(code)
            pol = policy.get(key)
            if cid and cid != t.get("changelog"):
                pol = bc_version(code, cid)
            time.sleep(0.3)
        except Blocked as e:
            WARNINGS.append(f"Bugcrowd answered {e} while checking briefs; skipped the rest this run. "
                            f"If this repeats, lower BBWATCH_BC_PER_RUN.")
            return
        except Exception as e:
            print(f"[!] bugcrowd {code}: {e}", file=sys.stderr)
            continue
        first = key not in track
        if not first and wanted(prog):
            if key in policy and pol is not policy[key]:
                diff_policy(key, prog, policy[key], pol, out)
            known = set(t.get("ann", []))
            for a in anns:
                if a["id"] not in known:
                    text = f'{a["title"]}: {a["body"]}'
                    out.add("ANNOUNCEMENT", key, prog, text[:300], is_ai(text), bool(BONUS_RE.search(text)))
        if pol is not None:
            policy[key] = pol
        track[key] = {"changelog": cid, "ann": sorted(a["id"] for a in anns)}


def list_note(n):
    notes = [x for x, on in (("login required", n["login"]), ("accept T&C first", n["tac"])) if on]
    if n.get("access") in IG_ACCESS_NOTES and n["access"] != "Registered":
        notes.append(IG_ACCESS_NOTES[n["access"]])
    return ", ".join(notes) or "from platform list"


def fetch_lists(state):
    """Returns {platform: {key: entry}} for direct lists that fetched cleanly."""
    if not DIRECT:
        return {}
    got = {}
    ig_fn = list_intigriti
    if IG_TOKEN:
        def ig_fn():
            try:
                return list_intigriti_api()
            except Exception as e:
                WARNINGS.append(f"Intigriti token failed ({e}). Using the public list until it's "
                                f"fixed. Expired? Create a new token and update the INTIGRITI_TOKEN secret.")
                return list_intigriti()
    sources = [("intigriti", ig_fn), ("yeswehack", list_yeswehack)]
    if H1_USER and H1_TOKEN:
        sources.append(("hackerone", list_hackerone))
    for plat, fn in sources:
        try:
            new = fn()
        except Exception as e:
            print(f"[!] {plat} list: {e}", file=sys.stderr)
            if plat == "hackerone":
                WARNINGS.append(f"HackerOne API failed ({e}). Policy and pause tracking for H1 is off "
                                f"until it's fixed. Check the H1_USERNAME / H1_TOKEN secrets.")
            continue
        before = sum(1 for v in state["lists"].values() if v["platform"] == plat)
        if before >= 20 and len(new) < before * (1 - GLITCH_DROP):
            print(f"[!] {plat} list: {before} -> {len(new)} programs, treating as glitch", file=sys.stderr)
            continue
        got[plat] = new
    return got


def direct_diff(state, lists, out, now):
    """Diffs the direct lists (and YesWeHack policies) into out. Mutates state."""
    seen = state["seen"]
    policy = state["policy"]
    feed = state["programs"]
    edited = []
    for plat, new in lists.items():
        old = {k: v for k, v in state["lists"].items() if v["platform"] == plat}
        first = not old  # first time we read this list: baseline silently
        stamp = now.isoformat(timespec="seconds")
        for key, n in new.items():
            o = old.get(key)
            if o is None:
                n["status_since"] = stamp
                if not first and key not in seen and wanted(n):
                    out.add("NEW_PROGRAM", key, n, list_note(n), is_ai(n["name"]))
                seen.add(key)
                continue
            n["status_since"] = o.get("status_since", stamp) if n["open"] == o["open"] else stamp
            if not (wanted(n) or wanted(o)):
                continue
            if n["open"] and not o["open"]:
                since = o.get("status_since")
                away = now - datetime.fromisoformat(since) if since else None
                if away is not None and away >= REOPEN_MIN:
                    out.add("REOPENED", key, n, f"back to open after {away.days} days suspended")
                else:  # report-cap style flip: logged, not pushed
                    out.add("REOPENED_BRIEF", key, n, "back to open after a short suspension")
            elif o["open"] and not n["open"]:
                out.add("PAUSED", key, n, "suspended on the platform")
            if key not in feed:  # feed already diffs money for programs it lists
                if n["paid"] and not o["paid"]:
                    out.add("VDP_TO_PAID", key, n, f'max {n["max_bounty"]:g}')
                elif o["paid"] and not n["paid"]:
                    out.add("PAID_TO_VDP", key, n)
                elif n["max_bounty"] != o["max_bounty"] and n["max_bounty"] and o["max_bounty"]:
                    up = n["max_bounty"] > o["max_bounty"]
                    out.add("BOUNTY_UP" if up else "BOUNTY_DOWN", key, n,
                            f'{o["max_bounty"]:g} -> {n["max_bounty"]:g}')
            if plat == "intigriti" and n["open"] and n["updated"] and o["updated"] and n["updated"] != o["updated"]:
                edited.append((key, n))
        if not first:
            for key, o in old.items():
                if key not in new and wanted(o):
                    out.add("PAUSED_OR_REMOVED", key, o, "no longer listed on the platform")
        for key in old:
            del state["lists"][key]
        state["lists"].update(new)

        if plat == "hackerone":
            h1_policy_diff(state, new, out)
        if plat == "yeswehack":
            for key, n in new.items():
                o = old.get(key)
                if key in policy and o and o["updated"] == n["updated"]:
                    continue
                try:
                    pol = ywh_policy(n["slug"])
                except Exception as e:
                    print(f"[!] yeswehack policy {n['slug']}: {e}", file=sys.stderr)
                    continue
                time.sleep(0.3)
                prev = policy.get(key)
                policy[key] = pol
                if prev and wanted(n):
                    diff_policy(key, n, prev, pol, out)

    # Intigriti edits we can't see inside: only worth a push if nothing else explains them
    explained = {c["key"] for c in out}
    for key, n in edited:
        if key not in explained:
            out.add("PROGRAM_UPDATED", key, n, "policy, scope or rewards edited; scope diff may follow")


# --------------------------------------------------------------------------- output

def money(c):
    if c["platform"] == "bbwatch":
        return ""
    if not c["paid"]:
        return "VDP"
    return f'max {c["max_bounty"]:g}' if c["max_bounty"] else "bounty"


def tags(c):
    return ("[AI] " if c["ai"] else "") + ("[BONUS] " if c.get("bonus") else "")


def fmt(c):
    tag = tags(c)
    detail = f' - {c["detail"]}' if c["detail"] else ""
    name = c["name"] if money(c) in c["name"] else f'{c["name"]} ({money(c)})'  # "" is always "in"
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
        if c["kind"] not in NEGATIVE | QUIET:
            groups.setdefault(c["key"], []).append(c)  # changes are pre-sorted, so first = best
    items = list(groups.values())
    for group in items[:NTFY_MAX]:
        top = group[0]
        ai = any(g["ai"] for g in group)
        hot = ai or any(g.get("bonus") for g in group)
        lines = [f'{tags(g)}{_label(g["kind"])}: {g["detail"]}'.rstrip(": ") for g in group]
        body = "\n".join(lines[:20]) + (f"\n+{len(lines) - 20} more" if len(lines) > 20 else "")
        prio = KINDS[top["kind"]][1]
        if top["kind"] == "NEW_PROGRAM" and not top["paid"]:
            prio = 4
        bonus = any(g.get("bonus") for g in group)
        send({
            "title": f'{"[AI] " if ai else ""}{"[BONUS] " if bonus else ""}{_label(top["kind"])}: {top["name"]}',
            "message": f'{top["platform"]} - {money(top)}\n{body}',
            "click": top["url"],
            "tags": ["robot"] if ai else ["moneybag"] if bonus else ["mag"],
            "priority": max(prio, 4) if hot else prio,
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
    pos = [fmt(c) for c in changes if c["kind"] not in NEGATIVE | QUIET]
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
            "ai": False, "bonus": False}])
    print("[+] test alert sent to every configured channel")


def main():
    # program names contain odd unicode; never let a console encoding kill a run
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
    if "--test-alert" in sys.argv:
        return test_alert()
    now = datetime.now(timezone.utc)
    new, fetched = snapshot()
    baseline = not STATE.exists()
    state = ({"version": STATE_VERSION, "programs": {}, "gone": {}, "lists": {}, "policy": {},
              "seen": set()} if baseline else load())
    lists = fetch_lists(state)

    # Intigriti from the researcher API (when the token works) instead of the feed. Switching
    # source either way re-baselines Intigriti silently: the two sources list different programs.
    ig_policy_diffs = []
    ig_source = "feed"
    if IG_TOKEN and "intigriti" in lists and any("id" in v for v in lists["intigriti"].values()):
        ig_programs, ig_policy_diffs = intigriti_programs(state, lists["intigriti"], now)
        if ig_programs:
            ig_source = "api"
            new = {k: v for k, v in new.items() if v["platform"] != "intigriti"}
            new.update(ig_programs)
            fetched.add("intigriti")
    if state.get("ig_source", "feed") != ig_source and not baseline:
        print(f"[*] intigriti source {state.get('ig_source', 'feed')} -> {ig_source}: re-baselining")
        state["programs"] = {k: v for k, v in state["programs"].items() if v["platform"] != "intigriti"}
        state["programs"].update({k: v for k, v in new.items() if v["platform"] == "intigriti"})
        state["gone"] = {k: v for k, v in state["gone"].items() if not k.startswith("intigriti:")}
        state["lists"] = {k: v for k, v in state["lists"].items() if v["platform"] != "intigriti"}
        state["seen"] |= {k for k, v in new.items() if v["platform"] == "intigriti"}
        ig_policy_diffs = []
    state["ig_source"] = ig_source

    if not new:
        sys.exit("[!] no data fetched")
    if baseline:
        state["programs"] = new
        state["seen"] = set(new)
        direct_diff(state, lists, Changes(), now)  # baseline lists + policies silently
        save(state)
        print(f"[+] baseline saved: {len(new)} programs, {len(state['lists'])} listed, "
              f"{len(state['policy'])} policies. Next run reports changes.")
        return
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

    changes = diff(state, new, fetched, now, authoritative=frozenset(lists))
    state["programs"] = new
    direct_diff(state, lists, changes, now)
    for key, before, after in ig_policy_diffs:
        prog = new.get(key) or state["lists"].get(key)
        if prog and wanted(prog):
            diff_policy(key, prog, before, after, changes)
    bugcrowd_diff(state, new, changes)
    for w in WARNINGS:
        changes.add("WARNING", "bbwatch", {"platform": "bbwatch", "name": "bbwatch needs attention",
                                           "url": "https://github.com/sinansinansi/bbwatch/settings/secrets/actions",
                                           "paid": True, "max_bounty": None}, w)
    sort_changes(changes)
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
