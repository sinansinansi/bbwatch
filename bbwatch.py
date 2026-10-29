#!/usr/bin/env python3
"""
bbwatch - breadth-first bug bounty change monitor.

Reads every public program on HackerOne, Bugcrowd, Intigriti and YesWeHack each run, diffs
scope and policy against the last snapshot, and pushes what changed, most useful first.

Sources (each platform's own API first; the arkadiyt/bounty-targets-data feed is the fallback
when a direct source fails, and switching source re-baselines that platform silently):
  HackerOne   Hacker API (H1_USERNAME/H1_TOKEN): program list with policy text and open/paused
              status every run; structured scopes of open programs at 1 req/s within a 5-minute
              budget, stopping at the first 429 (H1 limits well below its documented 600/min):
              programs whose feed scope just changed first, then least recently refreshed
              (40-100 per run observed); scope exclusions when the policy text changed
              or every 6h
  Bugcrowd    public engagement JSON: bug bounties and VDPs (the feed has no VDPs). Every run
              checks each engagement's latest changelog id and announcements; a new id fetches
              the brief version: targets per reward group, reward ranges, VRT exclusion rules
  Intigriti   researcher API (INTIGRITI_TOKEN): scope with tiers and rules of engagement,
              re-fetched when its activity log says so; public list as fallback
  YesWeHack   public API: every program's detail each run (scope with asset value levels,
              rules, (non-)qualifying vulnerabilities, reward grids)

Positive signals (pushed with sound):
  NEW_PROGRAM       new public program (includes private -> public launches)
  VDP_TO_PAID       program starts paying
  OOS_TO_IN_SCOPE   something that was out of scope is now in scope
  NEW_WILDCARD      new *.domain asset
  NEW_ASSET_TYPE    first asset of a type the program never had (first API, first mobile app...)
  REOPENED          program came back after a pause (Intigriti/H1: after >= 3 days suspended)
  ASSET_NOW_PAID    existing asset became bounty-eligible (H1 flag, Intigriti tier, Bugcrowd
                    reward group, YesWeHack asset value grid)
  NEW_ASSET         any other new in-scope asset
  OOS_REMOVED       out-of-scope exclusion dropped
  ASSET_TIER_UP     asset moved to a better-paying Intigriti tier / Bugcrowd reward group /
                    YesWeHack asset value
  BOUNTY_UP         max bounty raised (not H1: its API has no amounts)
  EXCLUSION_REMOVED a non-qualifying vulnerability class was dropped (it pays now)
  QUALIFYING_ADDED  new qualifying vulnerability class (YesWeHack)
  REWARD_UP         a reward grid / reward range cell went up (YesWeHack, Bugcrowd)
  POLICY_CHANGED    policy text changed: shows added (+) and removed (-) lines, since
                    exclusions are often bullet points that simply disappear
  ANNOUNCEMENT      new Bugcrowd program announcement
  PROGRAM_UPDATED   Intigriti (no token) says the program was edited, without saying what

Negative signals (one silent digest push per run):
  PAUSED, PAUSED_OR_REMOVED, PAID_TO_VDP, BOUNTY_DOWN, ASSET_REMOVED, ASSET_NO_LONGER_PAID,
  ASSET_TIER_DOWN, OOS_ADDED, EXCLUSION_ADDED, QUALIFYING_REMOVED, REWARD_DOWN

WARNING pushes mean bbwatch itself needs attention: a source failing several runs in a row,
an expired token, Bugcrowd answering 403/429, or the fallback feed not changing for a day.

Bugcrowd has no pause status, so a Bugcrowd program that disappears is reported after
GONE_GRACE_HOURS (to ride out glitches) and as REOPENED if it comes back.

Tags: [AI] for GenAI-looking assets/text (HackerOne AI_MODEL assets, chat/llm/agent/copilot
keywords), [BONUS] for policy text mentioning bonuses or promotions. Both push at high priority.

Stdlib only. Config through env vars:
  BBWATCH_STATE        path to snapshot file          (default: state.json next to script)
  BBWATCH_REPORT_DIR   where markdown reports go      (default: reports/ next to script)
  BBWATCH_MIN_BOUNTY   ignore programs whose max bounty is below this (default 0)
  BBWATCH_BOUNTY_ONLY  "1" to drop programs that pay nothing (also skips Bugcrowd VDPs)
  NTFY_TOPIC           ntfy.sh topic for phone push (optional, no account needed)
  NTFY_SERVER          self-hosted ntfy server        (default: https://ntfy.sh)
  NTFY_MAX             max pushes per run             (default 15)
  DISCORD_WEBHOOK      Discord webhook URL (optional)
  TELEGRAM_TOKEN / TELEGRAM_CHAT_ID   Telegram bot alerts (optional)
  BBWATCH_DIRECT       "0" to skip the direct platform APIs (default on, off with LOCAL_FEED)
  BBWATCH_H1_RPS / BBWATCH_BC_RPS / BBWATCH_YWH_RPS   request pacing per platform
"""
import base64
import difflib
import hashlib
import html
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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
    """Returns (parsed feed, raw bytes)."""
    if LOCAL_FEED_DIR:
        raw = (Path(LOCAL_FEED_DIR) / f"{platform}.json").read_bytes()
    else:
        req = urllib.request.Request(FEED.format(platform), headers={"User-Agent": "bbwatch"})
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
    return json.loads(raw.decode("utf-8")), raw


FEED_STALE = timedelta(hours=24)


def check_feed(state, fetched, digest, now):
    """Warns when feed downloads keep failing, or the feed stops changing (it normally updates
    every 30 minutes, so a day without any change means its scraper is down)."""
    for plat in PLATFORMS:
        health(state, f"scope feed ({plat})", plat in fetched, "Download failing.")
    if not fetched:
        return
    f = state.setdefault("feed", {})
    if f.get("digest") != digest:
        f.update(digest=digest, changed=now.isoformat(timespec="seconds"), warned=False)
    elif now - datetime.fromisoformat(f["changed"]) > FEED_STALE and not f.get("warned"):
        f["warned"] = True
        WARNINGS.append(f'Scope feed (bounty-targets-data) unchanged since {f["changed"][:16]} UTC. '
                        f"Its scraper may be down; feed-only programs won't show scope changes.")


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


def _asset(typ, bounty=None, tier=None, pay=None, level=None):
    """tier: Intigriti tier (1 pays most). pay/level: the best reward that applies to this asset
    and the name of where it comes from (Bugcrowd reward group, YesWeHack asset value)."""
    a = {"type": (typ or "").lower(), "bounty": bounty, "tier": tier}
    if pay is not None:
        a.update(pay=pay, level=level)
    return a


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
    """Returns ({key: program}, set of platforms fetched successfully, digest of all raw feeds)."""
    snap, ok, digest = {}, set(), hashlib.sha256()
    for plat in PLATFORMS:
        try:
            raw, body = fetch(plat)
        except Exception as e:  # one platform failing shouldn't kill the run
            print(f"[!] {plat}: {e}", file=sys.stderr)
            continue
        ok.add(plat)
        digest.update(body)
        for p in raw:
            try:
                key, prog = NORMALIZERS[plat](p)
            except (KeyError, TypeError, AttributeError) as e:
                print(f"[!] {plat}: skipped malformed program ({e})", file=sys.stderr)
                continue
            prog["platform"] = plat
            prog["src"] = "feed"
            prog["assets"] = {k.strip(): v for k, v in prog["assets"].items() if k.strip()}
            prog["oos"] = sorted({x.strip() for x in prog["oos"] if x.strip()})
            snap[f"{plat}:{key}"] = prog
    return snap, ok, digest.hexdigest()


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
    STATE.parent.mkdir(parents=True, exist_ok=True)  # first run on a fresh cache
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
        elif info.get("pay") and before.get("pay") and info["pay"] != before["pay"]:
            # Bugcrowd reward group / YesWeHack asset value moved
            up = info["pay"] > before["pay"]
            add("ASSET_TIER_UP" if up else "ASSET_TIER_DOWN",
                f'{a}  {before.get("level")} (max {before["pay"]:g}) -> {info.get("level")} (max {info["pay"]:g})',
                up and is_ai(a, typ))
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
                if g["prog"].get("src") == n.get("src"):
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
YWH_RPS = float(os.environ.get("BBWATCH_YWH_RPS", "4"))
WARNINGS = []


class Pacer:
    """Spaces requests to one host at least 1/per_sec apart, across threads."""

    def __init__(self, per_sec):
        self.gap, self.next, self.lock = 1.0 / per_sec, 0.0, threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            at = max(now, self.next)
            self.next = at + self.gap
        time.sleep(max(0.0, at - now))


def pmap(fn, items, workers):
    """[(item, result, exception)] for fn over items, on a small thread pool."""
    def safe(item):
        try:
            return item, fn(item), None
        except Exception as e:
            return item, None, e
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(safe, items))


def health(state, source, ok, message="", threshold=3, repeat=12):
    """Warns when a source fails `threshold` runs in a row, then every `repeat` runs, instead
    of failing silently (stale data looks exactly like 'no changes')."""
    h = state.setdefault("health", {}).setdefault(source, {"fails": 0})
    if ok:
        h["fails"] = 0
        return
    h["fails"] += 1
    n = h["fails"]
    if n == threshold or (n > threshold and (n - threshold) % repeat == 0):
        WARNINGS.append(f"{source}: failing for {n} runs in a row. {message}".strip())


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


YWH_LEVELS = ["very_low", "low", "medium", "high", "critical"]


def ywh_programs(state, ywh_list):
    """Fetches every YesWeHack program's detail each run (56 programs, cheap). Scope comes with
    each asset's value level, which picks the reward grid that applies to it.
    Returns ({key: program}, {key: policy}, failures)."""
    cache = state.setdefault("ywh_scope", {})
    pacer = Pacer(YWH_RPS)

    def work(key):
        pacer.wait()
        return get_json(YWH_DETAIL.format(ywh_list[key]["slug"]))

    policies, fails = {}, 0
    for key, d, err in pmap(work, list(ywh_list), 3):
        if err:
            fails += 1
            print(f"[!] yeswehack {key}: {err}", file=sys.stderr)
            continue
        cache[key] = ywh_scope(d, ywh_list[key]["paid"])
        policies[key] = ywh_policy(d)
    programs = {}
    for key, n in ywh_list.items():
        if key in cache:
            programs[key] = {"platform": "yeswehack", "name": n["name"], "url": n["url"],
                             "paid": n["paid"], "max_bounty": n["max_bounty"], "src": "api", **cache[key]}
    return programs, policies, fails


def _ywh_grids(d):
    grids = {}
    for k, grid in d.items():
        if k.startswith("reward_grid_") and isinstance(grid, dict):
            grids[k[len("reward_grid_"):]] = {sev.replace("bounty_", ""): float(v) for sev, v in grid.items() if v}
    return grids


def ywh_scope(d, paid):
    grids = _ywh_grids(d)
    assets = {}
    for s in d.get("scopes") or []:
        ident = (s.get("scope") or "").strip()
        if not ident:
            continue
        level = (s.get("asset_value") or "").lower()
        # an asset's value level picks its grid; programs without per-level grids use "default"
        grid = grids.get(level) or grids.get("default") or {}
        pay = max(grid.values(), default=0.0) if paid else 0.0
        assets[ident] = _asset(s.get("scope_type"), pay > 0, None, pay, level.upper() or None)
        if s.get("report_count") is not None:
            assets[ident]["reports"] = s["report_count"]
    oos = sorted({x.strip() for x in d.get("out_of_scope") or [] if isinstance(x, str) and x.strip()})
    return {"assets": assets, "oos": oos}


def ywh_policy(d):
    return {
        "rules": d.get("rules") or "",
        "account_access": d.get("account_access") or "",
        "qualifying": sorted(set(d.get("qualifying_vulnerability") or [])),
        "non_qualifying": sorted(set(d.get("non_qualifying_vulnerability") or [])),
        "rewards": {f"{g}.{sev}": v for g, cells in _ywh_grids(d).items() for sev, v in cells.items()},
    }


def changed_lines(a, b):
    """(added, removed) lines between two texts, or None if identical."""
    if a == b:
        return None
    added, removed = [], []
    for l in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0):
        text = l[1:].strip(" #*-")
        if not text or l.startswith(("+++", "---")):
            continue
        if l.startswith("+"):
            added.append(text)
        elif l.startswith("-"):
            removed.append(text)
    return added, removed


def apply_policies(state, policies, lookup, out, links=None):
    """Stores new policies and diffs them against the previous ones. Fields a source couldn't
    fetch this run (e.g. one program's exclusions failed) are carried over, not diffed away."""
    for key, pol in policies.items():
        prev = state["policy"].get(key)
        if prev:
            for f in ("non_qualifying", "qualifying"):
                if f not in pol and f in prev:
                    pol[f] = prev[f]
        state["policy"][key] = pol
        prog = lookup(key)
        if prev is not None and prog and wanted(prog):
            if links and key in links:
                prog = {**prog, "url": links[key]}
            diff_policy(key, prog, prev, pol, out)


def diff_policy(key, prog, o, n, out):
    """Policy dicts may carry: qualifying / non_qualifying (lists), rewards (cell -> amount),
    rules / account_access (text), testing (setting -> value). Missing fields are skipped."""
    def add(kind, detail, ai=False, bonus=False, limit=300):
        out.add(kind, key, prog, detail[:limit], ai, bonus)

    # list fields only compare when both sides have them
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
        lines = changed_lines(o.get(field, ""), n.get(field, ""))
        if lines is None:
            continue
        added, removed = lines
        # removed lines matter as much as added ones: exclusions are often bullet points
        parts = [f"+ {l}" for l in added[:3]] + [f"- {l}" for l in removed[:3]]
        more = len(added) + len(removed) - len(parts)
        detail = " | ".join(parts) + (f" | (+{more} more lines)" if more > 0 else "")
        add("POLICY_CHANGED", f"{field}: {detail or 'whitespace/formatting only'}",
            any(is_ai(l) for l in added + removed), any(BONUS_RE.search(l) for l in added), limit=450)
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
                             "paid": n["paid"], "max_bounty": n["max_bounty"], "src": "api",
                             "assets": c["assets"], "oos": c["oos"]}
    return programs, policy_diffs


# HackerOne Hacker API (API identifier + token, basic auth). The program list carries the full
# policy text and the real open/paused status. Every run, each open program's structured scopes
# and scope exclusions are fetched too, paced under H1's documented 600 reads/minute. Paused
# programs keep their last known scope.

H1_API = "https://api.hackerone.com/v1/hackers"
H1_USER, H1_TOKEN = os.environ.get("H1_USERNAME"), os.environ.get("H1_TOKEN")
# H1 documents 600 reads/min, but answered 429 after ~200 requests at both 7/s and 2/s, while a
# steady ~1/s ran 250 requests clean. So: 1/s, a time budget per run, stop at the first 429, and
# fetch programs whose feed scope just changed first, then the least recently refreshed.
H1_RPS = float(os.environ.get("BBWATCH_H1_RPS", "1"))
H1_BUDGET = float(os.environ.get("BBWATCH_H1_BUDGET_SECONDS", "300"))
# Exclusions rarely change on their own: refresh when the policy text changed, else every 6h.
H1_EXCL_MAX_AGE = timedelta(hours=float(os.environ.get("BBWATCH_H1_EXCL_HOURS", "6")))
H1_POLICIES = {}  # filled by list_hackerone for this run: key -> policy text


def h1_api(url, pacer=None):
    if pacer:
        pacer.wait()
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


def _h1_pages(path, pacer):
    url = path
    while url:
        j = h1_api(url, pacer)
        yield from j["data"]
        url = (j.get("links") or {}).get("next")


def h1_scope(handle, pacer):
    assets, oos = {}, []
    for s in _h1_pages(f"/programs/{handle}/structured_scopes?page%5Bsize%5D=100", pacer):
        a = s["attributes"]
        ident = (a.get("asset_identifier") or "").strip()
        if not ident:
            continue
        if a.get("eligible_for_submission", True):
            assets[ident] = _asset(a.get("asset_type"), bool(a.get("eligible_for_bounty")))
        else:
            oos.append(ident)
    return {"assets": assets, "oos": sorted(set(oos))}


def h1_exclusions(handle, pacer):
    cats = {e["attributes"].get("category") or ""
            for e in _h1_pages(f"/programs/{handle}/scope_exclusions?page%5Bsize%5D=100", pacer)}
    return sorted(c for c in cats if c)


def h1_programs(state, h1_list, feed):
    """Returns ({key: program}, {key: policy}, failures, rate-limited flag).
    H1 answers 429 well below its documented 600/min on these endpoints, so programs are
    fetched least-recently-refreshed first and the run stops fetching at the first 429; the
    rest keep their last known scope and exclusions until a later run gets to them."""
    cache = state.setdefault("h1_scope", {})
    pacer = Pacer(H1_RPS)
    stop = threading.Event()

    now = datetime.now(timezone.utc)
    policy = state["policy"]

    def excl_due(key):
        c, prev = cache.get(key) or {}, policy.get(key) or {}
        if "excl_fetched" not in c or "non_qualifying" not in prev:
            return True
        if prev.get("rules") != H1_POLICIES.get(key, ""):
            return True  # policy edits usually come with exclusion edits
        return now - datetime.fromisoformat(c["excl_fetched"]) > H1_EXCL_MAX_AGE

    deadline = time.monotonic() + H1_BUDGET

    def work(key):
        if stop.is_set():
            raise Blocked("skipped after a 429")
        if time.monotonic() > deadline:
            raise Blocked("time budget used up")
        handle = h1_list[key]["handle"]
        try:
            return h1_scope(handle, pacer), (h1_exclusions(handle, pacer) if excl_due(key) else None)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                stop.set()
                raise Blocked("HTTP 429") from e
            raise

    policies = {k: {"rules": H1_POLICIES.get(k, "")} for k in h1_list}
    # the feed lags but covers every open program: a change in its copy of a program's scope
    # is the cheapest hint of what to re-fetch first
    sigs = state.setdefault("h1_feedsig", {})
    hinted = set()
    for k in h1_list:
        if k in feed:
            sig = hashlib.sha256(json.dumps([sorted(feed[k]["assets"]), feed[k]["oos"]]).encode()).hexdigest()[:16]
            if sigs.get(k) not in (None, sig):
                hinted.add(k)
            sigs[k] = sig
    todo = sorted((k for k, n in h1_list.items() if n["open"]),
                  key=lambda k: (k not in hinted, (cache.get(k) or {}).get("fetched", "")))
    stamp = now.isoformat(timespec="seconds")
    fails, done = 0, 0
    for key, res, err in pmap(work, todo, 3):
        if err:
            if not isinstance(err, Blocked):
                fails += 1
                print(f"[!] hackerone {key}: {err}", file=sys.stderr)
            continue
        scope, excl = res
        entry = {**scope, "fetched": stamp, "excl_fetched": (cache.get(key) or {}).get("excl_fetched")}
        if excl is not None:
            policies[key]["non_qualifying"] = excl
            entry["excl_fetched"] = stamp
        if not entry["excl_fetched"]:
            del entry["excl_fetched"]
        cache[key] = entry
        done += 1
    print(f"[*] hackerone: refreshed {done} of {len(todo)} open programs ({len(hinted)} hinted by the feed)"
          + (" - stopped at a 429" if stop.is_set() else ""))
    programs = {}
    for key, n in h1_list.items():
        c = cache.get(key)
        if c and "assets" in c:
            scope, src = {"assets": c["assets"], "oos": c["oos"]}, "api"
        elif key in feed:
            scope, src = {"assets": feed[key]["assets"], "oos": feed[key]["oos"]}, "feed"
        else:
            continue
        programs[key] = {"platform": "hackerone", "name": n["name"], "url": n["url"],
                         "paid": n["paid"], "max_bounty": None, "src": src, **scope}
    return programs, policies, fails, stop.is_set()


# Bugcrowd public engagement JSON (no account). The list has bug bounties and VDPs (the feed
# only has bug bounties). Each engagement has a versioned changelog; a version holds the brief
# text, the targets per reward group with that group's reward range, and VRT scope rules
# (bug-class exclusions). Every run checks each engagement's latest changelog id (and
# announcements for paid ones) and fetches the version only when the id moved.

BC = "https://bugcrowd.com"
BC_RPS = float(os.environ.get("BBWATCH_BC_RPS", "4"))


class Blocked(Exception):
    pass


def bc_get(path, pacer=None):
    if pacer:
        pacer.wait()
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


def list_bugcrowd(pacer):
    out = {}
    for category in ("bug_bounty",) + (() if BOUNTY_ONLY else ("vdp",)):
        page = 1
        while True:
            j = bc_get(f"/engagements.json?category={category}&page={page}", pacer)
            for e in j.get("engagements") or []:
                top = _money(re.sub(r"[^\d.]", "", (e.get("rewardSummary") or {}).get("maxReward") or ""))
                code = e["briefUrl"].rstrip("/").rsplit("/", 1)[1]
                out[f'bugcrowd:{BC}{e["briefUrl"]}'] = {"name": e["name"].strip(), "code": code,
                                                       "url": BC + e["briefUrl"], "paid": top > 0, "max_bounty": top}
            meta = j.get("paginationMeta") or {}
            if not j.get("engagements") or page * meta.get("limit", 24) >= meta.get("totalCount", 0):
                break
            page += 1
    return out


def bc_latest_changelog(code, pacer):
    try:
        cl = bc_get(f"/engagements/{code}/changelog.json", pacer).get("changelogs") or []
    except urllib.error.HTTPError as e:
        if e.code == 404:  # listed, but no published brief (some VDPs)
            return None
        raise
    latest = [c for c in cl if c.get("changelogState") == "Latest"] or sorted(
        cl, key=lambda c: c.get("publishedAt") or "", reverse=True)
    return latest[0]["id"] if latest else None


def _bc_group_pay(g):
    best = 0.0
    for r in (g.get("rewardRangeData") or {}).values():
        if isinstance(r, dict) and r.get("max"):
            best = max(best, float(r["max"]))
        elif isinstance(r, (int, float)) and r:  # e.g. "programMax": 10000
            best = max(best, float(r))
    return best


def bc_version(code, cid, paid, pacer):
    """Returns (scope {"assets","oos"}, policy)."""
    d = bc_get(f"/engagements/{code}/changelog/{cid}.json", pacer)["data"]
    brief = d.get("brief") or {}
    rewards, excl, assets, oos = {}, [], {}, []
    for g in d.get("scope") or []:
        name = g.get("name") or "group"
        idents = [((t.get("uri") or t.get("name") or "").strip(), t.get("category")) for t in g.get("targets") or []]
        if not g.get("inScope"):
            oos += [i for i, _ in idents if i]
            continue
        pay = _bc_group_pay(g) if paid else 0.0
        for ident, cat in idents:
            if ident and (ident not in assets or pay > assets[ident]["pay"]):
                assets[ident] = _asset(cat, pay > 0, None, pay, name)
        for prio, r in (g.get("rewardRangeData") or {}).items():
            if isinstance(r, dict) and r.get("max"):
                rewards[f"{name}.P{prio}"] = float(r["max"])
            elif isinstance(r, (int, float)) and r:
                rewards[f"{name}.{prio}"] = float(r)
    for rule in d.get("vrtScopeRules") or []:
        where = "" if rule.get("allTargets") else " (some targets)"
        for ids in (rule.get("vrtIds") or {}).values():
            for v in ids if isinstance(ids, list) else []:
                excl.append(f'{v.get("id", "").replace("_", " ")}: {rule.get("exclusionType", "")}{where}')
    text = "\n".join(html_text(brief.get(k)) for k in ("description", "targetsOverview", "additionalInformation"))
    policy = {"rules": text, "non_qualifying": sorted(set(excl)), "rewards": rewards,
              "testing": {"safeHarbor": (brief.get("safeHarborStatus") or {}).get("status") or ""}}
    return {"assets": assets, "oos": sorted(set(oos) - set(assets))}, policy


def bc_announcements(code, pacer):
    return [{"id": a["id"], "title": a.get("title") or "", "body": html_text(a.get("body"))}
            for a in bc_get(f"/engagements/{code}/announcements.json", pacer).get("announcements") or []]


def bc_programs(state, feed):
    """Returns ({key: program}, {key: policy}, {key: changelog url}, [(key, announcement)],
    failures, blocked message or None). Programs whose brief can't be read fall back to the
    last known version, then to the feed."""
    pacer = Pacer(BC_RPS)
    track = state.setdefault("bc", {})
    try:
        listing = list_bugcrowd(pacer)
    except Blocked as e:
        return None, {}, {}, [], 0, f"Bugcrowd answered {e} on the engagement list"
    stop = threading.Event()

    def work(key):
        if stop.is_set():
            raise Blocked("skipped after an earlier block")
        e, t = listing[key], track.get(key, {})
        try:
            cid = bc_latest_changelog(e["code"], pacer)
            anns = bc_announcements(e["code"], pacer) if e["paid"] else None
            fresh = cid and (cid != t.get("changelog") or "scope" not in t)
            version = bc_version(e["code"], cid, e["paid"], pacer) if fresh else None
        except Blocked:
            stop.set()
            raise
        return cid, anns, version

    policies, links, announcements, fails, blocked = {}, {}, [], 0, None
    for key, res, err in pmap(work, list(listing), 3):
        if err:
            if isinstance(err, Blocked):
                blocked = blocked or f"Bugcrowd answered {err}"
            else:
                fails += 1
                print(f"[!] bugcrowd {key}: {err}", file=sys.stderr)
            continue
        cid, anns, version = res
        t = track.setdefault(key, {})
        known = t.get("ann")
        if anns is not None:
            if known is not None:
                announcements += [(key, a) for a in anns if a["id"] not in set(known)]
            t["ann"] = sorted(a["id"] for a in anns)
        if version:
            t["scope"], policies[key] = version
            t["changelog"] = cid
            links[key] = f'{BC}/engagements/{listing[key]["code"]}/changelog/{cid}'
    programs = {}
    for key, e in listing.items():
        scope, src = track.get(key, {}).get("scope"), "api"
        if scope is None and key in feed:
            scope, src = {"assets": feed[key]["assets"], "oos": feed[key]["oos"]}, "feed"
        if scope is not None:
            programs[key] = {"platform": "bugcrowd", "name": e["name"], "url": e["url"],
                             "paid": e["paid"], "max_bounty": e["max_bounty"], "src": src, **scope}
    return programs, policies, links, announcements, fails, blocked


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
                res = list_intigriti_api()
                health(state, "Intigriti token", True)
                return res
            except Exception as e:
                health(state, "Intigriti token", False, f"({e}) Using the public list meanwhile. Expired? "
                       f"Create a new token and update the INTIGRITI_TOKEN secret.", threshold=1)
                return list_intigriti()
    sources = [("intigriti", ig_fn), ("yeswehack", list_yeswehack)]
    if H1_USER and H1_TOKEN:
        sources.append(("hackerone", list_hackerone))
    for plat, fn in sources:
        hint = {"hackerone": "Check the H1_USERNAME / H1_TOKEN secrets."}.get(plat, "")
        try:
            new = fn()
            health(state, f"{plat} program list", True)
        except Exception as e:
            print(f"[!] {plat} list: {e}", file=sys.stderr)
            health(state, f"{plat} program list", False, f"({e}) {hint}",
                   threshold=1 if plat == "hackerone" else 3)
            continue
        before = sum(1 for v in state["lists"].values() if v["platform"] == plat)
        if before >= 20 and len(new) < before * (1 - GLITCH_DROP):
            print(f"[!] {plat} list: {before} -> {len(new)} programs, treating as glitch", file=sys.stderr)
            continue
        got[plat] = new
    return got


def direct_diff(state, lists, out, now):
    """Diffs the direct program lists (status, new programs) into out. Mutates state."""
    seen = state["seen"]
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


REPORT_KEEP = timedelta(days=14)


def write_report(changes, now):
    """Appends this run to the day's report. Returns (path, this run's section as text)."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for old in REPORT_DIR.glob("*.md"):
        if now - datetime.fromtimestamp(old.stat().st_mtime, timezone.utc) > REPORT_KEEP:
            old.unlink()
    section = f"\n## {now:%Y-%m-%d %H:%M} UTC - {len(changes)} changes\n\n" + "".join(
        "- " + fmt(c).replace("\n    ", "  \n  ") + "\n" for c in changes)
    path = REPORT_DIR / f"{now:%Y-%m-%d}.md"
    with open(path, "a", encoding="utf-8") as f:
        f.write(section)
    return path, section


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


def ntfy(changes, report=None):
    """One push per program for positive changes (tap opens the program), one silent digest
    for negative ones. When something doesn't fit, this run's full report is attached."""
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        return
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")

    def send(payload):
        try:
            post_json(server, {"topic": topic, **payload})
        except Exception as e:
            print(f"[!] ntfy failed: {e}", file=sys.stderr)

    def send_report(title):
        if not report:
            return send({"title": title, "priority": 2})
        try:  # ntfy attachment: PUT the file body; headers must be ASCII
            req = urllib.request.Request(f"{server}/{topic}", data=report.encode("utf-8"), method="PUT", headers={
                "Filename": f"bbwatch-{datetime.now(timezone.utc):%Y%m%d-%H%M}.md", "Title": title,
                "Message": "Full report for this run attached (ntfy.sh keeps attachments ~3 hours).",
                "Priority": "2", "User-Agent": "bbwatch"})
            urllib.request.urlopen(req, timeout=30).read()
        except Exception as e:
            print(f"[!] ntfy attachment failed: {e}", file=sys.stderr)

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
    neg = [c for c in changes if c["kind"] in NEGATIVE]
    if neg:
        lines = [f'{_label(c["kind"])}: {c["name"]} [{c["platform"]}] {c["detail"]}'.strip() for c in neg]
        body = "\n".join(lines[:25]) + (f"\n+{len(lines) - 25} more" if len(lines) > 25 else "")
        send({"title": f"{len(neg)} negative changes", "message": body[:3900],
              "tags": ["small_red_triangle_down"], "priority": 1})

    if len(items) > NTFY_MAX or len(neg) > 25:
        send_report(f"+{max(len(items) - NTFY_MAX, 0)} more programs changed - full report attached")


def alert(changes, report=None):
    ntfy(changes, report)
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
    feed, fetched, feed_digest = snapshot()
    new = dict(feed)
    baseline = not STATE.exists()
    state = ({"version": STATE_VERSION, "programs": {}, "gone": {}, "lists": {}, "policy": {},
              "seen": set()} if baseline else load())
    check_feed(state, fetched, feed_digest, now)
    lists = fetch_lists(state)

    # Direct platform sources, run in parallel (each paced for its own host). Each returns the
    # platform's programs; where it works it replaces the feed for that platform.
    jobs = {}
    if DIRECT:
        if IG_TOKEN and "intigriti" in lists and any("id" in v for v in lists["intigriti"].values()):
            jobs["intigriti"] = lambda: intigriti_programs(state, lists["intigriti"], now)
        if "hackerone" in lists:
            jobs["hackerone"] = lambda: h1_programs(state, lists["hackerone"], feed)
        if "yeswehack" in lists:
            jobs["yeswehack"] = lambda: ywh_programs(state, lists["yeswehack"])
        jobs["bugcrowd"] = lambda: bc_programs(state, feed)
    results = {plat: (res, err) for plat, res, err in pmap(lambda p: jobs[p](), list(jobs), len(jobs) or 1)}

    direct, policies, links, ig_policy_diffs, announcements = {}, {}, {}, [], []
    for plat, (res, err) in results.items():
        if err:
            print(f"[!] {plat} direct: {err}", file=sys.stderr)
            health(state, f"{plat} direct source", False, f"({err}) Falling back to the feed.")
            continue
        if plat == "intigriti":
            programs, ig_policy_diffs = res
            fails = 0
        elif plat == "bugcrowd":
            programs, pol, lnk, announcements, fails, blocked = res
            policies.update(pol)
            links.update(lnk)
            health(state, "Bugcrowd", not blocked, f"{blocked}. Checks stopped for that run; "
                   f"if this repeats, lower the BBWATCH_BC_RPS variable.", threshold=2)
        elif plat == "hackerone":
            programs, pol, fails, limited = res
            policies.update(pol)
        else:
            programs, pol, fails = res
            policies.update(pol)
        checked = max(len(programs), 1)
        health(state, f"{plat} scope/policy fetches", fails <= checked * 0.2,
               f"{fails} of {checked} programs failed this run.")
        if programs:
            direct[plat] = programs

    # Each platform's programs come from its direct source when that worked, else the feed.
    # Switching source either way re-baselines that platform silently (different coverage).
    sources = state.setdefault("sources", {"intigriti": state.pop("ig_source", "feed")})
    for plat in PLATFORMS:
        src = "api" if plat in direct else "feed"
        if plat in direct:
            new = {k: v for k, v in new.items() if v["platform"] != plat}
            new.update(direct[plat])
            fetched.add(plat)
        if sources.get(plat, "feed") != src and not baseline:
            print(f"[*] {plat} source {sources.get(plat, 'feed')} -> {src}: re-baselining")
            state["programs"] = {k: v for k, v in state["programs"].items() if v["platform"] != plat}
            state["programs"].update({k: v for k, v in new.items() if v["platform"] == plat})
            state["gone"] = {k: v for k, v in state["gone"].items() if not k.startswith(plat + ":")}
            state["seen"] |= {k for k, v in new.items() if v["platform"] == plat}
            if plat == "intigriti":
                state["lists"] = {k: v for k, v in state["lists"].items() if v["platform"] != plat}
                ig_policy_diffs = []
        sources[plat] = src

    if not new:
        sys.exit("[!] no data fetched")
    if baseline:
        state["programs"] = new
        state["seen"] = set(new)
        direct_diff(state, lists, Changes(), now)               # baseline lists silently
        apply_policies(state, policies, lambda k: None, Changes())  # and policies
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

    # A program whose scope came from a different source than last run (e.g. feed fallback
    # one run, API the next) is adopted silently: the sources format identifiers differently.
    for key, n in new.items():
        if key in old and old[key].get("src") != n.get("src"):
            old[key] = n

    changes = diff(state, new, fetched, now, authoritative=frozenset(lists))
    state["programs"] = new
    direct_diff(state, lists, changes, now)
    lookup = lambda k: new.get(k) or state["lists"].get(k)
    for key, before, after in ig_policy_diffs:
        prog = lookup(key)
        if prog and wanted(prog):
            diff_policy(key, prog, before, after, changes)
    apply_policies(state, policies, lookup, changes, links)
    for key, a in announcements:
        prog = new.get(key)
        if prog and wanted(prog):
            text = f'{a["title"]}: {a["body"]}'
            changes.add("ANNOUNCEMENT", key, {**prog, "url": prog["url"] + "/announcements"},
                        text[:300], is_ai(text), bool(BONUS_RE.search(text)))
    for w in WARNINGS:
        changes.add("WARNING", "bbwatch", {"platform": "bbwatch", "name": "bbwatch needs attention",
                                           "url": "https://github.com/sinansinansi/bbwatch/actions",
                                           "paid": True, "max_bounty": None}, w)
    sort_changes(changes)
    save(state)
    if not changes:
        print("[=] no changes")
        return
    path, section = write_report(changes, now)
    alert(changes, section)
    for c in changes:
        print(fmt(c))
    print(f"[+] {len(changes)} changes -> {path}")

if __name__ == "__main__":
    main()
