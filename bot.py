#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scheduled tasks runner: watches configured public data feeds and sends a
Telegram notification when something new appears. Runs one check per
invocation; scheduling is handled externally (cron / CI scheduler).

Feeds and options live in config.json. Python 3.8+, standard library only.

Usage:
    python bot.py                 # one monitoring cycle (schedule it externally)
    python bot.py --bootstrap     # record current items as known, send nothing
    python bot.py --dry-run       # don't send to Telegram, print messages
    python bot.py --demo          # treat the newest item as new (tests full path)
    python bot.py --hello         # send a test message to verify Telegram config
"""

import argparse
import gzip
import html as html_mod
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
STATE_PATH = os.path.join(BASE_DIR, "state.json")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
TIMEOUT = 30
PAUSE_BETWEEN_REQUESTS = 0.8          # be polite to the platforms
TELEGRAM_MAX_LEN = 4096
H1_PAGE_SIZE = 50
BC_PAGE_SIZE = 24
IT_PAGES = 2                          # page 1 = newest first

PLATFORM_META = {
    "hackerone":   {"label": "HackerOne",   "emoji": "⚡"},
    "bugcrowd":    {"label": "Bugcrowd",    "emoji": "🐞"},
    "intigriti":   {"label": "Intigriti",   "emoji": "🧩"},
    "yeswehack":   {"label": "YesWeHack",   "emoji": "🎯"},
    "standoff365": {"label": "Standoff365", "emoji": "🐻"},
}


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC] {msg}", flush=True)


# ----------------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------------

def http(url, method="GET", data=None, headers=None, opener=None, retries=1):
    """Fetch a URL, return (status, bytes). JSON body auto-encoded."""
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode() if data is not None else None
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    last_err = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with (opener.open(req, timeout=TIMEOUT) if opener
                  else urllib.request.urlopen(req, timeout=TIMEOUT)) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                return r.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                if e.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            except Exception:
                pass
            return e.code, raw
        except Exception as e:
            # some hosts (standoff365) ship a broken chain on some systems:
            # retry once without verification rather than losing the platform
            if "CERTIFICATE_VERIFY_FAILED" in str(getattr(e, "reason", e)):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                        raw = r.read()
                        if r.headers.get("Content-Encoding") == "gzip":
                            raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                        return r.status, raw
                except Exception as e2:
                    last_err = e2
                    if attempt < retries:
                        time.sleep(2)
                    continue
            last_err = e
            if attempt < retries:
                time.sleep(2)
    return 0, f"{type(last_err).__name__}: {last_err}".encode()


def http_json(url, method="GET", data=None, headers=None, opener=None, retries=1):
    st, raw = http(url, method, data, headers, opener, retries)
    if st != 200:
        raise RuntimeError(f"HTTP {st} from {url}: {raw[:200].decode('utf-8', 'replace')}")
    return json.loads(raw)


def html_text(html_str):
    """Strip tags -> plain text lines."""
    text = html_mod.unescape(re.sub(r"<[^>]+>", "\n", html_str))
    return [l.strip() for l in text.splitlines() if l.strip()]


# ----------------------------------------------------------------------------
# Program model
# ----------------------------------------------------------------------------

class Program:
    __slots__ = ("platform", "key", "name", "url", "launched", "bounties", "bounty_note")

    def __init__(self, platform, key, name, url, launched=None, bounties=None, bounty_note=""):
        self.platform = platform
        self.key = key
        self.name = name
        self.url = url
        self.launched = launched
        self.bounties = bounties
        self.bounty_note = bounty_note


# ----------------------------------------------------------------------------
# Platform fetchers (list of all currently-public programs)
# ----------------------------------------------------------------------------

class HackerOne:
    """Anonymous access via the web GraphQL endpoint (no account needed)."""

    SEARCH_Q = """query OpportunityCategoryElasticQuery($from: Int, $size: Int, $query: OpportunitiesQuery!, $filter: QueryInput!, $sort: [SortInput!], $post_filters: OpportunitiesFilterInput) {
  opportunities_search(query: $query, filter: $filter, from: $from, size: $size, sort: $sort, post_filters: $post_filters) {
    nodes { ... on OpportunityDocument { id handle name launched_at state offers_bounties submission_state minimum_bounty_table_value maximum_bounty_table_value currency __typename } }
    total_count
    __typename
  }
  __typename
}"""

    SCOPE_Q = """query TeamScopeQuery($handle: String!) {
  team(handle: $handle) {
    handle
    name
    structured_scopes(first: 60) {
      edges { node { asset_identifier asset_type eligible_for_bounty instruction __typename } __typename }
      __typename
    }
    __typename
  }
}"""

    def __init__(self):
        import http.cookiejar
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def _bootstrap(self):
        st, page = http("https://hackerone.com/opportunities",
                        headers={"Accept": "text/html"}, opener=self.opener)
        m = re.search(rb'name="csrf-token"\s+content="([^"]+)"', page)
        if st != 200 or not m:
            raise RuntimeError(f"cannot get H1 csrf token (HTTP {st})")
        self.csrf = m.group(1).decode()

    def _gql(self, operation, query, variables, referer):
        if not self.csrf:
            self._bootstrap()
        st, raw = http("https://hackerone.com/graphql", method="POST",
                       data={"operationName": operation, "query": query, "variables": variables},
                       headers={"X-CSRF-Token": self.csrf, "Referer": referer,
                                "Origin": "https://hackerone.com",
                                "X-Requested-With": "XMLHttpRequest"},
                       opener=self.opener, retries=2)
        if st != 200:
            raise RuntimeError(f"H1 graphql HTTP {st}: {raw[:150].decode('utf-8', 'replace')}")
        j = json.loads(raw)
        if j.get("errors"):
            raise RuntimeError("H1 graphql: " + j["errors"][0].get("message", "")[:200])
        return j.get("data") or {}

    def fetch_programs(self):
        if not self.csrf:
            self._bootstrap()
        progs, seen = [], set()
        for page in range(2):                       # 2 pages = 100 newest
            variables = {"size": H1_PAGE_SIZE, "from": page * H1_PAGE_SIZE,
                         "query": {}, "filter": {},
                         "sort": [{"field": "launched_at", "direction": "DESC"}],
                         "post_filters": {}}
            data = self._gql("OpportunityCategoryElasticQuery", self.SEARCH_Q,
                             variables, "https://hackerone.com/opportunities")
            search = data.get("opportunities_search") or {}
            nodes = search.get("nodes") or []
            for n in nodes:
                handle = n.get("handle")
                if not handle or handle in seen:
                    continue
                seen.add(handle)
                lo, hi = n.get("minimum_bounty_table_value"), n.get("maximum_bounty_table_value")
                note = ""
                if hi:
                    cur = {"usd": "$", "eur": "€", "gbp": "£"}.get(
                        (n.get("currency") or "").lower(), n.get("currency") or "")
                    note = f" ({cur}{lo} – {cur}{hi})"
                progs.append(Program(
                    "hackerone", handle, n.get("name") or handle,
                    f"https://hackerone.com/{handle}",
                    launched=n.get("launched_at"),
                    bounties=bool(n.get("offers_bounties")),
                    bounty_note=note))
            if len(nodes) < H1_PAGE_SIZE:
                break
            time.sleep(PAUSE_BETWEEN_REQUESTS)
        return progs

    def fetch_scope(self, prog):
        data = self._gql("TeamScopeQuery", self.SCOPE_Q, {"handle": prog.key},
                         f"https://hackerone.com/{prog.key}")
        team = data.get("team") or {}
        edges = ((team.get("structured_scopes") or {}).get("edges")) or []
        return [(e["node"].get("asset_identifier"), e["node"].get("asset_type"))
                for e in edges if e.get("node", {}).get("asset_identifier")]


class Bugcrowd:
    LIST = "https://bugcrowd.com/engagements.json"

    def fetch_programs(self):
        progs, seen = [], set()
        for page in range(1, 16):                   # 24/page, totalCount ~300
            j = http_json(f"{self.LIST}?page={page}")
            items = j.get("engagements") or []
            if not items:
                break
            for it in items:
                brief = it.get("briefUrl") or ""
                if not brief or brief in seen or it.get("isPrivate"):
                    continue
                seen.add(brief)
                reward = ((it.get("rewardSummary") or {}).get("summary")) or ""
                has_reward = bool(reward and re.search(r"\d", reward))
                progs.append(Program(
                    "bugcrowd", brief, it.get("name") or brief,
                    "https://bugcrowd.com" + brief,
                    bounties=has_reward,
                    bounty_note=f" ({reward})" if has_reward else ""))
            total = (j.get("paginationMeta") or {}).get("totalCount") or 0
            if page * BC_PAGE_SIZE >= total:
                break
            time.sleep(PAUSE_BETWEEN_REQUESTS)
        return progs

    def fetch_scope(self, prog):
        st, raw = http("https://bugcrowd.com" + prog.key,
                       headers={"Accept": "text/html"}, retries=2)
        if st != 200:
            raise RuntimeError(f"BC brief page HTTP {st}")
        m = re.search(rb'changelog/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', raw)
        if not m:
            raise RuntimeError("BC changelog uuid not found on brief page")
        j = http_json(f"https://bugcrowd.com{prog.key}/changelog/{m.group(1).decode()}/preview",
                      headers={"Accept": "application/json",
                               "X-Requested-With": "XMLHttpRequest"}, retries=2)
        sd = (j.get("reviews") or {}).get("scopeDetails") or {}
        val = sd.get("current") if isinstance(sd, dict) else sd
        if not val:
            raise RuntimeError("BC scopeDetails empty")
        lines = html_text(val)
        # drop markdown headers / separators / empty fluff, keep real content
        pairs = [(l, None) for l in lines
                 if not l.startswith("##") and set(l) != {"-"} and len(l) > 2]
        return pairs


class Intigriti:
    LIST = "https://www.intigriti.com/researchers/bug-bounty-programs"

    def fetch_programs(self):
        progs, seen = [], set()
        for page in range(1, IT_PAGES + 1):
            st, raw = http(f"{self.LIST}?programs_prod%5Bpage%5D={page}",
                           headers={"Accept": "text/html"})
            if st != 200:
                raise RuntimeError(f"IT list page {page} HTTP {st}")
            htmltxt = raw.decode("utf-8", "replace")
            names = re.findall(r"<h4[^>]*>([^<]+)</h4>", htmltxt)
            links = re.findall(r"https://app\.intigriti\.com/programs/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)", htmltxt)
            if not links:
                break
            for i, (company, handle) in enumerate(links):
                key = f"{company}/{handle}"
                if key in seen:
                    continue
                seen.add(key)
                name = html_mod.unescape(names[i]).strip() if i < len(names) else handle
                # bounty type: look for the tag shortly before this link
                pos = htmltxt.find(f"https://app.intigriti.com/programs/{key}")
                window = htmltxt[max(0, pos - 2500):pos] if pos > 0 else ""
                is_bounty = "Bug bounty program" in window
                progs.append(Program("intigriti", key, name,
                                     f"https://app.intigriti.com/programs/{key}",
                                     bounties=is_bounty))
            time.sleep(PAUSE_BETWEEN_REQUESTS)
        return progs

    def fetch_scope(self, prog):
        raise RuntimeError("Intigriti scope needs a researcher account (see README)")


class YesWeHack:
    LIST = "https://api.yeswehack.com/programs"

    def fetch_programs(self):
        progs, seen = [], set()
        page = 1
        while page <= 10:
            j = http_json(f"{self.LIST}?page={page}")
            nb_pages = (j.get("pagination") or {}).get("nb_pages") or 1
            for it in j.get("items") or []:
                slug = it.get("slug")
                if not slug or slug in seen or it.get("archived") or not it.get("public"):
                    continue
                seen.add(slug)
                progs.append(Program(
                    "yeswehack", slug, it.get("title") or slug,
                    f"https://yeswehack.com/programs/{slug}",
                    launched=it.get("last_update_at"),
                    bounties=bool(it.get("bounty"))))
            if page >= nb_pages:
                break
            page += 1
            time.sleep(PAUSE_BETWEEN_REQUESTS)
        return progs

    def fetch_scope(self, prog):
        j = http_json(f"https://api.yeswehack.com/programs/{prog.key}")
        pairs = []
        for s in j.get("scopes") or []:
            entry = s.get("scope") or ""
            extra = []
            if s.get("scope_type_name"):
                extra.append(s["scope_type_name"])
            if s.get("asset_value"):
                extra.append(s["asset_value"])
            line = entry + (f" [{', '.join(extra)}]" if extra else "")
            pairs.append((line, s.get("scope_type") or None))
        return pairs


class Standoff365:
    LIST = "https://bugbounty.standoff365.com/programs?lang=en"

    def fetch_programs(self):
        st, raw = http(self.LIST)
        if st != 200:
            raise RuntimeError(f"S365 list HTTP {st}")
        htmltxt = raw.decode("utf-8", "replace")
        m = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
                      htmltxt, re.S)
        if not m:
            raise RuntimeError("S365 __NEXT_DATA__ not found")
        pp = json.loads(m.group(1))["props"]["pageProps"]
        progs, seen = [], set()
        for it in pp.get("programs") or []:
            if it.get("archivedAt") or it.get("visibility") != "public":
                continue
            slug = it.get("slug") or str(it.get("id"))
            if slug in seen:
                continue
            seen.add(slug)
            desc = it.get("description") or it.get("shortDescription") or ""
            # Standoff doesn't flag paid vs VDP in the list payload — most
            # programs carry a reward, so sniff the description text
            paid = bool(re.search(r"рубл|₽|вознагражде|reward|bounty",
                                  desc, re.I))
            progs.append(Program(
                "standoff365", slug, it.get("name") or slug,
                f"https://bugbounty.standoff365.com/programs/{slug}",
                launched=it.get("publishedAt") or it.get("createdAt"),
                bounties=paid))
        return progs

    # a scope-section heading on the program page
    SCOPE_HEAD = re.compile(r"^#{0,6}\s*\**\s*(скоуп|scope|область действия)", re.I)
    # a heading that starts a post-scope section (rewards, rules, ...)
    STOP_HEAD = re.compile(r"(вознагражде|наград|reward|правил|требован|недопустимого события для)", re.I)

    @staticmethod
    def _scope_entry(line):
        """Return the line if it looks like a published scope entry
        (wildcard / domain / IP / IP-range / URL / mail-domain)."""
        l = line.strip().strip("`").strip()
        l = re.sub(r"^\*\*(.+)\*\*$", r"\1", l).strip()   # markdown bold
        if not l or len(l) > 160:
            return None
        if l.startswith("*."):
            return l
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?(?:\s*-\s*\d{1,3}(?:\.\d{1,3}){3})?\.?$", l):
            return l
        if re.match(r"^[a-zA-Z0-9*-]+(?:\.[a-zA-Z0-9*-]+)+\.?,?$", l):
            return l
        if re.search(r"https?://", l):
            return l
        if re.search(r"@[\w.-]+\.[a-zA-Z]{2,}", l):
            return l
        return None

    def fetch_scope(self, prog):
        """The exact scope section from the program description — wildcards,
        IPs, IP ranges, mail domains and URLs exactly as published."""
        st, raw = http(self.LIST)
        if st != 200:
            raise RuntimeError(f"S365 list HTTP {st}")
        htmltxt = raw.decode("utf-8", "replace")
        m = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
                      htmltxt, re.S)
        pp = json.loads(m.group(1))["props"]["pageProps"]
        desc = ""
        for it in pp.get("programs") or []:
            if (it.get("slug") or str(it.get("id"))) == prog.key:
                desc = it.get("description") or it.get("shortDescription") or ""
                break
        if not desc:
            raise RuntimeError("S365 description not found")

        lines = desc.splitlines()
        pairs, start = [], None
        for i, l in enumerate(lines):
            if self.SCOPE_HEAD.match(l.strip()):
                start = i + 1
                break
        if start is not None:
            for l in lines[start:start + 80]:
                s = l.strip()
                if pairs and re.match(r"^#{1,6}\s*\**\s*$", s):
                    break                                   # bare ### separator
                if self.STOP_HEAD.search(s):
                    break
                if s.startswith("#"):
                    continue                                # sub-heading
                e = self._scope_entry(re.sub(r"^(?:[-•*]\s+)+", "", s))
                if e and e not in [p[0] for p in pairs]:
                    pairs.append((e, None))
                if len(pairs) >= 20:
                    break
        if not pairs:
            # fallback: bare domain tokens anywhere in the description
            for tok in re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", desc.lower()):
                tok = tok.strip(".,;*")
                if tok and tok not in [p[0] for p in pairs]:
                    pairs.append((tok, None))
        return pairs[:15]


FETCHERS = {
    "hackerone": HackerOne,
    "bugcrowd": Bugcrowd,
    "intigriti": Intigriti,
    "yeswehack": YesWeHack,
    "standoff365": Standoff365,
}

# platforms whose fetcher returns the COMPLETE public list (safe for
# removed-program detection; the others only fetch the newest pages)
FULL_LIST = {
    "hackerone": False,
    "bugcrowd": True,
    "intigriti": False,
    "yeswehack": True,
    "standoff365": True,
}

# ---------------------------------------------------------------------------
# Fallback dataset: arkadiyt/bounty-targets-data mirrors every platform's
# full public list (with scope) and is refreshed every ~30 minutes.  Used
# when a platform's direct source breaks, so the bot keeps working forever.
# ---------------------------------------------------------------------------

DATASET_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/{}_data.json"


def dataset_programs(platform):
    st, raw = http(DATASET_URL.format(platform))
    if st != 200:
        raise RuntimeError(f"dataset HTTP {st} ({len(raw)} bytes)")
    items = json.loads(raw)
    progs = []
    for p in items:
        try:
            if platform == "hackerone":
                progs.append(Program(
                    platform, p["handle"], p.get("name") or p["handle"],
                    p.get("url") or f"https://hackerone.com/{p['handle']}",
                    bounties=bool(p.get("offers_bounties"))))
            elif platform == "bugcrowd":
                url = p.get("url") or ""
                key = url.replace("https://bugcrowd.com", "") or p["name"]
                mp = p.get("max_payout")
                progs.append(Program(
                    platform, key, p.get("name") or key, url,
                    bounties=bool(mp), bounty_note=f" (up to ${mp})" if mp else ""))
            elif platform == "intigriti":
                co, h = p.get("company_handle"), p.get("handle")
                if not co or not h:
                    continue
                mx = (p.get("max_bounty") or {}).get("value") or 0
                cur = (p.get("max_bounty") or {}).get("currency") or ""
                sym = {"EUR": "€", "USD": "$"}.get(cur, cur)
                progs.append(Program(
                    platform, f"{co}/{h}", p.get("name") or h,
                    f"https://app.intigriti.com/programs/{co}/{h}",
                    bounties=bool(mx), bounty_note=f" (up to {sym}{mx})" if mx else ""))
            elif platform == "yeswehack":
                if not p.get("public") or p.get("disabled"):
                    continue
                mx = p.get("max_bounty")
                progs.append(Program(
                    platform, p["id"], p.get("name") or p["id"],
                    f"https://yeswehack.com/programs/{p['id']}",
                    bounties=bool(mx)))
        except (KeyError, TypeError):
            continue
    return progs


def dataset_scope(platform, key):
    """Look up a program's in-scope targets in the fallback dataset."""
    st, raw = http(DATASET_URL.format(platform))
    if st != 200:
        return []
    for p in json.loads(raw):
        if platform == "hackerone":
            pk = p.get("handle")
        elif platform == "bugcrowd":
            pk = (p.get("url") or "").replace("https://bugcrowd.com", "")
        elif platform == "intigriti":
            pk = f"{p.get('company_handle')}/{p.get('handle')}"
        elif platform == "yeswehack":
            pk = p.get("id")
        else:
            return []
        if pk != key:
            continue
        pairs = []
        for t in (p.get("targets") or {}).get("in_scope") or []:
            ident = (t.get("asset_identifier") or t.get("target")
                     or t.get("uri") or t.get("endpoint") or "")
            if not ident:
                continue
            typ = (t.get("asset_type") or t.get("type") or "").strip()
            line = ident + (f" [{typ}]" if typ and typ.lower() != "all" else "")
            pairs.append((line, typ or None))
        return pairs
    return []


# ----------------------------------------------------------------------------
# Config / state
# ----------------------------------------------------------------------------

def load_config():
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    # environment wins over empty config values (secrets come from env)
    cfg["telegram_bot_token"] = (cfg.get("telegram_bot_token") or "").strip() \
        or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    cfg["telegram_chat_id"] = (cfg.get("telegram_chat_id") or "").strip() \
        or os.environ.get("TELEGRAM_CHAT_ID", "")
    cfg.setdefault("disable_link_preview", True)
    cfg.setdefault("only_bounties", False)
    cfg.setdefault("exclude_hardware_only", True)
    cfg.setdefault("notify_removed", False)
    cfg.setdefault("use_fallback_dataset", True)
    cfg.setdefault("max_scope_lines", 10)
    cfg.setdefault("utc_offset_hours", 0)
    cfg.setdefault("platforms", {k: True for k in FETCHERS})
    return cfg


def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {"platforms": {}}


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATE_PATH)


# ----------------------------------------------------------------------------
# Telegram
# ----------------------------------------------------------------------------

def send_telegram(cfg, text):
    token, chat_id = cfg["telegram_bot_token"], cfg["telegram_chat_id"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": bool(cfg.get("disable_link_preview", True))}
    st, raw = http(url, method="POST", data=payload)
    j = json.loads(raw) if raw[:1] == b"{" else {}
    if st != 200 or not j.get("ok"):
        raise RuntimeError(f"telegram send failed: HTTP {st} {raw[:200].decode('utf-8', 'replace')}")


def build_message(prog, scope_lines, cfg):
    meta = PLATFORM_META[prog.platform]
    esc = html_mod.escape
    lines = [
        f"🆕 New Program — {meta['label']} {meta['emoji']}",
        "",
        f"🏢 <b>{esc(prog.name)}</b>",
        f"🔗 {esc(prog.url)}",
    ]
    if prog.bounties is True:
        lines.append(f"💰 Bounties: Yes{esc(prog.bounty_note)}")
    elif prog.bounties is False:
        lines.append("💰 Bounties: No (VDP)")
    if prog.launched:
        try:
            dt = datetime.fromisoformat(prog.launched.replace("Z", "+00:00"))
            stamp = f"{dt.strftime('%Y-%m-%d %H:%M UTC')}"
            off = cfg.get("utc_offset_hours") or 0
            if off:
                local = dt + timedelta(hours=off)
                stamp += f" — {local.strftime('%H:%M your local time')}"
            lines.append(f"📅 {stamp}")
        except ValueError:
            lines.append(f"📅 {esc(prog.launched)}")
    if scope_lines:
        lines.append("")
        shown = scope_lines[: cfg["max_scope_lines"]]
        lines.append(f"🎯 <b>Scope</b> ({len(scope_lines)} in-scope targets):")
        lines += [f"• <code>{esc(s)}</code>" for s in shown]
        if len(scope_lines) > len(shown):
            lines.append(f"• … +{len(scope_lines) - len(shown)} more — full scope at the link")
    else:
        lines.append("")
        lines.append("🎯 Scope: see the program page")
    msg = "\n".join(lines)
    if len(msg) > TELEGRAM_MAX_LEN - 20:                # keep headroom
        msg = msg[: TELEGRAM_MAX_LEN - 23] + "…"
    return msg


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def run_cycle(cfg, state, dry_run=False, bootstrap=False, demo=False):
    enabled = [p for p, on in (cfg.get("platforms") or {}).items() if on]
    if not enabled:
        log("No platforms enabled in config.platforms")
        return

    all_programs = {}
    for platform in enabled:
        progs = []
        try:
            progs = FETCHERS[platform]().fetch_programs()
            log(f"{platform}: {len(progs)} public programs")
        except Exception as e:
            log(f"{platform}: direct fetch failed - {e}")
            if cfg.get("use_fallback_dataset", True):
                try:
                    progs = dataset_programs(platform)
                    log(f"{platform}: fallback dataset: {len(progs)} programs")
                except Exception as e2:
                    log(f"{platform}: fallback dataset failed - {e2}")
        if progs:
            all_programs[platform] = progs
        time.sleep(PAUSE_BETWEEN_REQUESTS)

    known = state.setdefault("platforms", {})
    if bootstrap or all(p not in known for p in all_programs):
        for platform, progs in all_programs.items():
            known[platform] = {p.key: {"name": p.name, "launched": p.launched, "url": p.url}
                               for p in progs}
        save_state(state)
        total = sum(len(v) for v in all_programs.values())
        log(f"Bootstrap: recorded {total} existing programs. "
            f"You will be notified from the next run onwards.")
        if not dry_run:
            try:
                send_telegram(cfg, "🤖 <b>Bug bounty monitor started.</b>\n"
                              f"Now watching <b>{total}</b> programs across "
                              f"{len(all_programs)} platform(s). "
                              "You'll get a message whenever a new program launches.")
                log("Bootstrap hello message sent")
            except Exception as e:
                log(f"bootstrap telegram message failed: {e}")
        return

    new_programs = []
    for platform, progs in all_programs.items():
        pk = known.setdefault(platform, {})
        for p in progs:
            if p.key not in pk:
                new_programs.append(p)

    if demo and all_programs:
        for progs in all_programs.values():
            if progs:
                new_programs.append(progs[0])       # newest program, for testing
                break

    # filter, newest first
    if cfg.get("only_bounties"):
        for p in new_programs:
            if p.bounties is not True:
                # record VDPs so they are never re-detected or announced later
                known.setdefault(p.platform, {})[p.key] = {
                    "name": p.name, "launched": p.launched, "url": p.url,
                    "skipped": "vdp"}
        new_programs = [p for p in new_programs if p.bounties is True]
    new_programs.sort(key=lambda p: p.launched or "", reverse=True)

    # programs that disappeared from a fully-listed platform (idea borrowed
    # from Alikhalkhali/programs-watcher)
    removed = []
    if cfg.get("notify_removed"):
        for platform, progs in all_programs.items():
            if not FULL_LIST.get(platform):
                continue
            pk = known.get(platform) or {}
            current = {p.key for p in progs}
            for key, meta in list(pk.items()):
                if key.startswith("_") or key in current:
                    continue
                removed.append((platform, key, meta))
                del pk[key]

    if not new_programs and not removed:
        log("No changes.")
        return

    if removed:
        log(f"{len(removed)} removed program(s): "
            + ", ".join(f"{platform}/{key}" for platform, key, _ in removed))
    for platform, key, meta in removed[:10]:
        name = meta.get("name") or key
        msg = (f"❌ <b>Program closed/removed — {PLATFORM_META[platform]['label']}</b>\n\n"
               f"🏢 {html_mod.escape(name)}\n"
               f"🔗 {html_mod.escape(meta.get('url') or 'https://' + platform + '.com')}\n\n"
               "It is no longer on the platform's public list.")
        if dry_run:
            print("=" * 60)
            print(re.sub(r"</?[a-z]+>", "", msg))
        else:
            try:
                send_telegram(cfg, msg)
            except Exception as e:
                log(f"  telegram send failed (removed {key}): {e}")
            time.sleep(1.2)

    log(f"{len(new_programs)} new program(s): "
        + ", ".join(f"{p.platform}/{p.key}" for p in new_programs))

    for prog in new_programs[:10]:                  # safety cap per cycle
        scope_pairs = []                            # (message line, type) tuples
        time.sleep(PAUSE_BETWEEN_REQUESTS)          # avoid bursting the platform
        fetcher = FETCHERS[prog.platform]()
        try:
            scope_pairs = fetcher.fetch_scope(prog) or []
            log(f"  scope {prog.platform}/{prog.key}: {len(scope_pairs)} targets")
        except Exception as e:
            if cfg.get("use_fallback_dataset", True):
                try:
                    scope_pairs = dataset_scope(prog.platform, prog.key)
                    if scope_pairs:
                        log(f"  scope {prog.platform}/{prog.key}: {len(scope_pairs)} targets (dataset)")
                except Exception:
                    pass
            if not scope_pairs:
                log(f"  scope {prog.platform}/{prog.key}: unavailable ({e})")

        # hardware-only filter: needs typed targets (H1/YWH direct, or the
        # fallback dataset for BC/IT).  A program is skipped only when EVERY
        # known target type is hardware — anything else passes.
        types = {t for _, t in scope_pairs if t}
        if not types and prog.platform != "standoff365" and cfg.get("use_fallback_dataset", True):
            try:
                types = {t for _, t in dataset_scope(prog.platform, prog.key) if t}
            except Exception:
                pass
        if cfg.get("exclude_hardware_only", True) and types and types <= {"hardware"}:
            log(f"  skipped (hardware-only): {prog.platform}/{prog.key}")
            known.setdefault(prog.platform, {})[prog.key] = {
                "name": prog.name, "launched": prog.launched, "url": prog.url,
                "skipped": "hardware"}
            continue

        msg = build_message(prog, [l for l, _ in scope_pairs], cfg)
        if dry_run:
            print("=" * 60)
            print(re.sub(r"</?[a-z]+>", "", msg))
        else:
            try:
                send_telegram(cfg, msg)
                log(f"  sent: {prog.platform}/{prog.key}")
            except Exception as e:
                log(f"  telegram send failed for {prog.key}: {e}")
            time.sleep(1.2)
        known.setdefault(prog.platform, {})[prog.key] = {
            "name": prog.name, "launched": prog.launched, "url": prog.url}

    save_state(state)


def maybe_update_heartbeat(state):
    """On GitHub Actions, refresh HEARTBEAT.md once/day so the repo keeps
    activity and GitHub never disables the schedule (60-day inactivity rule)."""
    if not os.environ.get("GITHUB_ACTIONS"):
        return False
    now = time.time()
    if now - state.get("last_heartbeat", 0) < 20 * 3600:
        return False
    state["last_heartbeat"] = now
    with open(os.path.join(BASE_DIR, "HEARTBEAT.md"), "w", encoding="utf-8") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()}\n")
    return True


def main():
    ap = argparse.ArgumentParser(description="Bug bounty new-program monitor -> Telegram")
    ap.add_argument("--bootstrap", action="store_true",
                    help="record current programs as known without notifying")
    ap.add_argument("--dry-run", action="store_true",
                    help="print messages instead of sending to Telegram")
    ap.add_argument("--demo", action="store_true",
                    help="treat the newest program as new (tests the full pipeline)")
    ap.add_argument("--hello", action="store_true",
                    help="send a test message to verify the Telegram config")
    args = ap.parse_args()

    cfg = load_config()
    state = load_state()

    if args.hello:
        send_telegram(cfg, "🤖 <b>Test message</b> — your bug bounty monitor "
                           "is configured correctly ✅")
        log("Test message sent OK")
        return

    run_cycle(cfg, state, dry_run=args.dry_run,
              bootstrap=args.bootstrap, demo=args.demo)
    if maybe_update_heartbeat(state):
        save_state(state)


if __name__ == "__main__":
    main()
