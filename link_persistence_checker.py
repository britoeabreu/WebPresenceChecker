#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
link_persistence_checker.py
===========================

Checks whether the web presence of a list of project links still exists and produces the indicators used to build the presence score of the smart-tourism
resilience measure:

    DomainFound      the registrable domain (e.g. example.com) responds
    SubdomainFound   the subdomain host (e.g. visit.example.com) responds
                     -- only when the link is hosted on a subdomain
                        (a leading "www." is NOT considered a subdomain)
    PageFound        the full link responds
                     -- only when the link points to a page
                        (a path below the root, or a query string)

and PresenceScore = 0 if not DomainFound, else 1 + (SubdomainFound or PageFound).

Resilience features
-------------------
* Public-suffix aware domain extraction (x.co.uk, x.gov.uk, x.com.tr ...).
* HEAD first, GET fallback when HEAD fails; browser-like User-Agent.
* Scheme fallback (https <-> http) and www/no-www variants.
* Timeouts, bounded retries with exponential back-off for transient errors
  (timeouts, connection resets, 429/5xx); no retry for definitive answers.
* Invalid TLS certificates are treated as "host alive" (flagged in Notes).
* 401/403 ("blocked") responses are reported separately and, by default,
  counted as "found" for domain/subdomain checks (the host exists).
* Redirect-to-homepage detection for pages (typical soft 404).
* Optional soft-404 detection (--soft404 text|full) for pages that answer "200"
  although the content is missing: (a) <title> and first <h1> are searched for
  "not found" wording in 12 languages (the matched phrase is written to Notes);
  (b) in "full" mode the program also requests a random non-existent address on
  the same site and compares the answer with the page: same final address, same
  content or same title and size reveal a site that serves error pages as 200.
* Per-host politeness delay, thread pool, in-memory de-duplication of
  domain/subdomain/page checks.
* Checkpointing to a JSONL file: an interrupted run (Ctrl-C, crash, network
  outage) resumes where it stopped. Output is written atomically.
* Initial connectivity test, so that a local network outage is not recorded
  as a world-wide loss of web presence.
* A sidecar .meta.json file records when and how the check was run.

Usage
-----
    python link_persistence_checker.py links.csv -o checked_links.csv
    python link_persistence_checker.py CatalogsData.xlsm --sheet INITIATIVES --column Link

Requirements: Python 3.9+, requests; optional: tldextract (recommended),
openpyxl (only to read .xlsx/.xlsm input).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import ipaddress
import json
import logging
import os
import platform
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit, urlunsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter

try:  # public-suffix aware domain splitting (offline snapshot, no downloads)
    import tldextract

    _TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover
    tldextract = None
    _TLD = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("linkcheck")

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 LinkPersistenceChecker/1.0"
)
COLUMNS = [
    "Link", "DomainFound", "HasSubdomain", "SubdomainFound", "IsPage", "PageFound",
    "PresenceScore", "Domain", "Subdomain", "DomainStatus", "SubdomainStatus",
    "PageStatus", "PageFinalUrl", "Notes", "CheckedAtUTC",
]
# lower = more informative when several variants of the same address fail
RANK = {
    "ok": 0, "blocked": 1, "soft404": 2, "not_found": 3, "http_error": 3,
    "server_error": 4, "rate_limited": 4, "ssl": 5, "redirect_loop": 5,
    "timeout": 6, "conn": 7, "dns": 8, "invalid": 9, "error": 9, "aborted": 10,
}
TRANSIENT = {"timeout", "conn", "server_error", "rate_limited"}
DNS_MARKERS = (
    "name or service not known", "nodename nor servname", "getaddrinfo failed",
    "name resolution", "no address associated", "temporary failure in name resolution",
)
SOFT404_RE = re.compile(
    r"((?<![\d/])\b404\b(?!\s*/\s*\d)|not\s+found|nicht\s+gefunden|introuvable|non\s+trovat|n[ãa]o\s+encontrad|"
    r"no\s+encontrad|niet\s+gevonden|nie\s+znaleziono|nenalezen|bulunamad|не\s+найден|"
    r"δεν\s+βρέθηκε)", re.I)
BODY_CAP = 65536          # bytes of a page read for soft-404 inspection
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "nom", "mil"}


# --------------------------------------------------------------------------- #
# URL handling
# --------------------------------------------------------------------------- #
def normalise_link(raw: str) -> Optional[str]:
    """Clean a raw link; return None when it cannot be an http(s) URL."""
    link = (raw or "").strip().strip("'\"<>").strip()
    if not link:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", link):
        link = "https://" + link.lstrip("/")
    try:
        parts = urlsplit(link)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            return None
        host = parts.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        port = parts.port
    except (ValueError, UnicodeError):
        return None
    if not re.fullmatch(r"[a-z0-9._\-\[\]:]+", host):
        return None
    netloc = host + (f":{port}" if port else "")
    path = quote(parts.path, safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&%:@!$'()*+,;/?-._~")
    return urlunsplit((scheme, netloc, path, query, ""))


def split_host(host: str) -> Tuple[str, bool]:
    """Return (registrable_domain, is_ip). Falls back to a heuristic without tldextract."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host, True
    except ValueError:
        pass
    if _TLD is not None:
        ext = _TLD(host)
        if ext.suffix:                              # known public suffix
            dom = (ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix")
                   else ext.registered_domain)
            if dom:
                return dom, False
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:]), False
    return (".".join(labels[-2:]) if len(labels) >= 2 else host), False


def is_page_url(url: str) -> bool:
    p = urlsplit(url)
    return p.path not in ("", "/") or bool(p.query)


def _dedupe(seq: List[str]) -> List[str]:
    seen, out = set(), []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# --------------------------------------------------------------------------- #
# HTTP probing
# --------------------------------------------------------------------------- #
@dataclass
class Probe:
    ok: bool
    kind: str = "ok"
    status: Optional[int] = None
    final_url: str = ""
    note: str = ""

    @property
    def label(self) -> str:
        if self.status and self.kind in ("ok", "http_error", "not_found"):
            return str(self.status)
        return f"{self.status}/{self.kind}" if self.status else self.kind


def classify_exception(exc: Exception) -> Probe:
    msg = str(exc).lower()
    ex = requests.exceptions
    if isinstance(exc, ex.SSLError):
        return Probe(False, "ssl", note=str(exc)[:120])
    if isinstance(exc, ex.Timeout):
        return Probe(False, "timeout")
    if isinstance(exc, ex.TooManyRedirects):
        return Probe(False, "redirect_loop")
    if isinstance(exc, (ex.InvalidURL, ex.InvalidSchema, ex.MissingSchema, ex.InvalidHeader)):
        return Probe(False, "invalid", note=str(exc)[:120])
    if isinstance(exc, ex.ConnectionError):
        return Probe(False, "dns" if any(m in msg for m in DNS_MARKERS) else "conn",
                     note=str(exc)[:120])
    return Probe(False, "error", note=repr(exc)[:120])


class Prober:
    def __init__(self, timeout: float = 15, retries: int = 2, backoff: float = 1.5,
                 delay: float = 0.5, user_agent: str = DEFAULT_UA, strict_ssl: bool = False,
                 pool_size: int = 32):
        self.timeout, self.retries, self.backoff = timeout, retries, backoff
        self.delay, self.user_agent, self.strict_ssl = delay, user_agent, strict_ssl
        self.pool_size = pool_size
        self.stop = threading.Event()
        self._local = threading.local()
        self._guard = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}
        self._last: Dict[str, float] = {}
        self._dns_dead: set = set()
        self._plocks: Dict[str, threading.Lock] = {}
        self._profiles: Dict[str, Optional[dict]] = {}

    # -- plumbing ----------------------------------------------------------- #
    def _session(self) -> requests.Session:
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en;q=0.8,*;q=0.5",
            })
            adapter = HTTPAdapter(max_retries=0, pool_connections=self.pool_size,
                                  pool_maxsize=self.pool_size)
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            self._local.s = s
        return s

    def _throttle(self, host: str) -> None:
        with self._guard:
            lock = self._locks.setdefault(host, threading.Lock())
        with lock:
            wait = self._last.get(host, 0.0) + self.delay - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.monotonic()

    def _send(self, method: str, url: str, verify: bool) -> requests.Response:
        return self._session().request(method, url, allow_redirects=True,
                                       timeout=(min(self.timeout, 10), self.timeout),
                                       verify=verify, stream=True)

    # -- soft-404 inspection ---------------------------------------------- #
    @staticmethod
    def _clean(fragment: str) -> str:
        txt = html.unescape(re.sub(r"<[^>]+>", " ", fragment))
        return re.sub(r"\s+", " ", txt).strip()[:200]

    def _inspect(self, url: str, verify: bool) -> dict:
        """GET a URL (first BODY_CAP bytes only) and extract what soft-404 tests need."""
        r = self._send("GET", url, verify)
        try:
            chunk = b""
            for part in r.iter_content(BODY_CAP):
                chunk = part
                break
            text = chunk.decode(r.encoding or "utf-8", "replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            h = re.search(r"<h1[^>]*>(.*?)</h1>", text, re.I | re.S)
            body = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
            body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip().lower()
            return {"status": r.status_code, "final_url": r.url,
                    "title": self._clean(m.group(1)) if m else "",
                    "h1": self._clean(h.group(1)) if h else "",
                    "hash": hashlib.sha1(body.encode("utf-8", "replace")).hexdigest(),
                    "len": len(chunk), "complete": len(chunk) < BODY_CAP}
        finally:
            r.close()

    def _profile(self, base: str, verify: bool) -> Optional[dict]:
        """Fingerprint of how a site answers a random, certainly non-existent address."""
        with self._guard:
            lock = self._plocks.setdefault(base, threading.Lock())
        with lock:
            if base in self._profiles:
                return self._profiles[base]
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            prof: Optional[dict] = None
            try:
                self._throttle(urlsplit(base).hostname or "")
                info = self._inspect(f"{base}/{token}", verify)
                info["ok"] = 200 <= info["status"] < 400
                prof = info
            except Exception:
                prof = None
            self._profiles[base] = prof
            return prof

    def _soft404_check(self, final: str, requested: str, verify: bool, mode: str) -> Tuple[bool, str]:
        """Return (is_soft_404, note) for a page that answered with a success code."""
        try:
            info = self._inspect(final, verify)
            for label in ("title", "h1"):
                m = SOFT404_RE.search(info[label] or "")
                if m:
                    return True, f"soft404_{label}:{re.sub(r'[^a-z0-9 ]', '', m.group(0).lower())[:30]}"
            if mode != "full":
                return False, ""
            fu = urlsplit(final)
            base = f"{fu.scheme}://{fu.netloc}"
            prof = self._profile(base, verify)
            if prof is None:
                return False, "soft404_profile_unavailable"
            if not prof["ok"]:
                return False, ""                    # site answers unknown addresses with a real error
            norm = lambda u: urlsplit(u).path.rstrip("/")
            if norm(info["final_url"]) == norm(prof["final_url"]) and norm(final) != norm(requested):
                return True, "soft404_fingerprint:same_final_url"
            if info["hash"] == prof["hash"] and info["len"] > 0:
                return True, "soft404_fingerprint:same_content"
            if (info["title"] and info["title"].lower() == (prof["title"] or "").lower()
                    and info["complete"] and prof["complete"]
                    and abs(info["len"] - prof["len"]) <= 0.10 * max(info["len"], prof["len"], 1)):
                return True, "soft404_fingerprint:same_title_and_size"
            return False, "host_answers_200_for_unknown_paths"
        except Exception:
            return False, "soft404_check_failed"

    # -- one attempt: HEAD, then GET on any failure ------------------------- #
    def _attempt(self, url: str, soft404: str) -> Probe:
        self._throttle(urlsplit(url).hostname or "")
        verify, note = True, ""
        for method in ("HEAD", "GET"):
            try:
                try:
                    r = self._send(method, url, verify)
                except requests.exceptions.SSLError as exc:
                    if self.strict_ssl:
                        return classify_exception(exc)
                    verify, note = False, "ssl_invalid_certificate"
                    r = self._send(method, url, False)
                status, final = r.status_code, r.url
                r.close()
                if 200 <= status < 400:
                    if soft404 != "off":
                        flagged, extra = self._soft404_check(final, url, verify, soft404)
                        note = ";".join(x for x in (note, extra) if x)
                        if flagged:
                            return Probe(False, "soft404", status, final, note)
                    return Probe(True, "ok", status, final, note)
                if method == "HEAD":
                    continue                      # confirm with GET
                if status in (401, 403):
                    kind = "blocked"
                elif status == 429:
                    kind = "rate_limited"
                elif status >= 500:
                    kind = "server_error"
                elif status in (404, 410):
                    kind = "not_found"
                else:
                    kind = "http_error"
                return Probe(False, kind, status, final, note)
            except requests.exceptions.RequestException as exc:
                p = classify_exception(exc)
                p.note = p.note or note
                return p
            except Exception as exc:              # never let one URL kill the run
                return Probe(False, "error", note=repr(exc)[:120])
        return Probe(False, "error")

    def probe(self, url: str, soft404: str = "off") -> Probe:
        host = urlsplit(url).hostname or ""
        if host in self._dns_dead:
            return Probe(False, "dns")
        last = Probe(False, "error")
        for attempt in range(self.retries + 1):
            if self.stop.is_set():
                return Probe(False, "aborted")
            last = self._attempt(url, soft404)
            if last.kind not in TRANSIENT and last.kind != "dns":
                return last
            if last.kind == "dns" and attempt >= 1:   # DNS: one confirmation only
                break
            if attempt < self.retries:
                self.stop.wait(min(self.backoff * (2 ** attempt), 15))
        if last.kind == "dns":
            self._dns_dead.add(host)
        return last

    def probe_variants(self, urls: List[str], soft404: str = "off") -> Probe:
        best: Optional[Probe] = None
        dead_hosts = set()
        for u in _dedupe(urls):
            if self.stop.is_set():
                return Probe(False, "aborted")
            host = urlsplit(u).hostname
            if host in dead_hosts:
                continue
            p = self.probe(u, soft404)
            if p.ok:
                return p
            if p.kind == "dns":
                dead_hosts.add(host)
            if best is None or RANK.get(p.kind, 9) < RANK.get(best.kind, 9):
                best = p
        return best or Probe(False, "invalid")


# --------------------------------------------------------------------------- #
# Checks per level
# --------------------------------------------------------------------------- #
@dataclass
class Level:
    found: bool
    label: str
    final_url: str = ""
    notes: Tuple[str, ...] = ()


class OnceCache:
    """Compute each key once, even when several threads ask for it at the same time."""

    def __init__(self):
        self._d: Dict[tuple, dict] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple, fn: Callable[[], Level]) -> Level:
        with self._lock:
            ent = self._d.get(key)
            owner = ent is None
            if owner:
                ent = self._d[key] = {"ev": threading.Event(), "val": None}
        if owner:
            try:
                ent["val"] = fn()
            except Exception as exc:
                ent["val"] = Level(False, "error", notes=(f"internal_error:{exc!r}"[:80],))
            finally:
                ent["ev"].set()
        else:
            ent["ev"].wait()
        return ent["val"]


class Checker:
    def __init__(self, prober: Prober, count_blocked: str = "host", lenient_root: bool = False,
                 soft404: str = "off", short_circuit: bool = False):
        self.prober, self.count_blocked = prober, count_blocked
        self.lenient_root, self.soft404, self.short_circuit = lenient_root, soft404, short_circuit
        self.cache = OnceCache()

    def _level(self, p: Probe, level: str, requested: str = "") -> Level:
        notes = [n for n in p.note.split(";") if n.startswith(("ssl_", "soft404", "host_"))]   # controlled vocabulary
        if p.ok:
            if (level == "page" and not self.lenient_root and requested
                    and is_page_url(requested) and not is_page_url(p.final_url)):
                return Level(False, p.label, p.final_url, tuple(notes + ["redirected_to_root"]))
            return Level(True, p.label, p.final_url, tuple(notes))
        if p.kind == "blocked" and (self.count_blocked == "all" or (
                self.count_blocked == "host" and level in ("domain", "subdomain"))):
            return Level(True, p.label, p.final_url, tuple(notes + ["blocked_counted_as_found"]))
        return Level(False, p.label, p.final_url, tuple(notes))

    def check_domain(self, domain: str, is_ip: bool) -> Level:
        hosts = [domain] if is_ip else [domain, "www." + domain]
        urls = [f"{s}://{h}/" for h in hosts for s in ("https", "http")]
        return self._level(self.prober.probe_variants(urls), "domain")

    def check_subdomain(self, host: str) -> Level:
        urls = [f"https://{host}/", f"http://{host}/"]
        return self._level(self.prober.probe_variants(urls), "subdomain")

    def check_page(self, url: str, toggle_www: bool) -> Level:
        p = urlsplit(url)
        swap = "http" if p.scheme == "https" else "https"
        urls = [url, urlunsplit((swap,) + tuple(p)[1:])]
        if toggle_www and p.hostname:
            h = p.hostname[4:] if p.hostname.startswith("www.") else "www." + p.hostname
            netloc = h + (f":{p.port}" if p.port else "")
            urls += [urlunsplit((p.scheme, netloc) + tuple(p)[2:]),
                     urlunsplit((swap, netloc) + tuple(p)[2:])]
        return self._level(self.prober.probe_variants(urls, soft404=self.soft404), "page", url)


def _tf(v: bool) -> str:
    return "TRUE" if v else "FALSE"


def process_link(raw: str, ck: Checker) -> Optional[dict]:
    row = {c: "" for c in COLUMNS}
    row["Link"] = raw.strip()
    row["CheckedAtUTC"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    norm = normalise_link(raw)
    if norm is None:
        row.update(DomainFound="FALSE", PresenceScore="0", Notes="invalid_url")
        return row

    host = urlsplit(norm).hostname or ""
    domain, is_ip = split_host(host)
    bare = host[4:] if host.startswith("www.") else host
    has_sub = (not is_ip) and bare != domain
    is_page = is_page_url(norm)
    row.update(Domain=domain, Subdomain=bare if has_sub else "",
               HasSubdomain=_tf(has_sub), IsPage=_tf(is_page))

    dom = ck.cache.get(("d", domain), lambda: ck.check_domain(domain, is_ip))
    sub = page = None
    notes: List[str] = list(dom.notes)
    if ck.short_circuit and not dom.found:
        notes.append("short_circuit")
    else:
        if has_sub:
            sub = ck.cache.get(("s", bare), lambda: ck.check_subdomain(bare))
            notes += sub.notes
        if is_page:
            page = ck.cache.get(("p", norm), lambda: ck.check_page(norm, not has_sub and not is_ip))
            notes += page.notes
    if ck.prober.stop.is_set():
        return None

    row["DomainFound"] = _tf(dom.found)
    row["DomainStatus"] = dom.label
    if sub is not None:
        row["SubdomainFound"], row["SubdomainStatus"] = _tf(sub.found), sub.label
    if page is not None:
        row["PageFound"], row["PageStatus"], row["PageFinalUrl"] = _tf(page.found), page.label, page.final_url
    lower = (sub is not None and sub.found) or (page is not None and page.found)
    row["PresenceScore"] = "0" if not dom.found else str(1 + int(lower))
    if lower and not dom.found:
        notes.append("lower_level_found_but_domain_not")
    row["Notes"] = ";".join(dict.fromkeys(n for n in notes if n))
    return row


# --------------------------------------------------------------------------- #
# I/O
# --------------------------------------------------------------------------- #
def read_links(path: str, column: str, sheet: Optional[str]) -> List[str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        from openpyxl import load_workbook          # optional dependency
        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb[sheet] if sheet else wb.worksheets[0]
        rows = ws.iter_rows(values_only=True)
        header = [str(h).strip().lower() if h is not None else "" for h in next(rows)]
        idx = int(column) if column.isdigit() else header.index(column.strip().lower())
        return [str(r[idx]).strip() for r in rows if r and r[idx] not in (None, "")]
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = [r for r in csv.reader(fh) if r]
    if not rows:
        return []
    header = [c.strip().lower() for c in rows[0]]
    if column.isdigit():
        idx, body = int(column), rows
    elif column.strip().lower() in header:
        idx, body = header.index(column.strip().lower()), rows[1:]
    else:                                           # headerless file: first column
        idx, body = 0, rows
    return [r[idx].strip() for r in body if len(r) > idx and r[idx].strip()]


def load_checkpoint(path: str) -> Dict[str, dict]:
    done: Dict[str, dict] = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    done[rec["key"]] = rec["row"]
                except (ValueError, KeyError):
                    continue                        # tolerate a half-written last line
    return done


def write_csv_atomic(path: str, rows: List[dict]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("Usage")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="CSV/TXT (one link per row) or .xlsx/.xlsm workbook")
    ap.add_argument("-o", "--output", help="output CSV (default: <input>_checked.csv)")
    ap.add_argument("--column", default="Link", help="column name or index with the links (default: Link)")
    ap.add_argument("--sheet", help="sheet name when the input is a workbook")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=15, help="read timeout in seconds (default 15)")
    ap.add_argument("--retries", type=int, default=2, help="retries for transient errors (default 2)")
    ap.add_argument("--backoff", type=float, default=1.5)
    ap.add_argument("--delay", type=float, default=0.5, help="min seconds between requests to the same host")
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--count-blocked", choices=["host", "all", "none"], default="host",
                    help="count 401/403 as found: for domain/subdomain only (host, default), "
                         "for every level (all) or never (none)")
    ap.add_argument("--strict-ssl", action="store_true", help="invalid certificates count as not found")
    ap.add_argument("--lenient-root-redirect", action="store_true",
                    help="a page that redirects to the site's home page counts as found")
    ap.add_argument("--soft404", nargs="?", const="full", default="off", choices=["off", "text", "full"],
                    help="detect 'not found' pages that answer 200. text: search <title>/<h1> for 'not found' "
                         "wording; full (default when the flag is given without value): text plus comparison "
                         "with the site's answer to a random non-existent address")
    ap.add_argument("--short-circuit", action="store_true",
                    help="skip subdomain/page tests when the domain is not found (original behaviour)")
    ap.add_argument("--fresh", action="store_true", help="ignore and overwrite the checkpoint file")
    ap.add_argument("--limit", type=int, help="only check the first N links (testing)")
    ap.add_argument("--skip-connectivity-check", action="store_true")
    ap.add_argument("--connectivity-url", default="https://www.wikipedia.org/")
    ap.add_argument("--log-level", default="INFO")
    return ap.parse_args(argv)


def run(args: argparse.Namespace, prober: Optional[Prober] = None) -> int:
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(message)s")
    out = args.output or os.path.splitext(args.input)[0] + "_checked.csv"
    ckpt = out + ".cache.jsonl"
    started = datetime.now(timezone.utc)

    links = read_links(args.input, args.column, args.sheet)
    if args.limit:
        links = links[: args.limit]
    log.info("%d links read from %s (%d unique)", len(links), args.input, len(set(links)))
    if not links:
        log.error("no links found - check --column / --sheet")
        return 2

    prober = prober or Prober(args.timeout, args.retries, args.backoff, args.delay,
                              args.user_agent, args.strict_ssl, max(32, args.workers * 2))
    if not args.skip_connectivity_check:
        p = prober.probe(args.connectivity_url)
        if not p.ok:
            log.error("connectivity test failed (%s: %s). Aborting so that a local network problem "
                      "is not recorded as lost web presence.", args.connectivity_url, p.label)
            return 3
    checker = Checker(prober, args.count_blocked, args.lenient_root_redirect, args.soft404, args.short_circuit)

    if args.fresh and os.path.exists(ckpt):
        os.remove(ckpt)
    done = load_checkpoint(ckpt)
    todo = [l for l in dict.fromkeys(links) if l not in done]
    log.info("%d already in checkpoint, %d to check", len(done), len(todo))

    interrupted = False
    with open(ckpt, "a", encoding="utf-8") as ck_fh, ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(process_link, l, checker): l for l in todo}
        n = 0
        try:
            for fut in as_completed(futs):
                raw = futs[fut]
                try:
                    row = fut.result()
                except Exception as exc:            # defensive: keep going
                    log.exception("internal error on %s", raw)
                    row = {c: "" for c in COLUMNS}
                    row.update(Link=raw, Notes=f"internal_error:{exc!r}"[:100])
                    done[raw] = row                 # shown in the output, retried on resume
                    continue
                if row is None:                     # aborted: do not checkpoint
                    continue
                done[raw] = row
                ck_fh.write(json.dumps({"key": raw, "row": row}, ensure_ascii=False) + "\n")
                ck_fh.flush()
                n += 1
                if n % 25 == 0 or n == len(todo):
                    log.info("progress %d/%d", n, len(todo))
        except KeyboardInterrupt:
            interrupted = True
            log.warning("interrupted - finishing in-flight requests and saving progress")
            prober.stop.set()
            ex.shutdown(wait=True, cancel_futures=True)

    rows = []
    for l in links:
        r = done.get(l)
        if r is None:
            r = {c: "" for c in COLUMNS}
            r.update(Link=l, Notes="not_checked")
        rows.append(r)
    write_csv_atomic(out, rows)

    finished = datetime.now(timezone.utc)
    meta = {
        "started_utc": started.isoformat(), "finished_utc": finished.isoformat(),
        "links": len(links), "unique_links": len(set(links)),
        "not_checked": sum(1 for r in rows if r.get("Notes") == "not_checked"),
        "python": sys.version.split()[0], "platform": platform.platform(),
        "requests": requests.__version__,
        "tldextract": getattr(tldextract, "__version__", None) if tldextract else None,
        "settings": {k: v for k, v in vars(args).items() if k != "user_agent"},
        "user_agent": args.user_agent,
    }
    with open(out + ".meta.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, ensure_ascii=False, default=str)
    log.info("written %s (%d rows)", out, len(rows))
    return 130 if interrupted else 0


def main(argv=None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())