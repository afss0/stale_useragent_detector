#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decide whether a User-Agent is stale, or generate an nginx policy from release timelines.

Single-file, stdlib-only tool with two modes. By default it answers one question
about a User-Agent string: is this client stale? The nginx policy generator is
an optional mode behind the --nginx-* flags.

The generator mode does what the old three-script pipeline did separately:

  1. fetch  -> download the release timelines (browsers + generic HTTP clients)
  2. generate -> turn "older than N months" into an enumerated nginx regex

Why a generator at all: an nginx `map` cannot do arithmetic. "Block anything released more
than N months ago" has to become an explicit enumeration of versions inside a regex, and that
enumeration rots. Here it is recomputed from the timelines, so the floor moves with the
calendar.

Design rules (each one cost a debugging session):
  * The family comes from the UA token. CriOS follows Chrome's numbering with a real lag,
    so Chrome's floor is slightly permissive for it -- a deliberate false negative.
  * No rule exists for what the UA cannot date: `Go-http-client/1.1`, `node`, `okhttp/`,
    `Wget/`, `Java/`, `libwww-perl/` carry no usable version. They are reported, never matched.
  * UA and IP allowlists exist so the policy does not kill your own tooling (ACME validation,
    Googlebot/Bingbot, loopback). A home/residential IP is NOT an allowlist entry: it is a
    client like any other and must go through the policy.
  * `--allow-ip` ADDS to the built-in loopback entries. Pass `--replace-allow-ips` to take
    the list over completely -- dropping loopback silently breaks local self-tests.

Usage:
  ./stale_useragent_detector.py --nginx-dry-run   # fetch if needed, print the policy
  ./stale_useragent_detector.py --nginx-policy /etc/nginx/conf.d/ua-policy.conf \\
                     --nginx-snippet /etc/nginx/snippets/ua-policy.conf
  ./stale_useragent_detector.py --refresh         # ignore the cache, re-download
  ./stale_useragent_detector.py --from-build ./build  # skip fetching, use prebuilt JSONs

Include the snippet INSIDE each server/location to protect -- never in the ACME location
(/.well-known/acme-challenge/) and it does not belong in http{}.
"""
import argparse
import datetime
from dataclasses import dataclass
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

__version__ = "0.1.0"

SOURCES = {
    # browsers
    "eol-chrome.json": "https://endoflife.date/api/chrome.json",
    "eol-firefox.json": "https://endoflife.date/api/firefox.json",
    "eol-ios.json": "https://endoflife.date/api/ios.json",
    "eol-macos.json": "https://endoflife.date/api/macos.json",
    "eol-android.json": "https://endoflife.date/api/android.json",
    "mozilla-firefox-history.json": "https://product-details.mozilla.org/1.0/firefox_history_major_releases.json",
    "mozilla-firefox-versions.json": "https://product-details.mozilla.org/1.0/firefox_versions.json",
    "chromiumdash-stable-win.json": "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=5",
    "chromiumdash-stable-ios.json": "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=iOS&num=5",
    "chromiumdash-stable-android.json": "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Android&num=5",
    "edgeupdates-products.json": "https://edgeupdates.microsoft.com/api/products?view=enterprise",
    # Safari minors: Apple's security-release table + the same release notes already parsed by BOFA
    "apple-security-releases.html": "https://support.apple.com/en-us/100100",
    "bofa-safari-history.json": "https://raw.githubusercontent.com/cocopuff2u/BOFA/main/latest_safari_files/safari_all_history.json",
    # generic HTTP clients with a public timeline
    "curl-releases.json": "https://api.github.com/repos/curl/curl/releases?per_page=100",
    "powershell-releases.json": "https://api.github.com/repos/PowerShell/PowerShell/releases?per_page=100",
    "requests-pypi.json": "https://pypi.org/pypi/requests/json",
    "node-dist-index.json": "https://nodejs.org/dist/index.json",
}

FAMILIES = {
    "Chromium": {"timeline": "Chrome", "tokens": r"Chrome|Edg|EdgA|EdgiOS|OPR|SamsungBrowser"},
    "Chrome-iOS": {"timeline": "Chrome", "tokens": r"CriOS"},
    "Firefox": {"timeline": "Firefox", "tokens": r"Firefox|FxiOS"},
    "Safari": {"timeline": "Safari-minors", "tokens": None, "kind": "safari-minor"},
}

ALLOW_UA_DEFAULT = [r"Let's Encrypt validation server", r"\(compatible; ACME ", r"Googlebot", r"Bingbot"]
DEFAULT_ALLOW_IP = ["127.0.0.1", "::1"]
# Proof-only rules: every entry here is a shape that cannot belong to a real client, so it needs
# no version heuristics. Deliberately NOT here: "Chrome/x.0.0.0 above 113 proves forgery" and
# "below 101 proves forgery" -- WebView/apps send a full version, and legitimate crawlers reuse a
# reduced token; measured against 2289 legitimate UAs those two produce 58-93 false positives.
NEVER_LEGIT_DEFAULT = [
    (r"(^|[\s/;(])(zgrab|l9scan|nuclei|nikto|masscan|sqlmap|wpscan|nmap|morfeus|zmeu|highperfscanner|censysinspect|shodan)",
     "security/scanner tools that name themselves (0 FP / 11 hits in the reference corpus)"),
    (r"CPU iPhone OS (19|2[7-9]|[3-9][0-9])[_.]",
     "iOS versions that never existed: Apple jumped from 18 to 26 (0 FP)"),
    (r"(CriOS|FxiOS|EdgiOS)/[0-9]+\.0\.0\.0",
     "CriOS/FxiOS/EdgiOS are never UA-reduced, so x.0.0.0 is an impossible shape (0 FP)"),
]
NEVER_LEGIT_SAMPLE = [
    ("zgrab/0.x", True),
    ("Mozilla/5.0 (compatible; Nuclei - Open-source project)", True),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X)", True),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 26_3 like Mac OS X) AppleWebKit/605.1.15 CriOS/152.0.0.0 Mobile/15E148", True),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36", False),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 26_3 like Mac OS X) AppleWebKit/605.1.15 CriOS/152.0.7977.64 Mobile/15E148", False),
]
NO_VERSION_IN_UA = {
    "Go-http-client": {"ua_token": "Go-http-client/", "note": "the string 'Go-http-client/1.1' never changes with the Go version; staleness is undetectable by UA"},
    "node": {"ua_token": "node", "note": "the UA is literally 'node', no version"},
    "okhttp": {"ua_token": "okhttp/", "note": "no public releases in the tested repo; no timeline"},
    "wget": {"ua_token": "Wget/", "note": "no releases in the GitHub mirror; needs the ftp.gnu.org listing"},
    "Java": {"ua_token": "Java/", "note": "runtime version, not client version"},
    "libwww-perl": {"ua_token": "libwww-perl/", "note": "CPAN distribution, no JSON timeline"},
}


# --------------------------------------------------------------------------- fetch
def fetch_sources(cache_dir, refresh=False, quiet=False):
    """Download every source into cache_dir. A source that fails is simply absent: the
    builders skip what they cannot parse, and the policy is built from what arrived."""
    os.makedirs(cache_dir, exist_ok=True)
    ok = failed = 0
    for name, url in SOURCES.items():
        path = os.path.join(cache_dir, name)
        if os.path.exists(path) and os.path.getsize(path) > 0 and not refresh:
            ok += 1
            continue
        req = urllib.request.Request(url, headers={
            "User-Agent": f"stale-useragent-detector/{__version__} (+https://github.com/)",
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read()
            if not body:
                raise ValueError("empty body")
            if name.endswith(".json"):
                json.loads(body.decode("utf-8", "replace"))
            with open(path, "wb") as fh:
                fh.write(body)
            ok += 1
        except (urllib.error.URLError, ValueError, json.JSONDecodeError, OSError) as exc:
            if os.path.exists(path):
                os.unlink(path)
            failed += 1
            print(f"  fetch FAILED {name}: {exc}", file=sys.stderr)
    if not quiet:
        print(f"  sources: {ok} ok, {failed} failed", file=sys.stderr)
    return ok, failed


def _load(cache_dir, name):
    path = os.path.join(cache_dir, name)
    if not os.path.exists(path) or os.path.getsize(path) < 10:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh) if name.endswith(".json") else fh.read()
    except (json.JSONDecodeError, OSError):
        return None


# ------------------------------------------------------------------- browser timelines
def _date(dd, mon, yy):
    months = {m: i + 1 for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
    return datetime.date(int(yy), months[mon], int(dd))


def safari_minors(cache_dir):
    """Safari by MINOR with a date. Primary: Apple's security-release table
    (support.apple.com/en-us/100100, rows 'Safari X.Y.Z' + 'DD Mon YYYY'). Secondary: Apple's
    Safari Release Notes as parsed by BOFA, which include non-CVE minors. Per line the NEWEST
    date wins: a user on 26.6.2 is current on patches, and permissive is the safe error."""
    out = {}
    html = _load(cache_dir, "apple-security-releases.html")
    if html:
        for row in re.findall(r"<tr.*?</tr>", html, re.S):
            nm = re.search(r"<tr[^>]*>\s*<td[^>]*>\s*<p[^>]*>(?:<a[^>]*>)?\s*Safari (\d+(?:\.\d+){1,2})", row)
            if not nm:
                continue
            dates = [_date(*m) for m in re.findall(r"(\d{2}) ([A-Z][a-z]{2}) (\d{4})", re.sub(r"<[^>]+>", " ", row))]
            if not dates:
                continue
            v = ".".join(nm.group(1).split(".")[:2])
            out[v] = max(out.get(v) or datetime.date.min, max(dates))
    bofa = _load(cache_dir, "bofa-safari-history.json")
    if bofa:
        for e in bofa or []:
            m = re.match(r"(\d+)(?:\.(\d+))?", str(e.get("version", "")))
            if not m or not e.get("released"):
                continue
            try:
                dt = datetime.datetime.strptime(e["released"].replace(",", ""), "%B %d %Y").date()
            except ValueError:
                continue
            out[f"{m.group(1)}.{m.group(2) or 0}"] = max(out.get(f"{m.group(1)}.{m.group(2) or 0}") or datetime.date.min, dt)
    return {v: d.isoformat() for v, d in out.items() if d != datetime.date.min}


def majors_from_eol(cache_dir, name):
    data = _load(cache_dir, name) or []
    out = []
    for c in data:
        cyc, date = c.get("cycle"), c.get("releaseDate")
        if not cyc or not date:
            continue
        try:
            major = int(str(cyc).split(".")[0])
        except ValueError:
            continue
        out.append({"version": major, "date": date})
    return sorted({(e["version"], e["date"]) for e in out})


def build_browser_releases(cache_dir):
    out = {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "timelines": {}, "current": {}, "notes": {}}
    out["timelines"]["Chrome"] = [{"version": v, "date": d} for v, d in majors_from_eol(cache_dir, "eol-chrome.json")]
    cd = _load(cache_dir, "chromiumdash-stable-win.json") or []
    if cd:
        out["current"]["chrome_stable"] = cd[0].get("version")

    cio = _load(cache_dir, "chromiumdash-stable-ios.json") or []
    out["timelines"]["Chrome-iOS"] = [
        {"version": int(e["version"].split(".")[0]),
         "date": datetime.datetime.fromtimestamp(e["time"] / 1000, datetime.timezone.utc).date().isoformat()}
        for e in cio if e.get("version") and e.get("time")
    ]
    if cio:
        out["current"]["chrome_ios"] = cio[0].get("version")

    hist = _load(cache_dir, "mozilla-firefox-history.json") or {}
    ff = []
    for v, d in hist.items():
        try:
            ff.append((int(float(v)), d))
        except (ValueError, TypeError):
            continue
    out["timelines"]["Firefox"] = [{"version": v, "date": d} for v, d in sorted(set(ff))]
    fv = _load(cache_dir, "mozilla-firefox-versions.json") or {}
    out["current"]["firefox"] = fv.get("LATEST_FIREFOX_VERSION")
    out["current"]["firefox_esr"] = fv.get("FIREFOX_ESR")
    # Mozilla publishes more than one live ESR line (FIREFOX_ESR, FIREFOX_ESR115, FIREFOX_ESR_NEXT).
    # An ESR UA is byte-identical to the release of the same major (bug 1225414, wontfix for
    # webcompat), so what is supported cannot come from the UA -- it comes from this feed.
    out["current"]["firefox_esr_lines"] = {
        str(int(v.split(".")[0])): v
        for k, v in fv.items()
        if k.startswith("FIREFOX_ESR") and isinstance(v, str) and v[:1].isdigit()
    }

    out["timelines"]["Safari-iOS"] = [{"version": v, "date": d} for v, d in majors_from_eol(cache_dir, "eol-ios.json")]
    out["timelines"]["Safari-macOS"] = [{"version": v, "date": d} for v, d in majors_from_eol(cache_dir, "eol-macos.json")]
    merged = {}
    for v, d in majors_from_eol(cache_dir, "eol-ios.json") + majors_from_eol(cache_dir, "eol-macos.json"):
        merged[v] = min(d, merged.get(v, d))
    out["timelines"]["Safari"] = [{"version": v, "date": d} for v, d in sorted(merged.items())]

    sm = safari_minors(cache_dir)
    if sm:
        items = sorted(sm.items(), key=lambda kv: [int(x) for x in kv[0].split(".")])
        covered = {v.split(".")[0] for v in sm}
        # A major that has minor data must not appear as a bare major: it would block the whole
        # line, including the fresh minor.
        items += [(str(v), d) for v, d in sorted(merged.items()) if str(v) not in covered and isinstance(v, int)]
        items.sort(key=lambda kv: [int(x) for x in str(kv[0]).split(".")])
        out["timelines"]["Safari-minors"] = [{"version": str(v), "date": d} for v, d in items]

    out["timelines"]["Android"] = [{"version": v, "date": d} for v, d in majors_from_eol(cache_dir, "eol-android.json")]
    return out


# -------------------------------------------------------------------- client timelines
def _gh_tag(tag, prefix=""):
    t = (tag or "").strip()
    if prefix and t.startswith(prefix):
        t = t[len(prefix):]
    return t.lstrip("v").replace("_", ".")


def _vkey(v):
    return [int(p) for p in re.findall(r"\d+", v)]


def build_client_releases(cache_dir):
    out = {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "clients": {}, "no_version_in_ua": dict(NO_VERSION_IN_UA)}

    curl = _load(cache_dir, "curl-releases.json")
    if curl:
        rel = []
        for r in curl:
            if r.get("draft") or r.get("prerelease"):
                continue
            v = _gh_tag(r.get("tag_name"), "curl-")
            if re.fullmatch(r"\d+\.\d+(\.\d+)?", v):
                rel.append({"version": v, "date": (r.get("published_at") or "")[:10]})
        out["clients"]["curl"] = {"ua_token": "curl/", "releases": sorted(rel, key=lambda x: _vkey(x["version"]))}

    req = _load(cache_dir, "requests-pypi.json")
    if req:
        rel = []
        for v, files in (req.get("releases") or {}).items():
            if not re.fullmatch(r"\d+\.\d+(\.\d+)?", v):
                continue
            dates = [f.get("upload_time") or f.get("upload_time_iso_8601") for f in files if f.get("upload_time")]
            if dates:
                rel.append({"version": v, "date": min(dates)[:10]})
        out["clients"]["python-requests"] = {"ua_token": "python-requests/", "releases": sorted(rel, key=lambda x: _vkey(x["version"]))}

    ps = _load(cache_dir, "powershell-releases.json")
    if ps:
        rel = []
        for r in ps:
            if r.get("draft") or r.get("prerelease"):
                continue
            v = _gh_tag(r.get("tag_name"), "v")
            if re.fullmatch(r"\d+\.\d+(\.\d+)?", v):
                rel.append({"version": v, "date": (r.get("published_at") or "")[:10]})
        out["clients"]["PowerShell"] = {"ua_token": "PowerShell/", "releases": sorted(rel, key=lambda x: _vkey(x["version"]))}

    node = _load(cache_dir, "node-dist-index.json")
    if node:
        out["no_version_in_ua"]["node"] = {
            "ua_token": "node", "note": "the UA is literally 'node', no version",
            "releases_count": len(node),
        }
    return out


# ------------------------------------------------------------------------- the policy
def compress_numbers(nums):
    """[1,2,3,...] -> compact alternation. Missing numbers become false negatives (by design)."""
    nums = sorted(set(nums))
    terms, i = [], 0
    while i < len(nums):
        j = i
        while (j + 1 < len(nums)
               and str(nums[j + 1])[:-1] == str(nums[i])[:-1]
               and int(str(nums[j + 1])[-1]) == int(str(nums[j])[-1]) + 1):
            j += 1
        run = nums[i:j + 1]
        prefix = str(run[0])[:-1]
        if len(run) == 10:
            terms.append((prefix or "") + "[0-9]")
        elif len(run) > 2 and prefix:
            terms.append(prefix + "[" + str(run[0])[-1] + "-" + str(run[-1])[-1] + "]")
        else:
            terms.extend(str(n) for n in run)
        i = j + 1
    return "|".join(terms)


def version_terms(allv, blocked, partial_suffix="\\."):
    """Compact alternation of blocked versions, grouped by major / major.minor.
    partial_suffix is what must follow a blocked minor: HTTP clients always carry three
    components ("curl/8.19.0") -> "\\."; Safari carries two or three ("Version/26.3" and
    "Version/26.6.2") -> accept dot, space or end, else two-component UAs escape."""
    bset = set(blocked)
    terms, bymaj = [], {}
    for v in allv:
        bymaj.setdefault(_vkey(v)[0], []).append(v)
    for maj, vs in sorted(bymaj.items()):
        blk = [v for v in vs if v in bset]
        if not blk:
            continue
        if len(blk) == len(vs):
            terms.append(rf"{maj}\.")
            continue
        bymin = {}
        for v in vs:
            bymin.setdefault(tuple(_vkey(v)[:2]), []).append(v)
        for mn, vv in sorted(bymin.items()):
            blk2 = [v for v in vv if v in bset]
            if not blk2:
                continue
            if len(blk2) == len(vv):
                terms.append(rf"{mn[0]}\." if len(mn) == 1 else rf"{mn[0]}\.{mn[1]}{partial_suffix}")
            else:
                terms.extend(re.escape(v) for v in blk2)
    return "|".join(sorted(set(terms)))


def build_policy(now, bmonths, cmonths, brel, crel):
    pats, floors = {}, {}
    bcut = now - datetime.timedelta(days=int(bmonths * 30.44))
    ccut = now - datetime.timedelta(days=int(cmonths * 30.44))

    for fam, cfg in FAMILIES.items():
        tl = brel["timelines"].get(cfg["timeline"]) or []
        released = {}
        for e in tl:
            released[e["version"]] = max(released.get(e["version"], ""), e["date"])
        blocked = sorted(v for v, d in released.items() if d and datetime.date.fromisoformat(d) < bcut)
        if not blocked:
            continue
        if cfg.get("kind") == "safari-minor":
            allv = [str(e["version"]) for e in tl]
            blocked = sorted(blocked, key=_vkey)
            alt = version_terms(allv, blocked, partial_suffix=r"(\.|\s|$)")
            if not alt:
                continue
            rx = rf"Version/({alt})"          # the terms already carry their dots
        else:
            alt = compress_numbers(blocked)
            rx = rf"({cfg['tokens']})/({alt})\."
        floors[fam] = {"timeline": cfg["timeline"], "blocked": blocked,
                       "gran": "minor" if cfg.get("kind") else "major"}
        if cfg.get("kind"):
            floors[fam]["all"] = allv
        pats[fam] = rx

    for fam, d in (crel.get("clients") or {}).items():
        tok, rel = d.get("ua_token"), d.get("releases") or []
        if not tok or not rel:
            continue
        blocked = [v for v in rel if datetime.date.fromisoformat(v["date"]) < ccut]
        if not blocked:
            continue
        allv = [v["version"] for v in rel]
        bset = {b["version"] for b in blocked}
        terms, bymaj = [], {}
        for v in allv:
            bymaj.setdefault(_vkey(v)[0], []).append(v)
        for maj, vs in sorted(bymaj.items()):
            blk = [v for v in vs if v in bset]
            if not blk:
                continue
            if len(blk) == len(vs):
                terms.append(rf"{maj}\.")
                continue
            bymin = {}
            for v in vs:
                bymin.setdefault(tuple(_vkey(v)[:2]), []).append(v)
            for mn, vv in sorted(bymin.items()):
                blk2 = [v for v in vv if v in bset]
                if not blk2:
                    continue
                if len(blk2) == len(vv):
                    terms.append(rf"{mn[0]}\.{mn[1]}\.")
                else:
                    terms.extend(re.escape(v) for v in blk2)
        if terms:
            pats[fam] = rf"{re.escape(tok)}({'|'.join(sorted(set(terms)))})"
            floors[fam] = {"timeline": "client", "blocked": sorted(bset, key=_vkey), "gran": "client"}
    return pats, floors


def self_test(pats, floors):
    """Prove every rule against synthetic UAs of the same family: every blocked version must
    match, and a sample of the unblocked ones must not. Exit code 2 on any mismatch."""
    errs = 0
    for fam in sorted(pats):
        rx, fl = pats[fam], floors[fam]
        try:
            p = re.compile(rx, re.I)
        except re.error as exc:
            print(f"  {fam}: INVALID REGEX: {exc}")
            return 1

        def ua(major, fam=fam):
            if fam == "Safari":
                return ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                        f"(KHTML, like Gecko) Version/{major} Safari/605.1.15")
            if fam == "Chrome-iOS":
                return ("Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 "
                        f"(KHTML, like Gecko) CriOS/{major}.0.0.0 Mobile/15E148 Safari/604.1")
            if fam == "Firefox":
                return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"
            return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")

        if fl.get("gran") == "minor":
            bset = set(fl["blocked"])
            # a real Safari UA is at least major.minor ("Version/5.1.7"), never "Version/5"
            shapes = lambda v: [str(v), str(v) + ".5"] if "." in str(v) else [str(v) + ".0", str(v) + ".1.2"]
            for v in fl["blocked"]:
                for fu in shapes(v):
                    if not p.search(ua(fu)):
                        errs += 1
                        print(f"  ERROR {fam}: Version/{fu} should be blocked and was not")
            for v in [x for x in fl.get("all", []) if x not in bset]:
                for fu in shapes(v):
                    if p.search(ua(fu)):
                        errs += 1
                        print(f"  ERROR {fam}: Version/{fu} should not be blocked and was")
        else:
            if fl.get("gran") == "client":
                blocked = [v for v in fl["blocked"]]
                # the token in the regex is escaped for nginx; probe with the real UA token
                tok = re.sub(r"\\(.)", r"\1", re.match(r"^[^(]+", rx).group(0))
                for v in blocked[:5] + blocked[-5:]:
                    probe = f"{tok}{v}"
                    if not p.search(probe):
                        errs += 1
                        print(f"  ERROR {fam}: {probe} should be blocked and was not")
                continue
            blk = set(fl["blocked"])
            for m in blk:
                if not p.search(ua(m)):
                    errs += 1
                    print(f"  ERROR {fam}: major {m} should be blocked and was not")
            allowed = [m for m in range(1, 300) if m not in blk][:120]
            for m in allowed:
                if p.search(ua(m)):
                    errs += 1
                    print(f"  ERROR {fam}: major {m} should not be blocked and was")
    return errs


def render(now, bmonths, cmonths, pats, esr_rx, esr_src, allow_ua, allow_ips, never_legit=True):
    conf = [
        "# GENERATED by stale_useragent_detector.py -- do not edit by hand (the generator rewrites this).",
        f"# policy of {now}: browser > {bmonths:.0f} months, client > {cmonths:.0f} months",
        "# sources: vendor release timelines (see the SOURCES table in the script)",
        "",
        "map $http_user_agent $ua_stale {",
        "    default 0;",
    ]
    for fam in sorted(pats):
        conf.append(f"    # {fam}")
        conf.append(f'    "~*{pats[fam]}" 1;')
    conf += ["}", ""]
    if never_legit:
        conf += ["# Proof-only block: shapes that cannot be a real client. No version heuristics here.",
                 "map $http_user_agent $ua_never_legit {", "    default 0;"]
        for rx, why in NEVER_LEGIT_DEFAULT:
            conf.append(f"    # {why}")
            conf.append(f'    "~*{rx}" 1;')
        conf += ["}", ""]
    conf += ["map $http_user_agent $ua_allowlisted {", "    default 0;"]
    for rx in list(dict.fromkeys(ALLOW_UA_DEFAULT + allow_ua)):
        conf.append(f'    "~*{rx}" 1;')
    if esr_rx:
        conf.append(f"    # ESR lines Mozilla declares live: {esr_src}")
        conf.append("    # An ESR UA is byte-identical to the release of the same major (bug 1225414,")
        conf.append("    # wontfix for webcompat), so the only possible signal is Mozilla's own list.")
        for rx in esr_rx:
            conf.append(f'    "~*{rx}" 1;')
    conf += ["}", "", "map $remote_addr $ua_ip_ok {", "    default 0;"]
    for ip in allow_ips:
        conf.append(f"    {ip} 1;")
    conf += ["}", "",
             "# block only when the UA is stale AND neither the UA nor the IP is allowlisted",
             'map "$ua_stale$ua_allowlisted$ua_ip_ok" $ua_block {',
             '    "100" 1;',
             "    default 0;",
             "}", ""]
    lines_out = ["# Include INSIDE each server/location that must be protected:",
                 "#     include /etc/nginx/snippets/ua-policy.conf;",
                 "# NEVER in the ACME location (/.well-known/acme-challenge/) and it does not belong in http{}."]
    if never_legit:
        lines_out += ["# proof-only: cannot be a real client, blocked regardless of IP allowlist",
                      "if ($ua_never_legit) { return 444; }"]
    lines_out.append("if ($ua_block) { return 444; }")
    snippet = "\n".join(lines_out) + "\n"
    return "\n".join(conf) + "\n", snippet


def nginx_main(a):
    bmonths = a.browser_months if a.browser_months is not None else a.max_age_months
    cmonths = a.client_months if a.client_months is not None else a.max_age_months
    timelines = load_timelines(
        a.cache, refresh=a.refresh, offline=a.offline, from_build=a.from_build,
        max_age_days=a.max_data_age_days, quiet=False)
    brel, crel = timelines.browser, timelines.client
    if a.dump_build:
        dump_build(timelines, a.dump_build)
    if not any((brel.get("timelines") or {}).values()):
        print("error: no browser timelines available", file=sys.stderr)
        return 3

    now = datetime.date.fromisoformat(a.as_of) if a.as_of else datetime.date.today()
    esr_lines = (brel.get("current") or {}).get("firefox_esr_lines") or {}
    if a.esr_lines == "off" or not esr_lines:
        esr_rx, esr_src = [], "disabled"
    else:
        if a.esr_lines == "primary":
            prim = (brel.get("current") or {}).get("firefox_esr") or ""
            keep = {str(prim.split(".")[0])} if prim[:1].isdigit() else set()
            esr_lines = {k: v for k, v in esr_lines.items() if k in keep}
        esr_rx = [rf"Firefox/{m}\." for m in sorted(esr_lines, key=int)]
        esr_src = ", ".join(f"{k} ({v})" for k, v in sorted(esr_lines.items(), key=lambda kv: int(kv[0])))

    pats, floors = build_policy(now, bmonths, cmonths, brel, crel)
    for fam in a.exclude_family:
        if fam in pats:
            del pats[fam]
            floors.pop(fam, None)
            print(f"  (excluded by --exclude-family: {fam})")

    errs = self_test(pats, floors)
    # the proof-only block is static, but a typo in it would silently disable the rule
    nvr = [(rx, re.compile(rx, re.I)) for rx, _why in NEVER_LEGIT_DEFAULT]
    for sample, expected in NEVER_LEGIT_SAMPLE:
        hit = any(p.search(sample) for _rx, p in nvr)
        if hit != expected:
            errs += 1
            print(f"  ERROR never_legit: {sample!r} expected match={expected}, got {hit}")
    if errs:
        for fam in sorted(pats):
            print(f"  {fam:<12} {len(floors[fam].get('blocked') or []):>4} versions blocked   {pats[fam][:96]}")
        print("  self-test errors:", errs)
        return 2

    allow_ips = list(dict.fromkeys(list(a.allow_ip or []) if a.replace_allow_ips
                                   else DEFAULT_ALLOW_IP + list(a.allow_ip or [])))
    text, snippet = render(now, bmonths, cmonths, pats, esr_rx, esr_src, a.allow_ua, allow_ips,
                           never_legit=a.never_legit)

    # --stdout: the policy alone, nothing else, so it can be piped or diffed
    if a.stdout:
        sys.stdout.write(text)
        return 0

    print(f"policy {now}: browser > {bmonths:.0f} months | client > {cmonths:.0f} months")
    for fam in sorted(pats):
        print(f"  {fam:<12} {len(floors[fam].get('blocked') or []):>4} versions blocked   {pats[fam][:96]}")
    print(f"  ESR allowed (not datable by UA): {esr_src}")
    print("  no datable version in UA:", ", ".join((crel.get("no_version_in_ua") or {}).keys()))
    print("  self-test errors:", errs)
    print("\n--- policy ---\n" + text)   # full text, never truncated

    # Each output is independent: --snippet or --manifest without --out still writes.
    def write_file(path, body):
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)      # /etc/nginx/... may not exist
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"wrote {path} ({len(body)} bytes)")

    if a.dry_run or not (a.out or a.snippet or a.manifest):
        return 0
    try:
        if a.out:
            write_file(a.out, text)
        if a.snippet:
            write_file(a.snippet, snippet)
        if a.manifest:
            manifest = {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "as_of": now.isoformat(),
                "browser_months": bmonths, "client_months": cmonths,
                "esr_lines": esr_lines, "esr_allow_regex": esr_rx, "allow_ips": allow_ips,
                "never_legit_rules": [rx for rx, _why in NEVER_LEGIT_DEFAULT] if a.never_legit else [],
                "families": {k: {"timeline": v["timeline"], "blocked_count": len(v.get("blocked") or [])}
                             for k, v in floors.items()},
            }
            write_file(a.manifest, json.dumps(manifest, indent=1, ensure_ascii=False))
    except OSError as exc:
        print(f"write FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


# ============================================================= stale detector
# Public API: Timelines, Verdict, DataUnavailable, load_timelines, is_stale,
# is_forged. The nginx generator below is an optional mode of this same file.

CLIENTS = ("curl", "python-requests", "PowerShell")


@dataclass(frozen=True)
class Timelines:
    browser: dict
    client: dict
    generated_at: str | None = None


class DataUnavailable(RuntimeError):
    def __init__(self, family: str):
        self.family = family
        super().__init__(f"no release timeline for {family}")


@dataclass(frozen=True)
class Verdict:
    stale: bool
    reason: str
    family: str | None = None
    version: str | None = None
    released: datetime.date | None = None
    age_days: int | None = None
    forged: bool = False


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def dump_build(timelines, path):
    """Write the fetched release tables; useful as a pinned fixture."""
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "browser-releases.json"), "w", encoding="utf-8") as fh:
        json.dump(timelines.browser, fh, indent=1, ensure_ascii=False)
    with open(os.path.join(path, "client-releases.json"), "w", encoding="utf-8") as fh:
        json.dump(timelines.client, fh, indent=1, ensure_ascii=False)


def load_timelines(cache_dir, *, refresh=False, offline=False, from_build=None,
                   max_age_days=7.0, quiet=False):
    """Load the browser and client release tables.

    from_build bypasses the network entirely. Otherwise the source cache is
    reused until it is older than max_age_days; a failed refresh keeps the
    existing cache and only warns.
    """
    if from_build:
        browser = _read_json(os.path.join(from_build, "browser-releases.json"))
        client = _read_json(os.path.join(from_build, "client-releases.json"))
        if browser is None or client is None:
            raise DataUnavailable("build")
        return Timelines(browser, client, browser.get("generated_at"))

    marker = os.path.join(cache_dir, ".last_fetch")
    need = refresh or not os.path.exists(marker)
    if not need and max_age_days >= 0:
        need = (time.time() - os.path.getmtime(marker)) > max_age_days * 86400
    if need and not offline:
        ok, _failed = fetch_sources(cache_dir, refresh=refresh, quiet=quiet)
        if ok:
            try:
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write(datetime.datetime.now(datetime.timezone.utc).isoformat())
            except OSError:
                pass
        elif not quiet:
            print("warning: fetch failed; using the existing cache", file=sys.stderr)

    browser = build_browser_releases(cache_dir)
    client = build_client_releases(cache_dir)
    return Timelines(browser, client, browser.get("generated_at"))


def _vkc(value, width=5):
    """Comparison key: numeric components, zero-padded so 8.19 == 8.19.0."""
    parts = [int(p) for p in re.findall(r"\d+", str(value))][:width]
    return tuple(parts + [0] * (width - len(parts)))


def _series(timelines, family):
    """Return [(version, date)] for the family, or [] when the data is absent."""
    if family == "Safari":
        names = ("Safari-minors", "Safari")
    elif family in CLIENTS:
        d = ((timelines.client.get("clients") or {}).get(family) or {})
        return [(str(r["version"]), str(r["date"]))
                for r in (d.get("releases") or []) if r.get("version") and r.get("date")]
    else:
        names = (FAMILIES[family]["timeline"],)
    for name in names:
        entries = ((timelines.browser.get("timelines") or {}).get(name) or [])
        out = [(str(e["version"]), str(e["date"]))
               for e in entries if e.get("version") and e.get("date")]
        if out:
            return out
    return []


def _lookup(entries, family, version):
    """Pick the release row that dates this UA.

    Exact match at the family's granularity first; then the nearest lower
    release (the UA is between releases); then the oldest release if the UA is
    older than everything known. A version above every known release is None:
    the data is older than the client, so the client is not stale.
    """
    if not entries:
        raise DataUnavailable(family)
    vk = _vkc(version)
    rows = [(e, _vkc(e[0])) for e in entries]
    if family == "Safari":
        if "." not in str(version):
            same_major = [e for e, k in rows if k[0] == vk[0]]
            if same_major:
                return max(same_major, key=lambda e: _vkc(e[0]))
        exact = [e for e, k in rows if k[:2] == vk[:2]]
        if exact:
            return max(exact, key=lambda e: e[1])
        same_major = [(e, k) for e, k in rows if k[0] == vk[0]]
        lower = [(e, k) for e, k in same_major if k[1] < vk[1]]
        higher = [(e, k) for e, k in same_major if k[1] > vk[1]]
        if lower and not higher:
            return None  # above the newest known minor
        if lower:
            return max((e for e, _k in lower), key=lambda e: _vkc(e[0]))
        if higher:
            return min((e for e, _k in higher), key=lambda e: _vkc(e[0]))
        if all(k[0] < vk[0] for _e, k in rows):
            return None  # above the newest known major
        lower_major = [e for e, k in rows if k[0] < vk[0]]
        if lower_major:
            return max(lower_major, key=lambda e: _vkc(e[0]))
        return min(entries, key=lambda e: _vkc(e[0]))

    if family in CLIENTS:
        if vk > max(k for _e, k in rows):
            return None  # above the newest known release
        exact = [e for e, k in rows if k == vk]
        if exact:
            return max(exact, key=lambda e: e[1])
        lower = [e for e, k in rows if k < vk]
        if lower:
            return max(lower, key=lambda e: _vkc(e[0]))
        if all(k > vk for _e, k in rows):
            return min(entries, key=lambda e: _vkc(e[0]))
        return None

    if vk[0] > max(k[0] for _e, k in rows):
        return None  # above the newest known major
    exact = [e for e, k in rows if k[0] == vk[0]]
    if exact:
        return max(exact, key=lambda e: e[1])
    lower = [e for e, k in rows if k[0] < vk[0]]
    if lower:
        return max(lower, key=lambda e: _vkc(e[0]))
    if all(k[0] > vk[0] for _e, k in rows):
        return min(entries, key=lambda e: _vkc(e[0]))
    return None


def _esr(timelines, version, mode):
    if mode == "off":
        return False
    cur = timelines.browser.get("current") or {}
    lines = cur.get("firefox_esr_lines") or {}
    major = str(_vkc(version)[0])
    if major not in lines:
        return False
    if mode == "primary":
        primary = cur.get("firefox_esr") or ""
        return str(_vkc(primary)[0]) == major
    return True


_ALLOW_COMPILED = [re.compile(rx, re.I) for rx in ALLOW_UA_DEFAULT]
_NEVER_LEGIT_COMPILED = [(rx, re.compile(rx, re.I)) for rx, _why in NEVER_LEGIT_DEFAULT]


def _allowed(ua, extra):
    if any(p.search(ua) for p in _ALLOW_COMPILED):
        return True
    return any(re.compile(rx, re.I).search(ua) for rx in extra)


def _undatable(ua):
    low = ua.strip().lower()
    for d in NO_VERSION_IN_UA.values():
        token = d["ua_token"]
        if token == "node":
            if low == "node":
                return True
        elif token.lower() in low:
            return True
    return False


def parse_ua(user_agent):
    """Return (family, version) or (None, None).

    Order matters: Edg/OPR/SamsungBrowser/CriOS all carry a Chrome-like token,
    so they are checked before Chrome. Safari is last and only when no other
    browser token is present.
    """
    ua = user_agent or ""
    for token, family in (
        ("EdgiOS/", "Chromium"),
        ("EdgA/", "Chromium"),
        ("Edg/", "Chromium"),
        ("OPR/", "Chromium"),
        ("SamsungBrowser/", "Chromium"),
        ("CriOS/", "Chrome-iOS"),
        ("FxiOS/", "Firefox"),
        ("Firefox/", "Firefox"),
        ("curl/", "curl"),
        ("python-requests/", "python-requests"),
        ("PowerShell/", "PowerShell"),
        ("Chrome/", "Chromium"),
        ("Chromium/", "Chromium"),
    ):
        m = re.search(re.escape(token) + r"([\d.]+)", ua, re.I)
        if m:
            return family, m.group(1)
    if re.search(r"Safari/", ua, re.I) and not re.search(
            r"(Chrome|Chromium|CriOS|FxiOS|Firefox|Edg|OPR|SamsungBrowser)/", ua, re.I):
        m = re.search(r"Version/([\d.]+)", ua, re.I)
        if m:
            return "Safari", m.group(1)
    return None, None


def is_forged(user_agent):
    """Proof-only predicate: a shape that cannot belong to a real client."""
    ua = user_agent or ""
    return any(p.search(ua) for _rx, p in _NEVER_LEGIT_COMPILED)


def is_stale(user_agent, timelines, *, as_of=None, max_age_months=6.0,
             browser_months=None, client_months=None, allow_ua=(), esr_lines="all"):
    """Decide whether the UA names a client released before the window.

    Pure: no network and no writes. Raises DataUnavailable when the family is
    datable but its timeline is missing.
    """
    ua = user_agent or ""
    forged = is_forged(ua)
    if not ua.strip():
        return Verdict(False, "empty", forged=forged)
    if _allowed(ua, allow_ua):
        return Verdict(False, "allowlisted", forged=forged)
    if _undatable(ua):
        return Verdict(False, "no-version-in-ua", forged=forged)
    family, version = parse_ua(ua)
    if not family:
        return Verdict(False, "unrecognized", forged=forged)

    if as_of is None:
        as_of = datetime.date.today()
    months = (client_months if client_months is not None else max_age_months) \
        if family in CLIENTS else \
        (browser_months if browser_months is not None else max_age_months)

    entries = _series(timelines, family)
    if not entries:
        raise DataUnavailable(family)

    if family == "Firefox" and _esr(timelines, version, esr_lines):
        row = _lookup(entries, family, version)
        released = datetime.date.fromisoformat(row[1]) if row else None
        age = (as_of - released).days if released else None
        return Verdict(False, "esr", family, version, released, age, forged)

    row = _lookup(entries, family, version)
    if row is None:
        return Verdict(False, "version-not-in-timeline", family, version, None, None, forged)
    try:
        released = datetime.date.fromisoformat(row[1])
    except ValueError:
        raise DataUnavailable(family)
    age = (as_of - released).days
    cut = as_of - datetime.timedelta(days=int(months * 30.44))
    stale = released < cut
    return Verdict(stale, "older-than-window" if stale else "current",
                   family, version, released, age, forged)


def detector_main(a):
    ua = a.ua
    if ua is None:
        if sys.stdin.isatty():
            print("error: provide a User-Agent string or pipe one on stdin", file=sys.stderr)
            return 4
        ua = sys.stdin.readline()
    elif ua == "-":
        ua = sys.stdin.readline()
    ua = ua.rstrip("\r\n")

    as_of = datetime.date.fromisoformat(a.as_of) if a.as_of else datetime.date.today()
    try:
        timelines = load_timelines(
            a.cache, refresh=a.refresh, offline=a.offline, from_build=a.from_build,
            max_age_days=a.max_data_age_days, quiet=a.json)
        if a.dump_build:
            dump_build(timelines, a.dump_build)
        verdict = is_stale(
            ua, timelines, as_of=as_of, max_age_months=a.max_age_months,
            browser_months=a.browser_months, client_months=a.client_months,
            allow_ua=a.allow_ua, esr_lines=a.esr_lines)
    except DataUnavailable as exc:
        if not a.allow_undated:
            print(f"error: no release timeline for {exc.family}", file=sys.stderr)
            return 3
        verdict = Verdict(False, "data-unavailable", family=exc.family, forged=is_forged(ua))
    except re.error as exc:
        print(f"error: invalid allowlist regex: {exc}", file=sys.stderr)
        return 2

    selected = verdict.forged if a.forged else verdict.stale
    if a.json:
        sys.stdout.write(json.dumps({
            "user_agent": ua,
            "checked": "forged" if a.forged else "stale",
            "stale": verdict.stale,
            "forged": verdict.forged,
            "reason": verdict.reason,
            "family": verdict.family,
            "version": verdict.version,
            "released": verdict.released.isoformat() if verdict.released else None,
            "age_days": verdict.age_days,
            "as_of": as_of.isoformat(),
            "max_age_months": a.max_age_months,
        }, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(("true" if selected else "false") + "\n")

    if a.explain:
        if verdict.released:
            print(f"{verdict.family} {verdict.version} released "
                  f"{verdict.released.isoformat()} ({verdict.age_days} days; "
                  f"window {a.max_age_months:g} months) => "
                  f"{'stale' if verdict.stale else 'current'}", file=sys.stderr)
        else:
            print(f"{verdict.family or 'UA'} => {verdict.reason}", file=sys.stderr)

    return 1 if (a.exit_code and selected) else 0


def build_parser():
    ap = argparse.ArgumentParser(
        description="Decide whether a User-Agent is stale, or generate an optional nginx policy.")
    ap.add_argument("ua", nargs="?", help="User-Agent string; '-' or omitted reads stdin")
    ap.add_argument("--as-of", help="date the window is measured from (YYYY-MM-DD), default today")
    ap.add_argument("--max-age-months", type=float,
                    default=float(os.environ.get("UA_POLICY_MONTHS", 6)))
    ap.add_argument("--browser-months", type=float, help="override the browser window")
    ap.add_argument("--client-months", type=float, help="override the client window")
    ap.add_argument("--allow-ua", action="append", default=[], help="extra UA allowlist regex (repeatable)")
    ap.add_argument("--esr-lines", choices=["all", "primary", "off"], default="all")
    ap.add_argument("--json", action="store_true", help="print a JSON object")
    ap.add_argument("--explain", action="store_true", help="print the reason on stderr")
    ap.add_argument("--exit-code", action="store_true", help="exit 1 when the predicate is true")
    ap.add_argument("--forged", action="store_true", help="evaluate the proof-only predicate")
    ap.add_argument("--allow-undated", action="store_true",
                    help="return false/data-unavailable instead of exiting 3")
    ap.add_argument("--cache", default=os.environ.get("UA_CACHE", "./ua-cache"))
    ap.add_argument("--refresh", action="store_true", help="re-download every source")
    ap.add_argument("--offline", action="store_true", help="never fetch")
    ap.add_argument("--from-build", help="read browser/client release JSONs from this directory")
    ap.add_argument("--dump-build", help="write the fetched release tables here")
    ap.add_argument("--max-data-age-days", type=float, default=7.0,
                    help="refresh when the cache is older than this")

    ap.add_argument("--nginx-policy", dest="out", help="write the nginx map policy")
    ap.add_argument("--nginx-snippet", dest="snippet", help="write the nginx include snippet")
    ap.add_argument("--nginx-manifest", dest="manifest", help="write the JSON manifest")
    ap.add_argument("--nginx-stdout", dest="stdout", action="store_true",
                    help="print the policy alone")
    ap.add_argument("--nginx-dry-run", dest="dry_run", action="store_true",
                    help="print the policy with the summary, write nothing")
    ap.add_argument("--allow-ip", action="append", default=None,
                    help="add an IP to the loopback allowlist (repeatable)")
    ap.add_argument("--replace-allow-ips", action="store_true",
                    help="replace the loopback defaults instead of adding")
    ap.add_argument("--exclude-family", action="append", default=[], help="skip a family")
    ap.add_argument("--no-never-legit", dest="never_legit", action="store_false",
                    help="omit the proof-only map")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    nginx_mode = any([args.out, args.snippet, args.manifest, args.stdout, args.dry_run])
    if nginx_mode:
        if args.ua is not None:
            parser.error("a UA argument cannot be combined with --nginx-* flags")
        return nginx_main(args)
    if (args.allow_ip or args.replace_allow_ips or args.exclude_family
            or args.never_legit is False):
        parser.error("--allow-ip/--replace-allow-ips/--exclude-family/--no-never-legit "
                     "require --nginx-* flags")
    return detector_main(args)


if __name__ == "__main__":
    sys.exit(main())
