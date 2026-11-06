#!/usr/bin/env python3
"""Apply a generated ua-policy.conf to real nginx logs.

Reports, per log source:
  * status matrix: how much of the traffic the UA policy would block, split by status class
  * $ua_never_legit hits (the proof-only block)
  * which user agents still get served (2xx/3xx) -- the false-positive check that matters

Usage: ./test-against-logs.py ua-policy.conf [logdir]
The logdir defaults to ./nginx-logs (or $NGINX_LOG_DIR) and must contain nginx
access logs (access.log*); *doh-access.log* files are classified separately.
"""
import glob
import gzip
import os
import re
import sys
from collections import Counter, defaultdict

LOG_DIR = (sys.argv[2] if len(sys.argv) > 2
           else os.environ.get("NGINX_LOG_DIR", "./nginx-logs"))


def rules_from_conf(path):
    stale, allow, never, section, fam = [], [], [], None, None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("map "):
                section = ("stale" if "$ua_stale {" in s
                           else "allow" if "$ua_allowlisted {" in s
                           else "never" if "$ua_never_legit {" in s else None)
                continue
            if s == "}":
                section = None
                continue
            m = re.match(r"^#\s*(\S+)$", s)
            if m and section == "stale":
                fam = m.group(1)
                continue
            m = re.match(r'^"~\*(.+)"\s+1;$', s)
            if m and section:
                {"stale": stale, "allow": allow, "never": never}[section].append((fam, m.group(1)))
    return ([(f, re.compile(r, re.I)) for f, r in stale],
            [(f, re.compile(r, re.I)) for f, r in allow],
            [re.compile(r, re.I) for _f, r in never])


def lines():
    for path in sorted(glob.glob(f"{LOG_DIR}/*access.log*")):
        kind = "doh" if "/doh-access" in path else "main"
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield kind, line.rstrip("\n")


def parse(line, kind):
    q = re.findall(r'"([^"]*)"', line)
    if len(q) < 2:
        return None
    status = next((p for p in line.split() if re.fullmatch(r"\d{3}", p)), "?")
    # main log = combined + trailing host=""/sni="" extras, so the UA is q[2];
    # the doh log uses a custom format whose last quoted field IS the UA.
    ua = q[-1] if kind == "doh" else (q[2] if len(q) >= 3 else q[-1])
    return status, q[0], ua


def main():
    conf = sys.argv[1]
    stale, allow, never = rules_from_conf(conf)
    print(f"conf: {conf}")
    print(f"  {len(stale)} stale rules, {len(allow)} allowlist rules, {len(never)} never-legit rules")

    matrix = defaultdict(Counter)        # (kind, status-class) -> blocked/kept
    never_hits = Counter()               # kind -> requests caught by $ua_never_legit
    never_status = defaultdict(Counter)  # kind -> status counts of those requests
    kept_2xx = defaultdict(Counter)      # kind -> UA of successful, non-blocked requests
    blocked_2xx = defaultdict(Counter)   # kind -> UA blocked despite a successful status

    for kind, line in lines():
        rec = parse(line, kind)
        if not rec:
            continue
        status, request, ua = rec
        if any(p.search(ua) for p in never):
            never_hits[kind] += 1
            never_status[kind][status] += 1
        fam = next((f for f, p in stale if p.search(ua)), None)
        blocked = fam is not None and not any(p.search(ua) for _f, p in allow)
        cls = "2xx/3xx" if status[:1] in "23" else status
        matrix[(kind, cls)]["blocked" if blocked else "kept"] += 1
        if status[:1] in "23":
            (blocked_2xx if blocked else kept_2xx)[kind][ua[:100]] += 1

    for kind in ("doh", "main"):
        rows = [(cls, c) for (k, cls), c in matrix.items() if k == kind]
        if not rows:
            continue
        print(f"\n[{kind}] status x policy")
        for cls, c in sorted(rows):
            b, kept = c["blocked"], c["kept"]
            tot = b + kept
            print(f"  {cls:<8} total={tot:>5}  would_block={b:>5} ({100*b/tot:>3.0f}%)  kept={kept:>5}")
        print(f"  $ua_never_legit: {never_hits.get(kind, 0)} requests"
              + (f"  status {dict(never_status[kind])}" if never_hits.get(kind) else ""))
        n = sum(blocked_2xx[kind].values())
        print(f"  false positives on served traffic: {n}")
        for ua, c in blocked_2xx[kind].most_common(4):
            print(f"    {c:>4}x  {ua}")
        print(f"  served UAs (2xx/3xx): {sum(kept_2xx[kind].values())}")
        for ua, c in kept_2xx[kind].most_common(4):
            print(f"    {c:>4}x  {ua}")


if __name__ == "__main__":
    main()
