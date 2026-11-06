#!/usr/bin/env python3
"""Apply a generated ua-policy.conf to real nginx logs and report what it would block.

Reads the regexes from the artifact itself ("~*..." inside map $http_user_agent $ua_stale),
so this tests exactly what would be deployed -- not a reimplementation.

Usage: ./test-against-logs-families.py ua-policy.conf [logdir]
The logdir defaults to ./nginx-logs (or $NGINX_LOG_DIR).
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
    stale, allow = [], []
    section = None
    fam = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("map "):
                section = "stale" if "$ua_stale {" in s else "allow" if "$ua_allowlisted {" in s else None
                continue
            if s == "}":
                section = None
                continue
            m = re.match(r"^#\s*(\S+)$", s)
            if m and section == "stale":
                fam = m.group(1)
                continue
            m = re.match(r'^"~\*(.+)"\s+1;$', s)
            if m:
                (stale if section == "stale" else allow).append((fam, m.group(1)))
    return stale, allow


def log_lines():
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
    parts = line.split()
    ip = parts[0]
    status = next((p for p in parts if re.fullmatch(r"\d{3}", p)), "?")
    # main log = combined + trailing host=""/sni="" extras, so the UA is q[2];
    # the doh log uses a custom format whose last quoted field IS the UA.
    if kind == "doh":
        ua = q[-1]
    else:
        ua = q[2] if len(q) >= 3 else q[-1]
    return ip, status, q[0], ua


def main():
    conf = sys.argv[1]
    stale, allow = rules_from_conf(conf)
    stale = [(f, rx, re.compile(rx, re.I)) for f, rx in stale]
    allow = [(f, re.compile(rx, re.I)) for f, rx in allow]
    print(f"conf: {conf}\n  {len(stale)} stale rules, {len(allow)} allowlist rules\n")

    total = Counter()
    uas = defaultdict(Counter)          # kind -> UA -> count
    status_of = defaultdict(Counter)   # (kind, blocked) -> status counts
    fam_hits = Counter()
    blocked_samples = defaultdict(Counter)
    paths_blocked = Counter()

    for kind, line in log_lines():
        rec = parse(line, kind)
        if not rec:
            continue
        ip, status, request, ua = rec
        total[kind] += 1
        uas[kind][ua] += 1
        fam = next((f for f, _rx, p in stale if p.search(ua)), None)
        ok = fam is None or any(p.search(ua) for _f, p in allow)
        blocked = not ok
        status_of[(kind, blocked)][status] += 1
        if blocked:
            fam_hits[(kind, fam)] += 1
            blocked_samples[kind][ua[:110]] += 1
            paths_blocked[(kind, request.split(" ")[1] if " " in request else request)] += 1

    for kind in ("doh", "main"):
        t = total[kind]
        b = sum(status_of[(kind, True)].values())
        print(f"[{kind}] requests={t}  distinct_UAs={len(uas[kind])}  blocked={b} ({100*b/t:.1f}%)" if t else f"[{kind}] empty")
        if b:
            top_status = ", ".join(f"{s}:{c}" for s, c in status_of[(kind, True)].most_common(4))
            print(f"        blocked status: {top_status}")
            for ua, c in blocked_samples[kind].most_common(5):
                print(f"        {c:>5}x  {ua}")

    for kind in ("doh", "main"):
        fams = [(f, c) for (k, f), c in fam_hits.items() if k == kind]
        if not fams:
            continue
        print(f"\nblocked by family [{kind}]:")
        for fam, c in sorted(fams, key=lambda kv: -kv[1]):
            print(f"  {str(fam):<18} {c:>5}")
        print(f"top blocked paths [{kind}]:")
        for (k, p), c in [x for x in paths_blocked.most_common() if x[0][0] == kind][:6]:
            print(f"  {c:>5}x  {p}")


if __name__ == "__main__":
    main()
