# stale_useragent_detector

A standalone, standard-library Python tool that answers one question about a
User-Agent string: is this client stale?

Status: implemented 2026-11-05. `SPEC.md` is the contract; the implementation is
`stale_useragent_detector.py`. 27 unit tests green, including byte-identical
parity of the nginx `$ua_stale` map against a reference deployment checkout.

## Detector

```bash
./stale_useragent_detector.py "Mozilla/5.0 ... Chrome/128.0.0.0 ..."
# false

./stale_useragent_detector.py --json --as-of 2026-11-05 "$UA"
# {"stale": true, "reason": "older-than-window", "family": "Chromium", ...}

echo "$UA" | ./stale_useragent_detector.py --exit-code
```

`true` means the UA names a datable family and its release is older than the
window (default 6 months). `false` covers current, allowlisted, ESR,
undatable-by-UA, and unrecognized clients. `--forged` evaluates the separate
proof-only predicate.

Exit codes: 0 decision, 1 predicate true with `--exit-code`, 2 usage, 3 data
unavailable, 4 no UA on stdin.

## Nginx mode (optional)

```bash
./stale_useragent_detector.py --nginx-policy /etc/nginx/conf.d/ua-policy.conf \
    --nginx-snippet /etc/nginx/snippets/ua-policy.conf --as-of 2026-10-01
```

Modes are exclusive: any `--nginx-*` flag selects generation, and a positional
UA is rejected there. `--nginx-stdout` and `--nginx-dry-run` preview without
writing.

## Tests

```bash
python3 -m unittest discover -s tests -v
# parity check against a reference checkout:
TIMELINES_REPO=/path/to/reference python3 -m unittest discover -s tests -v
```

## Files

- `SPEC.md` — the contract, decision rules, flags, acceptance criteria.
- `stale_useragent_detector.py` — the tool.
- `tests/` — unit and CLI tests, plus fixture timelines.
- `examples/` — generated nginx policy and snippet.
- `test-against-logs*.py` — corpus checks against real nginx logs.
- `LICENSE` — MIT.

## License

MIT. See `LICENSE`.
