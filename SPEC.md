# stale_useragent_detector — specification

Status: implemented 2026-11-05.
The nginx policy generator remains as an optional mode; the default behavior is
now a single User-Agent staleness verdict.

## 1. Purpose

One Python file, standard library only. Given a User-Agent string, answer one
question: is this client stale?

- `true` — the UA names a datable client family and its version was released
  before the configured age window.
- `false` — it is current, allowlisted, an ESR line, undatable by UA, or
  unrecognized.

The detector does not block anything. It returns a verdict; blocking belongs to
the caller. The existing nginx policy generation is retained as an optional mode
behind `--nginx-*` flags, not as the default behavior.

## 2. Public contract

### 2.1 Python API

```python
from stale_useragent_detector import (
    Timelines, Verdict, DataUnavailable,
    load_timelines, is_stale, is_forged,
)

timelines = load_timelines("./ua-cache")          # may fetch on cache miss/TTL
verdict = is_stale(user_agent, timelines, as_of=date(2026, 11, 5))
verdict.stale        # bool
verdict.reason       # "older-than-window" | "current" | "esr" | "allowlisted"
                     # | "no-version-in-ua" | "unrecognized" | "empty"
                     # | "version-not-in-timeline" | "data-unavailable"
verdict.family       # "Chromium" | "Chrome-iOS" | "Firefox" | "Safari" | "curl" | ...
verdict.version      # the version string actually compared, or None
verdict.released     # datetime.date of that release, or None
verdict.age_days     # int, or None
verdict.forged       # bool, computed by the proof-only predicate

is_forged(user_agent)  # bool, independent of the age verdict and allowlists
```

`is_stale()` is pure: no network, no filesystem writes. It raises
`DataUnavailable(family)` when the UA's family is datable but its timeline is
missing. `--allow-undated` on the CLI turns that into
`stale=False, reason="data-unavailable"` instead of an error.

`Timelines` is an immutable object holding the browser and client release
tables plus their `generated_at` timestamp.

### 2.2 CLI

```text
stale_useragent_detector.py [UA | -] [options]
```

With no UA argument, read one line from stdin. If stdin is a TTY and no UA was
given, exit 2 with usage (do not hang waiting for input).

Detector options:

```text
--as-of YYYY-MM-DD          measure the window from this date (default: today)
--max-age-months N          browser and client window (default: 6.0)
--browser-months N          override the browser window
--client-months N           override the client window
--allow-ua REGEX            add a UA allowlist regex (repeatable)
--esr-lines {all,primary,off}
--json                      structured result
--explain                   one-line reason on stderr; stdout stays true/false
--exit-code                 exit 1 when the selected predicate is true
--forged                    evaluate the proof-only predicate instead of staleness
--allow-undated             return false/data-unavailable instead of exit 3
--cache DIR                 download cache (default: ./ua-cache, or $UA_CACHE)
--refresh                   re-download every source
--offline                   never fetch; use cache/build or fail
--from-build DIR            read browser-releases.json and client-releases.json
--dump-build DIR            write the fetched tables there
--max-data-age-days N       refresh when the cache is older than N days (default: 7)
--version                   print the version and exit
```

Output:

- Default: `true` or `false`, one line, nothing else on stdout.
- `--json`: one object with `user_agent`, `checked`, `stale`, `forged`,
  `reason`, `family`, `version`, `released`, `age_days`, `as_of`,
  `max_age_months`.
- `--explain`: a line such as
  `Chrome 128 released 2025-03-04 (611 days old; window 6 months) => stale`
  on stderr.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | decision made (stale or not) |
| 1 | predicate true, only with `--exit-code` |
| 2 | usage error, invalid regex, self-test failure |
| 3 | data unavailable for a datable family |
| 4 | no UA on stdin |

### 2.3 Order of checks

1. Empty or whitespace-only UA -> `false`, `empty`.
2. Built-in or `--allow-ua` allowlist -> `false`, `allowlisted`.
3. Undatable client token -> `false`, `no-version-in-ua`.
4. Family and version parse -> if none, `false`, `unrecognized`.
5. Firefox ESR major declared live by Mozilla -> `false`, `esr`.
6. Release date older than the floor -> `true`, `older-than-window`;
   otherwise `false`, `current`.

The floor is `released < as_of - int(30.44 * months) days` (strict `<`, same as
the current generator). `age_days` is `(as_of - released).days`.

`forged` is computed independently: a UA matching any proof-only rule is forged
even if it is allowlisted. The `stale` verdict does not include forgery.

## 3. Family rules

| Family | UA tokens (checked in this order) | Timeline | Granularity |
|---|---|---|---|
| Chromium | `EdgiOS`, `EdgA`, `Edg`, `OPR`, `SamsungBrowser`, `Chrome` | Chrome | major |
| Chrome-iOS | `CriOS` | Chrome | major |
| Firefox | `FxiOS`, `Firefox` | Firefox | major |
| Safari | `Version/x.y` with `Safari/`, only when no Chromium/Firefox token | Safari minors | major.minor |
| curl | `curl/` | curl | full version |
| python-requests | `python-requests/` | requests | full version |
| PowerShell | `PowerShell/` | PowerShell | full version |

- Chrome-iOS deliberately uses Chrome's timeline. CriOS lags Chrome, so the
  verdict is slightly permissive for it. That is a deliberate false negative,
  not a bug.
- Safari uses the newest date for the minor. If the UA carries only a major,
  use the newest known minor of that major. A bare major must not be treated as
  the oldest release of the line.
- For full-version clients: exact match first; otherwise the nearest lower
  release date (conservative); otherwise the oldest known release. A version
  above every known release is `version-not-in-timeline` and `false`, because
  the data is older than the client, not the client stale.
- Undatable tokens: `Go-http-client/`, `node` (exact), `okhttp/`, `Wget/`,
  `Java/`, `libwww-perl/`. The UA carries no usable client version; the verdict
  is `false`, never a guess.

## 4. Data lifecycle

Sources are the 17 public timelines already in the generator (endoflife.date,
Mozilla, chromiumdash, edgeupdates, Apple, GitHub releases, PyPI, nodejs.org).
The fetch and build functions are reused unchanged.

- Cache miss or cache older than `--max-data-age-days`: fetch, then rebuild.
- Fetch failure with a usable cache: keep the cache and print a warning to
  stderr; do not fail the decision.
- No cache and no `--from-build`: exit 3, naming the missing source.
- `--from-build` reads prebuilt JSONs and performs no network access.
- `--offline` is a hard no-network switch: existing cache/build or error.
- The detector never writes into the cache during a read-only decision except
  through the documented fetch/rebuild step.

## 5. Nginx mode (optional)

Any `--nginx-*` flag selects nginx mode. A positional UA is a usage error in
that mode. Without `--nginx-*`, the tool is the detector and writes nothing.

```text
--nginx-policy PATH      write the map policy (was --out)
--nginx-snippet PATH     write the include snippet (was --snippet)
--nginx-manifest PATH    write the JSON manifest (was --manifest)
--nginx-stdout           print the policy alone, no summary
--nginx-dry-run          print the policy with the summary, write nothing
--allow-ip IP            add to the loopback allowlist (repeatable)
--replace-allow-ips      replace the loopback defaults instead of adding
--exclude-family FAM     skip a family (e.g. Safari)
--no-never-legit         omit the proof-only map
```

Shared with detector mode: `--as-of`, `--browser-months`, `--client-months`,
`--esr-lines`, `--allow-ua`, `--cache`, `--refresh`, `--offline`,
`--from-build`, `--dump-build`, `--max-data-age-days`.

The generated semantics stay exactly as they are today: `$ua_stale`,
`$ua_never_legit`, `$ua_allowlisted`, `$ua_ip_ok`, and `$ua_block`, with the
snippet using `if ($ua_block) { return 444; }` and the proof-only block checked
first, regardless of IP allowlist. `--allow-ip` adds to `127.0.0.1`/`::1`;
`--replace-allow-ips` is the only way to drop loopback.

The nginx mode must be byte-identical to the current generator for the same
inputs and `--as-of`. Parity is an acceptance test, not an aspiration.

## 6. Non-goals

- Not a WAF, IP-reputation service, JS challenge, or rate limiter.
- No nginx reload, deploy, or remote execution. Output files only.
- No per-request network calls.
- No telemetry, and no UA logging by default.
- No blocking decisions inside the detector; the caller decides.
- No third-party Python packages.

## 7. Acceptance criteria

1. `python3 -m py_compile stale_useragent_detector.py` is clean.
2. A fixed `Timelines` fixture plus `--as-of` gives the expected verdict for:
   current Chrome/Firefox/Safari/curl, old versions of each, a Safari minor
   boundary, an ESR major, CriOS, an allowlisted bot, an undatable client, an
   empty UA, and an unrecognized UA.
3. `is_stale()` performs no network I/O and raises `DataUnavailable` when the
   identified family has no timeline; `--allow-undated` returns
   `data-unavailable` instead.
4. The CLI prints exactly `true` or `false` on stdout; `--json` parses; stdin
   and positional UA forms agree; `--exit-code` maps stale/forged to 1.
5. `--offline` with no cache exits 3 and never touches the network.
6. With `--from-build` on a reference deployment's build JSONs and
   `--as-of 2026-10-01`, the `$ua_stale` map is byte-identical to its committed
   `ua-policy.conf`.
7. `nginx -t` passes on a test vhost with the generated policy and snippet
   (manual check; never against production).
8. A single decision after loading the timelines takes under 10 ms on the
   reference machine; a cold cache load takes under 100 ms.

Tests use `unittest` and fixtures; the suite must pass without network access:

```bash
python3 -m unittest discover -s tests -v
```

## 8. Migration from the pre-refactor generator

Reused unchanged: `SOURCES`, `FAMILIES`, `ALLOW_UA_DEFAULT`,
`DEFAULT_ALLOW_IP`, `NEVER_LEGIT_DEFAULT`, `NEVER_LEGIT_SAMPLE`,
`NO_VERSION_IN_UA`, `fetch_sources`, `_load`, `_date`, `safari_minors`,
`majors_from_eol`, `build_browser_releases`, `build_client_releases`,
`compress_numbers`, `version_terms`, `build_policy`, `self_test`, `render`.

New: `Timelines`, `load_timelines`, `parse_ua`, `Verdict`, `is_stale`,
`is_forged`, and a `main()` dispatcher. The old `main()` becomes `nginx_main()`.

The refactor landed 2026-11-05. The pre-refactor generator was removed after the
refactor; the new file contains the same fetch/build/policy functions. The entry
point is `stale_useragent_detector.py`. The generated `ua-policy.conf` and
`ua-policy-snippet.conf` are artifacts and live in `examples/`.

## 9. License

MIT. The file header carries `SPDX-License-Identifier: MIT`.
