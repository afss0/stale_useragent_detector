import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import stale_useragent_detector as d  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
SCRIPT = ROOT / "stale_useragent_detector.py"
AS_OF = date(2026, 11, 5)

CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36")
SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/{v} Safari/605.1.15")
FIREFOX = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) "
           "Gecko/20100101 Firefox/{v}.0")
CRIOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 "
         "(KHTML, like Gecko) CriOS/{v}.0.0.0 Mobile/15E148 Safari/604.1")


class DetectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tl = d.load_timelines(None, from_build=str(FIXTURES))

    def verdict(self, ua, **kwargs):
        return d.is_stale(ua, self.tl, as_of=AS_OF, **kwargs)

    def test_old_chrome_is_stale(self):
        v = self.verdict(CHROME.format(v=100))
        self.assertTrue(v.stale)
        self.assertEqual(v.reason, "older-than-window")
        self.assertEqual(v.family, "Chromium")
        self.assertEqual(v.released, date(2020, 1, 1))

    def test_current_chrome_is_not_stale(self):
        v = self.verdict(CHROME.format(v=140))
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "current")

    def test_version_above_timeline_is_not_stale(self):
        v = self.verdict(CHROME.format(v=150))
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "version-not-in-timeline")

    def test_safari_minor_boundary(self):
        self.assertTrue(self.verdict(SAFARI.format(v="26.5")).stale)
        self.assertFalse(self.verdict(SAFARI.format(v="26.6")).stale)

    def test_safari_above_timeline(self):
        v = self.verdict(SAFARI.format(v="26.7"))
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "version-not-in-timeline")

    def test_esr_is_not_stale(self):
        v = self.verdict(FIREFOX.format(v=140))
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "esr")

    def test_esr_can_be_disabled(self):
        v = self.verdict(FIREFOX.format(v=140), esr_lines="off")
        self.assertTrue(v.stale)
        self.assertEqual(v.reason, "older-than-window")

    def test_chrome_ios_uses_chrome_timeline(self):
        v = self.verdict(CRIOS.format(v=100))
        self.assertTrue(v.stale)
        self.assertEqual(v.family, "Chrome-iOS")

    def test_allowlisted_bot(self):
        v = self.verdict("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "allowlisted")

    def test_custom_allowlist(self):
        v = self.verdict("MyCrawler/1.0", allow_ua=[r"MyCrawler"])
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "allowlisted")

    def test_undatable_client(self):
        for ua in ("Go-http-client/1.1", "node", "Wget/1.21", "Java/1.8", "libwww-perl/6.0"):
            v = self.verdict(ua)
            self.assertFalse(v.stale, ua)
            self.assertEqual(v.reason, "no-version-in-ua", ua)

    def test_unknown_is_not_stale(self):
        v = self.verdict("SomeCustomClient/1.0")
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "unrecognized")

    def test_empty(self):
        v = self.verdict("   ")
        self.assertFalse(v.stale)
        self.assertEqual(v.reason, "empty")

    def test_forged_is_separate(self):
        v = self.verdict("zgrab/0.x")
        self.assertFalse(v.stale)
        self.assertTrue(v.forged)
        self.assertTrue(d.is_forged("Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X)"))
        self.assertFalse(d.is_forged(CHROME.format(v=140)))

    def test_client_versions(self):
        self.assertTrue(self.verdict("curl/8.0.0").stale)
        self.assertFalse(self.verdict("curl/8.19.0").stale)
        self.assertTrue(self.verdict("PowerShell/7.0.0").stale)
        self.assertFalse(self.verdict("PowerShell/7.6.0").stale)

    def test_missing_timeline_raises(self):
        empty = d.Timelines({"timelines": {}, "current": {}}, {"clients": {}})
        with self.assertRaises(d.DataUnavailable):
            d.is_stale(CHROME.format(v=140), empty, as_of=AS_OF)

    def test_window_override(self):
        # Chrome 140 is from 2026-09-01; a one-day window makes it stale.
        v = self.verdict(CHROME.format(v=140), max_age_months=0.03)
        self.assertTrue(v.stale)


class CliTest(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--from-build", str(FIXTURES),
             "--as-of", "2026-11-05", *args],
            input=stdin, capture_output=True, text=True, timeout=30)

    def test_true(self):
        p = self.run_cli(CHROME.format(v=100))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "true\n")

    def test_false(self):
        p = self.run_cli(CHROME.format(v=140))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "false\n")

    def test_json(self):
        p = self.run_cli("--json", CHROME.format(v=100))
        payload = json.loads(p.stdout)
        self.assertTrue(payload["stale"])
        self.assertEqual(payload["family"], "Chromium")
        self.assertEqual(payload["reason"], "older-than-window")
        self.assertEqual(payload["as_of"], "2026-11-05")

    def test_stdin(self):
        p = self.run_cli(stdin=CHROME.format(v=100) + "\n")
        self.assertEqual(p.stdout, "true\n")

    def test_exit_code(self):
        self.assertEqual(self.run_cli("--exit-code", CHROME.format(v=100)).returncode, 1)
        self.assertEqual(self.run_cli("--exit-code", CHROME.format(v=140)).returncode, 0)

    def test_forged(self):
        p = self.run_cli("--forged", "zgrab/0.x")
        self.assertEqual(p.stdout, "true\n")
        self.assertEqual(self.run_cli("--forged", "--exit-code", "zgrab/0.x").returncode, 1)

    def test_offline_without_cache_exits_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline", "--cache", tmp,
                 "--as-of", "2026-11-05", CHROME.format(v=140)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 3)
        self.assertIn("no release timeline", p.stderr)

    def test_allow_undated(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline", "--cache", tmp, "--allow-undated",
                 "--as-of", "2026-11-05", CHROME.format(v=140)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "false\n")

    def test_require_sources_offline_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--offline", "--cache", tmp, "--require-sources",
                 "--as-of", "2026-11-05", CHROME.format(v=140)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 3)
        self.assertIn("incomplete release data", p.stderr)

    def test_require_sources_from_build(self):
        p = self.run_cli("--require-sources", CHROME.format(v=140))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "false\n")

    def test_require_sources_incomplete_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "browser-releases.json").write_text('{"timelines": {}, "current": {}}')
            Path(tmp, "client-releases.json").write_text('{"clients": {}}')
            p = subprocess.run(
                [sys.executable, str(SCRIPT), "--from-build", tmp, "--require-sources",
                 "--as-of", "2026-11-05", CHROME.format(v=140)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 3)
        self.assertIn("incomplete release data", p.stderr)

    def test_build_only_rejects_ua(self):
        p = self.run_cli("--build-only", "/tmp/never-written", CHROME.format(v=140))
        self.assertEqual(p.returncode, 2)

    def test_build_only_rejects_from_build(self):
        p = self.run_cli("--build-only", "/tmp/never-written", "--from-build", str(FIXTURES))
        self.assertEqual(p.returncode, 2)

    def test_nginx_mode_rejects_positional_ua(self):
        p = self.run_cli("--nginx-stdout", CHROME.format(v=140))
        self.assertEqual(p.returncode, 2)


class NginxParityTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("TIMELINES_REPO"),
                         "set TIMELINES_REPO to a reference checkout with build/")
    def test_stale_map_is_byte_identical(self):
        repo = Path(os.environ["TIMELINES_REPO"])
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "--from-build", str(repo / "build"),
             "--as-of", "2026-10-01", "--nginx-stdout"],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        generated = self.block(p.stdout)
        committed = self.block((repo / "deploy" / "nginx" / "ua-policy.conf").read_text())
        self.assertEqual(generated, committed)

    @staticmethod
    def block(text):
        m = re.search(r"^map \$http_user_agent \$ua_stale \{.*?^\}", text, re.S | re.M)
        assert m, "no $ua_stale map in output"
        return m.group(0)


if __name__ == "__main__":
    unittest.main()
