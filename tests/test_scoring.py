"""Tests for the confidence-scoring + code-signing-trust engine.

These use stubbed signature verification so they're deterministic and run
anywhere (no real signed binaries / PowerShell needed).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from antivirus import scoring                                    # noqa: E402
from antivirus.models import SUSPICIOUS, MALWARE, Detection, ScanResult  # noqa: E402
from antivirus.trust import SignatureInfo                        # noqa: E402


def _det(path, sig, score):
    return Detection(path=Path(path), signature=sig, method="heuristic",
                     severity=SUSPICIOUS, description="x", score=score)


class TestScoring(unittest.TestCase):
    def setUp(self):
        # Default stub: nothing is signed, nothing is treated as a PE on disk.
        self._orig_verify = scoring.verify_batch
        self._orig_is_pe = scoring._is_pe
        scoring._is_pe = lambda p: False
        scoring.verify_batch = lambda paths: {}

    def tearDown(self):
        scoring.verify_batch = self._orig_verify
        scoring._is_pe = self._orig_is_pe

    def test_below_threshold_is_dropped(self):
        r = ScanResult()
        r.detections = [_det("a.bin", "Heuristic.Weak", 20)]  # < 35, non-PE
        scoring.finalize(r)
        self.assertEqual(r.suspicious, [])

    def test_above_threshold_is_kept(self):
        r = ScanResult()
        r.detections = [_det("a.ps1", "Heuristic.Obfuscated.Script", 40)]
        scoring.finalize(r)
        self.assertEqual(len(r.suspicious), 1)

    def test_combined_signals_cross_threshold(self):
        r = ScanResult()
        r.detections = [_det("a.bin", "S1", 20), _det("a.bin", "S2", 20)]
        scoring.finalize(r)
        self.assertEqual(len(r.suspicious), 2)  # 40 >= 35, both kept

    def test_trusted_signature_suppresses(self):
        # File looks like a PE and is validly signed -> all suspicions cleared.
        scoring._is_pe = lambda p: True
        scoring.verify_batch = lambda paths: {
            p: SignatureInfo("Valid", "CN=Trusted Vendor") for p in paths}
        r = ScanResult()
        r.detections = [_det("vendor.exe", "Heuristic.Packed.PE", 60)]
        scoring.finalize(r)
        self.assertEqual(r.suspicious, [])
        self.assertEqual(r.trusted_suppressed, 1)

    def test_unsigned_pe_in_risky_location_gets_boost(self):
        scoring._is_pe = lambda p: True
        scoring.verify_batch = lambda paths: {
            p: SignatureInfo("NotSigned") for p in paths}
        # 20 alone is < 35, but a PE in a Temp path gets +20 -> 40 -> kept.
        r = ScanResult()
        r.detections = [_det(r"C:\Users\x\AppData\Local\Temp\evil.exe",
                             "Heuristic.Behavior.anti-analysis", 20)]
        scoring.finalize(r)
        self.assertEqual(len(r.suspicious), 1)

    def test_hard_signatures_bypass_scoring(self):
        r = ScanResult()
        r.detections = [Detection(path=Path("x.com"), signature="Known.Bad",
                                  method="hash", severity=MALWARE,
                                  description="known", score=0)]
        scoring.finalize(r)
        self.assertEqual(len(r.known_bad), 1)  # kept despite score 0


if __name__ == "__main__":
    unittest.main(verbosity=2)
