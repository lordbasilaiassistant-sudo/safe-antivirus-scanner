"""Safety + correctness tests. Uses only stdlib unittest -- no deps to install.

Run:  py -m unittest discover -s tests -v
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from antivirus.scanner import Scanner, CHUNK_SIZE          # noqa: E402
from antivirus.signatures import EICAR_STRING               # noqa: E402


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p


class TestDetection(TempDirTest):
    def test_detects_eicar(self):
        self.write("evil.com", EICAR_STRING)
        result = Scanner().scan_path(self.root)
        self.assertIn("EICAR-Test-File", {d.signature for d in result.detections})

    def test_eicar_is_test_not_threat(self):
        self.write("evil.com", EICAR_STRING)
        result = Scanner().scan_path(self.root)
        self.assertTrue(result.test_hits)
        self.assertEqual(result.known_bad, [],
                         "EICAR must be a harmless test, not known-bad")

    def test_clean_file_not_flagged(self):
        self.write("notes.txt", b"hello world, perfectly safe content\n" * 100)
        result = Scanner().scan_path(self.root)
        self.assertEqual(result.detections, [])

    def test_exact_hash_match(self):
        self.write("exact.com", EICAR_STRING)
        result = Scanner().scan_path(self.root)
        methods = {d.method for d in result.detections}
        self.assertIn("hash", methods)
        self.assertIn("pattern", methods)

    def test_pattern_split_across_chunk_boundary(self):
        pad = CHUNK_SIZE - (len(EICAR_STRING) // 2)
        data = b"A" * pad + EICAR_STRING + b"B" * 100
        self.write("split.bin", data)
        result = Scanner().scan_path(self.root)
        self.assertIn("EICAR-Test-File", {d.signature for d in result.detections})


class TestHeuristics(TempDirTest):
    # use_trust=False keeps these deterministic and PowerShell-free; trust
    # behaviour is covered separately in test_scoring.py.
    def scan(self):
        return Scanner(use_trust=False).scan_path(self.root)

    def test_double_extension_flagged(self):
        self.write("invoice.pdf.exe", b"MZ" + b"\x00" * 500)
        result = self.scan()
        self.assertIn("Heuristic.DeceptiveDoubleExtension",
                      {d.signature for d in result.suspicious})

    def test_obfuscated_script_flagged(self):
        payload = (b"$x = [System.Convert]::FromBase64String('"
                   + b"QQ" * 300 + b"');\nIEX $x\n")
        self.write("dropper.ps1", payload)
        result = self.scan()
        self.assertIn("Heuristic.Obfuscated.Script",
                      {d.signature for d in result.suspicious})

    def test_high_entropy_pe_flagged(self):
        # A PE-looking file full of (deterministic) high-entropy bytes.
        body = bytes((i * 73 + 31) % 256 for i in range(20000))
        self.write("packed.exe", b"MZ" + b"PE\x00\x00" + body)
        result = self.scan()
        sigs = {d.signature for d in result.suspicious}
        self.assertIn("Heuristic.Packed.PE", sigs)

    def test_plain_text_is_not_suspicious(self):
        self.write("readme.txt", b"This is a normal text file.\n" * 200)
        self.write("photo.jpgnote", b"not really anything special")
        result = self.scan()
        self.assertEqual(result.suspicious, [])

    def test_heuristics_can_be_disabled(self):
        self.write("invoice.pdf.exe", b"MZ" + b"\x00" * 500)
        result = Scanner(enable_heuristics=False).scan_path(self.root)
        self.assertEqual(result.suspicious, [])


class TestSafety(TempDirTest):
    def test_scan_does_not_modify_files(self):
        p = self.write("evil.com", EICAR_STRING)
        before_bytes = p.read_bytes()
        before_mtime = p.stat().st_mtime_ns
        Scanner().scan_path(self.root)
        self.assertEqual(p.read_bytes(), before_bytes, "file content changed!")
        self.assertEqual(p.stat().st_mtime_ns, before_mtime, "file mtime changed!")
        self.assertTrue(p.exists(), "file was removed!")

    def test_unreadable_file_is_skipped_not_fatal(self):
        good = self.write("good.txt", b"safe")
        missing = self.root / "ghost.bin"
        s = Scanner()
        r1 = s.scan_path(good)
        r2 = s.scan_path(missing)
        self.assertEqual(r1.detections, [])
        self.assertEqual(r2.files_scanned, 0)
        self.assertTrue(any("ghost" in str(p) for p, _ in r2.skipped))

    def test_size_limit_skips_large_files(self):
        self.write("big.bin", b"X" * (2 * 1024 * 1024))
        result = Scanner(max_file_bytes=1024).scan_path(self.root)
        self.assertEqual(result.files_scanned, 0)
        self.assertTrue(result.skipped)

    def test_should_stop_halts_scan(self):
        for i in range(10):
            self.write(f"f{i}.txt", b"content")
        result = Scanner().scan_path(self.root, should_stop=lambda: True)
        self.assertEqual(result.files_scanned, 0)

    @unittest.skipUnless(hasattr(os, "symlink"), "no symlink support")
    def test_does_not_follow_symlink_out_of_root(self):
        outside = Path(self._tmp.name).parent / "outside_eicar.com"
        try:
            outside.write_bytes(EICAR_STRING)
            link = self.root / "link.com"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation not permitted on this system")
            result = Scanner().scan_path(self.root)
            self.assertEqual(result.known_bad, [])
            self.assertNotIn("EICAR-Test-File",
                             {d.signature for d in result.detections})
        finally:
            if outside.exists():
                outside.unlink()


class TestSignatureValues(unittest.TestCase):
    def test_published_eicar_hash_matches(self):
        digest = hashlib.sha256(EICAR_STRING).hexdigest()
        self.assertEqual(
            digest,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        )

    def test_json_db_loads(self):
        from antivirus.signatures import load_all_signatures
        patterns, hashes = load_all_signatures()
        # Built-in EICAR pattern + hash must always be present.
        self.assertIn("EICAR-Test-File", {p.name for p in patterns})
        self.assertTrue(any(h.sha256.startswith("275a021") for h in hashes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
