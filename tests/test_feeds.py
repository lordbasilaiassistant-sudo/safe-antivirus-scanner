"""Tests for the threat-intel feed importer. Network is stubbed -- offline-safe."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from antivirus import feeds                                  # noqa: E402
from antivirus.signatures import load_all_signatures         # noqa: E402

_FAKE_FEED = """\
################################################
# MalwareBazaar recent malware samples         #
################################################
4a98b2b72a5f6c9fa0d01b6ccf9a8ff7ccfc3a3f7117398888b0b7de40eddcb0
27F8BE17CDC13A16C8462A8BBEF82F265C53F6FED2C2A2CECAC3397F2FBE8EFD
not-a-valid-hash
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
e19eed96a246d7a5f33796446931ae643afeb153d7a243e3b9d11fbd1e6d4a48
"""


class TestParse(unittest.TestCase):
    def test_parses_and_filters(self):
        hashes = feeds._parse_sha256_list(_FAKE_FEED)
        # 3 valid hex SHA-256s; comments, junk, and non-hex 'zzz...' dropped.
        self.assertEqual(len(hashes), 3)
        self.assertTrue(all(len(h) == 64 for h in hashes))
        self.assertTrue(all(h == h.lower() for h in hashes))  # normalised


class TestImportIntoDB(unittest.TestCase):
    def test_write_pack_loads_into_engine(self):
        with tempfile.TemporaryDirectory() as d:
            db_dir = Path(d)
            hashes = feeds._parse_sha256_list(_FAKE_FEED)
            n = feeds.write_signature_pack(hashes, db_dir / "mb.json",
                                           "mb", "test malware")
            self.assertEqual(n, 3)
            patterns, sig_hashes = load_all_signatures(db_dir=db_dir)
            loaded = {h.sha256 for h in sig_hashes}
            for h in hashes:
                self.assertIn(h, loaded)
            # Imported hashes are severity 'malware' (known-bad), not test.
            mb = [h for h in sig_hashes if h.name.startswith("MalwareBazaar")]
            self.assertTrue(mb)
            self.assertTrue(all(h.severity == "malware" for h in mb))


class TestVirusTotalGuard(unittest.TestCase):
    def test_no_key_is_graceful(self):
        import os
        old = os.environ.pop("VT_API_KEY", None)
        try:
            rep = feeds.virustotal_lookup(
                "0" * 64, api_key=None)
            self.assertFalse(rep.is_flagged)
            self.assertIn("api key", rep.error.lower())
        finally:
            if old is not None:
                os.environ["VT_API_KEY"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
