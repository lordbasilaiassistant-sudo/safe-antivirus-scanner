"""Tests for scan-profile target resolution."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from antivirus import targets  # noqa: E402


class TestTargets(unittest.TestCase):
    def test_quick_returns_existing_paths(self):
        roots = targets.quick_scan_roots()
        # Every returned root must actually exist.
        for r in roots:
            self.assertTrue(r.exists(), f"{r} does not exist")

    def test_dedupe_drops_nested_roots(self):
        # A child path inside a parent should be collapsed away.
        parent = Path.home()
        child = Path.home() / "Downloads"
        kept = targets._dedupe_roots([parent, child])
        self.assertIn(parent.resolve(), [k for k in kept])
        self.assertNotIn(child.resolve(), [k for k in kept])

    def test_custom_profile_requires_existing_path(self):
        self.assertEqual(targets.resolve_profile(targets.CUSTOM, "Z:\\nope\\nope"), [])
        here = str(Path(__file__).resolve().parent)
        self.assertEqual(targets.resolve_profile(targets.CUSTOM, here,
                                                 include_autoruns=False),
                         [Path(here)])

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            targets.resolve_profile("bogus")


if __name__ == "__main__":
    unittest.main(verbosity=2)
