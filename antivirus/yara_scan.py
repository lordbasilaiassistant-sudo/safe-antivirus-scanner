"""YARA rule engine -- pattern-based malware-family detection.

Hashes catch files you've seen before; YARA rules catch *families* -- they
describe the strings, byte patterns, and structure that a whole class of malware
shares, so a never-before-seen variant still matches. This is the same rule
language the professional AV/IR world uses, and there are large free community
rule sets you can drop into the rules/ directory.

Rules are compiled once and reused. Matching is read-only -- YARA reads file
bytes, never executes them. If yara-python isn't installed, this degrades to a
no-op so the rest of the scanner keeps working.

Rule severity comes from the rule's own metadata: a `meta:` field of
`severity = "malware"` (default) or `"suspicious"` controls how a match is
reported. Test rules can use `severity = "test"`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .models import MALWARE, SUSPICIOUS, TEST, Detection

try:
    import yara  # type: ignore
    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _HAVE_YARA = False

_VALID = {MALWARE, SUSPICIOUS, TEST}


def have_yara() -> bool:
    return _HAVE_YARA


def default_rules_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = Path(base) / "antivirus" / "rules"
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parent / "rules"


class YaraEngine:
    """Compiles the .yar files in a directory and scans files against them."""

    def __init__(self, rules_dir: Path | None = None):
        self.rules = None
        self.rule_count = 0
        if not _HAVE_YARA:
            return
        rules_dir = rules_dir or default_rules_dir()
        if not rules_dir.is_dir():
            return
        filepaths = {}
        for i, rf in enumerate(sorted(rules_dir.glob("*.yar")) +
                               sorted(rules_dir.glob("*.yara"))):
            filepaths[f"ns{i}"] = str(rf)
        if not filepaths:
            return
        try:
            # externals declared so rules referencing filename/extension compile.
            self.rules = yara.compile(
                filepaths=filepaths,
                externals={"filename": "", "extension": ""},
            )
            self.rule_count = len(filepaths)
        except yara.Error:
            # A broken community rule file shouldn't disable the whole engine.
            self.rules = _compile_individually(filepaths)
            self.rule_count = len(filepaths) if self.rules else 0

    @property
    def available(self) -> bool:
        return self.rules is not None

    def scan_file(self, path: Path) -> list[Detection]:
        if self.rules is None:
            return []
        try:
            ext = path.suffix.lower().lstrip(".")
            matches = self.rules.match(
                str(path),
                externals={"filename": path.name.lower(), "extension": ext},
                timeout=20,
            )
        except (yara.Error, OSError):
            return []
        out: list[Detection] = []
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            sev = str(meta.get("severity", MALWARE)).lower()
            if sev not in _VALID:
                sev = MALWARE
            desc = str(meta.get("description", f"Matched YARA rule '{m.rule}'"))
            score = int(meta.get("score", 0) or 0)
            if sev == SUSPICIOUS and score == 0:
                score = 45  # a YARA family heuristic is a strong review signal
            out.append(Detection(
                path=path,
                signature=f"YARA.{m.rule}",
                method="yara",
                severity=sev,
                description=desc,
                evidence="strings: " + ", ".join(
                    sorted({s.identifier for s in getattr(m, "strings", [])})[:5]),
                score=score,
            ))
        return out


def _compile_individually(filepaths: dict) -> "object | None":
    """Fallback: compile each rule file alone, skipping any that fail."""
    if not _HAVE_YARA:
        return None
    good = {}
    for ns, fp in filepaths.items():
        try:
            yara.compile(filepath=fp, externals={"filename": "", "extension": ""})
            good[ns] = fp
        except yara.Error:
            continue
    if not good:
        return None
    try:
        return yara.compile(filepaths=good,
                            externals={"filename": "", "extension": ""})
    except yara.Error:
        return None
