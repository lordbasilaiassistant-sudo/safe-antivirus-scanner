"""Signature database: byte patterns and full-file SHA-256 hashes.

Two layers:
  1. Built-in EICAR signatures, always present so the scanner is testable.
  2. Optional JSON signature files loaded from a db/ directory, so the community
     can extend detection WITHOUT editing code.

OPEN-SOURCE SAFETY RULE: this repository ships only the harmless EICAR test
signature and *fingerprints* (hashes / short byte patterns) of malware -- never a
live, runnable malware sample. A hash or pattern cannot reconstruct a virus.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .models import MALWARE, PUP, TEST


@dataclass(frozen=True)
class PatternSignature:
    name: str
    pattern: bytes
    description: str
    severity: str = MALWARE


@dataclass(frozen=True)
class HashSignature:
    name: str
    sha256: str
    description: str
    severity: str = MALWARE


# The EICAR standard test string -- 68 printable ASCII bytes, defined precisely so
# AV products have something safe to detect. NOT a virus.
EICAR_STRING = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

_BUILTIN_PATTERNS: list[PatternSignature] = [
    PatternSignature(
        name="EICAR-Test-File",
        pattern=EICAR_STRING,
        description="EICAR standard antivirus test file (harmless test signature)",
        severity=TEST,
    ),
]

_BUILTIN_HASHES: list[HashSignature] = [
    HashSignature(
        name="EICAR-Test-File (exact)",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        description="A file containing exactly the EICAR test string and nothing else",
        severity=TEST,
    ),
]

_VALID_SEVERITIES = {TEST, MALWARE, PUP}


def _coerce_pattern(value: str, encoding: str) -> bytes:
    if encoding == "hex":
        return bytes.fromhex(value)
    if encoding == "utf-8":
        return value.encode("utf-8")
    if encoding == "latin-1":
        return value.encode("latin-1")
    raise ValueError(f"unknown pattern encoding: {encoding!r}")


def load_json_db(db_dir: Path) -> tuple[list[PatternSignature], list[HashSignature]]:
    """Load every *.json signature file in db_dir. Malformed entries are skipped,
    not fatal -- a bad community file must never brick the scanner."""
    patterns: list[PatternSignature] = []
    hashes: list[HashSignature] = []
    if not db_dir.is_dir():
        return patterns, hashes
    for jf in sorted(db_dir.glob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for entry in data.get("patterns", []):
            try:
                sev = entry.get("severity", MALWARE)
                if sev not in _VALID_SEVERITIES:
                    continue
                patterns.append(PatternSignature(
                    name=str(entry["name"]),
                    pattern=_coerce_pattern(entry["pattern"], entry.get("encoding", "hex")),
                    description=str(entry.get("description", "")),
                    severity=sev,
                ))
            except (KeyError, ValueError, TypeError):
                continue
        for entry in data.get("hashes", []):
            try:
                sev = entry.get("severity", MALWARE)
                if sev not in _VALID_SEVERITIES:
                    continue
                hashes.append(HashSignature(
                    name=str(entry["name"]),
                    sha256=str(entry["sha256"]).lower().strip(),
                    description=str(entry.get("description", "")),
                    severity=sev,
                ))
            except (KeyError, TypeError):
                continue
    return patterns, hashes


def default_db_dir() -> Path:
    # When frozen by PyInstaller, bundled data lives under sys._MEIPASS.
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = Path(base) / "antivirus" / "db"
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parent / "db"


def load_all_signatures(
    db_dir: Path | None = None,
) -> tuple[list[PatternSignature], list[HashSignature]]:
    """Built-in EICAR signatures plus any JSON DB signatures."""
    extra_patterns, extra_hashes = load_json_db(db_dir or default_db_dir())
    return _BUILTIN_PATTERNS + extra_patterns, _BUILTIN_HASHES + extra_hashes


# Convenience module-level defaults (built-ins + default db dir).
PATTERN_SIGNATURES, HASH_SIGNATURES = load_all_signatures()
