"""Shared data models and the severity vocabulary.

Severity is deliberately three-tiered so the human review step is meaningful:

  TEST       -- the harmless EICAR signal. Proof the scanner works. Never a threat.
  SUSPICIOUS -- a HEURISTIC fired (entropy, packing, macros, deceptive name...).
                This is NOT a confirmation. It is exactly the "review this" bucket.
  MALWARE    -- a known signature (hash or byte pattern) matched. High confidence.

The scanner reports all three; the UI/CLI surfaces SUSPICIOUS and MALWARE for the
human to review and never auto-acts on them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Severity vocabulary
TEST = "test"
SUSPICIOUS = "suspicious"
MALWARE = "malware"
PUP = "pup"  # potentially unwanted program (treated like a known finding)

_KNOWN_BAD = {MALWARE, PUP}


@dataclass
class Detection:
    path: Path
    signature: str        # short label, e.g. "EICAR-Test-File" or "Heuristic.Packed.PE"
    method: str           # "pattern" | "hash" | "heuristic"
    severity: str         # one of the constants above
    description: str      # human-readable reason
    evidence: str = ""    # optional concrete detail (e.g. "entropy 7.97, .exe")

    def is_test(self) -> bool:
        return self.severity == TEST

    def is_known_bad(self) -> bool:
        return self.severity in _KNOWN_BAD

    def is_suspicious(self) -> bool:
        return self.severity == SUSPICIOUS


@dataclass
class FileContext:
    """Everything an analyzer needs, gathered during the single read-only pass."""
    path: Path
    size: int
    head: bytes          # first chunk of the file (up to CHUNK_SIZE bytes)
    entropy: float       # Shannon entropy over the whole file, bits/byte
    sha256: str


@dataclass
class ScanResult:
    detections: list[Detection] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped: list[tuple] = field(default_factory=list)  # (path, reason)

    @property
    def known_bad(self) -> list[Detection]:
        """High-confidence findings: matched a known signature."""
        return [d for d in self.detections if d.is_known_bad()]

    @property
    def suspicious(self) -> list[Detection]:
        """Heuristic findings -- needs human review, not confirmed."""
        return [d for d in self.detections if d.is_suspicious()]

    @property
    def test_hits(self) -> list[Detection]:
        return [d for d in self.detections if d.is_test()]

    @property
    def needs_review(self) -> list[Detection]:
        """Everything a human should look at: known-bad + suspicious."""
        return [d for d in self.detections if not d.is_test()]
