"""Confidence scoring -- the "intelligence" that decides what actually surfaces.

A single weak signal (e.g. a binary that imports one anti-debug API) is NOT a
detection -- legitimate software does that constantly. Real confidence comes from
*combining* signals and weighing them against reputation:

  total = sum(heuristic scores on the file)
          + context boost (unsigned executable sitting in Temp/AppData/Downloads)

Then:
  * A validly code-signed executable has its heuristic suspicions SUPPRESSED --
    a trusted publisher vouches for it. This is what stops legitimate installers
    (Opera, Claude, RuneLite, ...) from being flagged just for being compressed.
  * Remaining files only surface if their combined score clears a threshold, so
    the scanner doesn't cry wolf.

Hard signature matches (known-bad hash/pattern) bypass all of this -- they are
high-confidence by definition and always reported.
"""

from __future__ import annotations

import os
from pathlib import Path

from .models import MALWARE, SUSPICIOUS, TEST, Detection, ScanResult
from .trust import verify_batch

# A file must reach this combined heuristic score to be reported as REVIEW.
REPORT_THRESHOLD = 35
# Above this, we tag the finding as high-confidence (still review-only; we never
# auto-act on heuristics).
HIGH_CONFIDENCE = 70

# Drop zones where malware typically lands, with how much suspicion they add.
# Temp/AppData/Recycle.Bin are stronger signals than Downloads (where users
# legitimately keep unsigned tools they chose to download).
_HIGH_RISK_MARKERS = (
    os.sep + "temp" + os.sep,
    os.sep + "tmp" + os.sep,
    os.sep + "appdata" + os.sep,
    os.sep + "programdata" + os.sep,
    os.sep + "$recycle.bin" + os.sep,
)
_LOW_RISK_MARKERS = (
    os.sep + "downloads" + os.sep,
)


def _location_boost(path: Path) -> int:
    s = (os.sep + str(path).lower() + os.sep)
    if any(m in s for m in _HIGH_RISK_MARKERS):
        return 20
    if any(m in s for m in _LOW_RISK_MARKERS):
        return 10
    return 0


def _is_pe(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def finalize(result: ScanResult, use_trust: bool = True) -> ScanResult:
    """Apply trust + scoring to the raw detections. Mutates and returns result.

    Adds result.trusted_suppressed (count of files cleared by a valid signature).
    """
    # Split high-confidence findings (always kept) from heuristic ones (scored).
    # Anything classified malware/test -- a known signature OR a malware-severity
    # YARA family rule -- is high-confidence by definition. SUSPICIOUS findings
    # (entropy, PE behaviour, suspicious YARA rules) are the ones we score.
    hard = [d for d in result.detections if d.severity in (MALWARE, TEST)]
    heuristics = [d for d in result.detections if d.severity not in (MALWARE, TEST)]

    # Group heuristic findings per file.
    by_file: dict[Path, list[Detection]] = {}
    for d in heuristics:
        by_file.setdefault(d.path, []).append(d)

    # Verify signatures for the PE files that got flagged (lazy + batched).
    pe_files = [p for p in by_file if _is_pe(p)]
    trust_map = verify_batch(pe_files) if (use_trust and pe_files) else {}

    trusted_suppressed = 0
    kept: list[Detection] = []

    for path, dets in by_file.items():
        info = trust_map.get(path)
        is_pe = info is not None or _is_pe(path)

        # A trusted publisher signature clears packing/behaviour suspicions.
        if info is not None and info.is_trusted:
            trusted_suppressed += 1
            continue

        total = sum(d.score for d in dets)
        if is_pe:
            total += _location_boost(path)  # unsigned/untrusted executable in a drop zone

        if total < REPORT_THRESHOLD:
            continue  # below confidence -- don't cry wolf

        tier = "high-confidence" if total >= HIGH_CONFIDENCE else "review"
        signer_note = ""
        if info is not None:
            if info.status == "NotSigned":
                signer_note = "; file is unsigned"
            elif info.status not in ("Valid", "Unknown"):
                signer_note = f"; signature status: {info.status}"
        for d in dets:
            d.evidence = (d.evidence + f"  [combined score {total}, {tier}{signer_note}]").strip()
            kept.append(d)

    result.detections = hard + kept
    result.trusted_suppressed = trusted_suppressed
    return result
