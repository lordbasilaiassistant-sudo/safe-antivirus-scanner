"""Command-line interface.

A plain `scan` does nothing but read and report. Quarantine is opt-in, requires
an explicit flag, asks for confirmation, and only *moves* files into a quarantine
folder (fully reversible) -- it never deletes. Nothing is ever executed.

Exit codes:  0 = clean / test-only,  1 = something needs review (known-bad or
heuristic), so the command is usable in scripts and CI.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import Detection, ScanResult
from .scanner import Scanner
from . import targets


def _print_report(result: ScanResult, target: str) -> None:
    print(f"\n  Scan of: {target}")
    print(f"  Files scanned: {result.files_scanned:,}   "
          f"Bytes: {result.bytes_scanned:,}   "
          f"Skipped: {len(result.skipped):,}   "
          f"Trusted (signed, cleared): {result.trusted_suppressed:,}")

    if not result.detections:
        print("\n  [OK] No signatures matched, no heuristics fired. Nothing flagged.\n")
        return

    if result.test_hits:
        print(f"\n  [TEST] {len(result.test_hits)} test detection(s) "
              f"(harmless EICAR -- the scanner is working):")
        for d in result.test_hits:
            print(f"      [{d.method}] {d.signature}  ->  {d.path}")

    if result.known_bad:
        print(f"\n  [THREAT] {len(result.known_bad)} KNOWN-BAD match(es) "
              f"-- high confidence, review before acting:")
        for d in result.known_bad:
            _print_detail(d)

    if result.suspicious:
        print(f"\n  [REVIEW] {len(result.suspicious)} heuristic flag(s) "
              f"-- NOT confirmed malware, a human should review:")
        for d in result.suspicious:
            _print_detail(d)

    if result.needs_review:
        print("\n  Nothing above was modified, quarantined, or deleted -- report only.\n")
    else:
        print("\n  Only the harmless test signature was seen.\n")


def _print_detail(d: Detection) -> None:
    print(f"      [{d.severity}/{d.method}] {d.signature}")
    print(f"          file: {d.path}")
    print(f"          why:  {d.description}")
    if d.evidence:
        print(f"          seen: {d.evidence}")


def _quarantine(result: ScanResult, qdir: Path) -> None:
    # Only ever quarantine high-confidence known-bad files. Heuristic "suspicious"
    # findings are NOT auto-quarantined -- they are review-only by design.
    targets = result.known_bad
    if not targets:
        print("  Nothing to quarantine (no known-bad files; heuristics are review-only).")
        return
    print(f"\n  About to MOVE {len(targets)} known-bad file(s) into quarantine: {qdir}")
    print("  (Reversible -- files are moved, not deleted.)")
    for d in targets:
        print(f"      {d.path}")
    answer = input("\n  Type 'yes' to proceed: ").strip().lower()
    if answer != "yes":
        print("  Aborted. No files moved.\n")
        return
    qdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    seen: set = set()
    for d in targets:
        if d.path in seen:
            continue
        seen.add(d.path)
        try:
            dest = qdir / f"{stamp}__{d.signature}__{d.path.name}"
            shutil.move(str(d.path), str(dest))
            print(f"  moved: {d.path} -> {dest}")
        except OSError as e:
            print(f"  FAILED to move {d.path}: {e}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="antivirus",
        description="Safe, read-only antivirus scanner. Reports detections for review.",
    )
    p.add_argument("--version", action="version", version=f"antivirus {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file, directory, or a built-in profile.")
    scan.add_argument("target", nargs="?", default=None,
                      help="File or directory to scan. Omit when using --profile.")
    scan.add_argument("--profile", choices=[targets.QUICK, targets.FULL], default=None,
                      help="Scan a built-in set of locations instead of a path. "
                           "'quick' = high-risk areas + autoruns; 'full' = all fixed drives.")
    scan.add_argument("--max-file-mb", type=float, default=None,
                      help="Skip files larger than this many MiB.")
    scan.add_argument("--no-heuristics", action="store_true",
                      help="Disable heuristic analyzers; use known signatures only.")
    scan.add_argument("--quarantine", metavar="DIR", default=None,
                      help="If KNOWN-BAD files are found, offer to MOVE them into DIR "
                           "(asks for confirmation; never deletes; heuristics excluded).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        if not args.profile and not args.target:
            print("  Provide a path to scan, or use --profile quick|full.")
            return 2
        max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb else None
        scanner = Scanner(max_file_bytes=max_bytes,
                          enable_heuristics=not args.no_heuristics)
        if args.profile:
            roots = targets.resolve_profile(args.profile)
            label = f"{args.profile} profile ({len(roots)} locations)"
            print(f"  {args.profile.title()} scan: {len(roots)} locations "
                  f"(this can take a while)...")
            result = scanner.scan_roots(roots)
        else:
            label = args.target
            result = scanner.scan_path(args.target)
        _print_report(result, label)

        if args.quarantine and result.known_bad:
            _quarantine(result, Path(args.quarantine))

        return 1 if result.needs_review else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
