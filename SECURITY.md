# Security Policy & Safety Design

This is a security tool that other people will run on their own machines. Its
first job is to **not harm the user**. This document is the contract for that.

## Safety guarantees (enforced in code, covered by tests)

1. **A scan is read-only.** Files are opened with `"rb"`. There is no code path
   that writes to, truncates, renames, deletes, or executes a file *during a
   scan*. See `tests/test_scanner.py::TestSafety::test_scan_does_not_modify_files`.
2. **No automatic action on detections.** Findings are reported. The only thing
   that ever moves a file is the **quarantine** action, which is:
   - opt-in (an explicit flag / a button),
   - confirmed by the user first,
   - a **move** into a quarantine folder (reversible) — never a delete,
   - limited to **known-bad signature matches**; heuristic ("suspicious")
     findings are review-only and are never auto-quarantined.
3. **Nothing is ever executed.** The scanner inspects bytes. It does not run,
   load, or detonate any file it scans.
4. **It cannot escape the folder you point it at.** Symlinks and directory
   junctions are not followed, so a scan of `C:\Users\you\Downloads` cannot be
   tricked into reading or acting on files elsewhere.
5. **One bad file never crashes a scan.** Permission errors, vanished files, and
   locked files are recorded as "skipped" and the scan continues.
6. **Bounded memory.** Files are streamed in 1 MiB chunks; entropy is computed
   from a running histogram. A multi-GB file will not exhaust RAM.

## What this tool is NOT

- It is **not** a real-time/on-access antivirus. It does not install a driver,
  hook the kernel, or run in the background. That is exactly the class of
  software that *can* break a computer, and we deliberately don't do it.
- It is **not** a replacement for Microsoft Defender or a commercial AV. It ships
  with only the harmless EICAR test signature plus heuristics. Treat it as an
  on-demand triage scanner, not full endpoint protection.
- Heuristic flags are **signals to review, not verdicts.** A legitimate installer
  can be high-entropy; a normal macro-enabled spreadsheet is not malware.

## No live malware in this repository

We never commit a runnable malware sample. Signature contributions are
**fingerprints only** — SHA-256 hashes and short byte patterns, which cannot be
used to reconstruct a virus. The only test artifact used anywhere is the
industry-standard, harmless EICAR string.

## Reporting a vulnerability

If you find a way this tool could damage a user's system, mislead them into a
destructive action, or be abused, please open a private report / issue describing
the problem and a reproduction. Safety bugs are treated as the highest priority.
