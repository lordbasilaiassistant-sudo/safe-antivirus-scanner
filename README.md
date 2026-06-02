# Antivirus Scanner

A small, **safe-by-design**, open-source antivirus scanner for Windows. It scans
a folder, reports what it finds for **your review**, and never modifies your
files unless you explicitly tell it to.

It comes as a one-file Windows app (`AntivirusScanner.exe`) and a CLI.

> **Design promise:** a scan is read-only. It cannot write, delete, rename, or run
> your files. The only action that ever moves a file is an opt-in, confirmed
> *quarantine* that **moves** (never deletes) known-bad files. See
> [`SECURITY.md`](SECURITY.md).

---

## What it does

- **One-click scan profiles — no folder picking needed:**
  - **Quick Scan** — the places malware actually lands and hides: temp dirs,
    Downloads, Desktop, the AppData trees, Startup folders, and every program
    that auto-runs (registry Run keys, Startup, scheduled tasks).
  - **Full Scan** — every fixed drive.
  - **Custom** — pick a folder (the classic behaviour).
- **Real malware signatures** — ships with a baseline of real, in-the-wild
  malware fingerprints from the free **abuse.ch MalwareBazaar** feed (plus the
  harmless EICAR test signature). Refresh anytime with **Update signatures** in
  the app, or `antivirus update` / `antivirus update --full` on the CLI.
- **Optional VirusTotal second opinion** — hash-only, opt-in (`--virustotal`,
  needs a free `VT_API_KEY`). Sends a fingerprint, never your file.
- **Behavioural analysis of executables** (via `pefile`) — reads the import table
  and flags capability combinations that characterise malware: **process
  injection**, **keylogging**, **anti-analysis/sandbox-evasion**, credential
  access, and known **packer** sections.
- **Code-signing trust** — a file validly signed by a trusted publisher has its
  heuristic suspicions cleared. This is what stops legitimate installers (Opera,
  Claude, RuneLite, …) from being false-flagged just for being compressed.
- **Confidence scoring** — weak signals don't flag on their own; findings only
  surface when combined signals (and context, like an *unsigned* binary sitting
  in a temp folder) cross a threshold. Cuts false positives.
- **Heuristics** — high **entropy** packing, Office **VBA macros**, obfuscated
  **scripts**, **deceptive double extensions** like `invoice.pdf.exe`.
- **Review-first results** in three tiers: `THREAT` (known-bad) · `REVIEW`
  (heuristic, unconfirmed) · `TEST` (harmless EICAR).
- **Quarantine** that is opt-in, confirmed, reversible (move, not delete), and
  limited to known-bad matches.

## Accuracy & honest limitations

No scanner detects *every* virus — not this one, and not the big commercial names
either. Here's the real picture so you can trust the results:

- **Strong at:** known signatures, malware that betrays itself through its
  imports/behaviour (injectors, keyloggers, packers), persistence locations
  (autoruns), and obvious social-engineering tricks. The code-signing + scoring
  model keeps false positives low.
- **Weak at / does not do:** brand-new zero-days with no signature and benign-
  looking imports; fileless / in-memory-only malware (it scans files, not live
  process memory); and the proprietary behavioural-telemetry networks that
  vendors like Malwarebytes/Defender run. Its known-bad coverage is the
  MalwareBazaar feed (refreshable, and you can add your own packs) plus the
  optional VirusTotal lookup — broad, but not the full proprietary corpus a paid
  vendor maintains.
- **Heuristic `REVIEW` flags are leads, not verdicts.** An unsigned power-user
  tool (e.g. a password recovery utility) can legitimately trip them.

Treat it as a sharp **on-demand triage scanner** that runs alongside Defender —
not a replacement for it.

## What it is NOT

Not a real-time/on-access antivirus. It installs no driver and runs nothing in
the background — that's the class of software that can break a PC, and it
deliberately avoids it.

---

## Run it

### The app (no Python needed)

Double-click **`AntivirusScanner.exe`** (in `dist/` after building, or from a
release). Pick a folder → **Scan** → review results → optionally **Quarantine**.

### From source (Python 3.11+)

```powershell
# Optional but recommended for behavioural analysis + signature trust:
py -m pip install pefile pywin32

# GUI
py -m antivirus

# CLI -- one-click Quick scan (high-risk locations + autoruns), read-only
py -m antivirus.cli scan --profile quick

# CLI -- Full scan (all fixed drives)
py -m antivirus.cli scan --profile full

# CLI -- scan a specific folder
py -m antivirus.cli scan "$env:USERPROFILE\Downloads"

# CLI -- known signatures only, no heuristics
py -m antivirus.cli scan C:\some\folder --no-heuristics

# CLI -- offer to quarantine KNOWN-BAD files (asks before moving anything)
py -m antivirus.cli scan C:\some\folder --quarantine C:\Quarantine
```

CLI exit codes: `0` = clean/test-only, `1` = something needs review.

---

## Prove it's working (safe self-test)

The EICAR string is a harmless 68-byte test file every antivirus is designed to
detect. Create one and scan it:

```powershell
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
New-Item -ItemType Directory -Force "$env:TEMP\av_test" | Out-Null
Set-Content -Path "$env:TEMP\av_test\eicar.com" -Value $eicar -NoNewline -Encoding Ascii
py -m antivirus.cli scan "$env:TEMP\av_test"
```

You should see a `TEST` detection. Delete `%TEMP%\av_test` afterward.

---

## Build the .exe yourself

No "trust me" binaries — rebuild it from source:

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1
# -> dist\AntivirusScanner.exe
```

This runs the test suite, installs PyInstaller, and builds via
`packaging/antivirus.spec`.

---

## Tests

```powershell
py -m unittest discover -s tests -v
```

The suite covers detection (EICAR, hash, pattern, cross-chunk), every heuristic,
and the safety guarantees (read-only, no symlink escape, size limits, graceful
skips).

---

## Project layout

```
antivirus/
  scanner.py      read-only scanning engine (streaming, entropy, pipeline)
  targets.py      Quick/Full/Custom scan-profile location resolver
  analyzers.py    cheap heuristics (entropy / script / macro / double-extension)
  pe_analyze.py   deep PE behaviour analysis via pefile (imports/sections)
  trust.py        Authenticode code-signing verification (FP suppression)
  scoring.py      confidence scoring: combine signals, weigh against trust
  autoruns.py     read-only enumeration of Run keys / Startup / scheduled tasks
  signatures.py   built-in EICAR + JSON signature DB loader
  models.py       data models + severity vocabulary
  entropy.py      Shannon entropy
  cli.py          command-line interface
  gui.py          tkinter desktop app
  db/             JSON signature packs (fingerprints only -- never live malware)
packaging/        PyInstaller spec + entry point
tests/            unittest suite (stdlib only)
```

## Safety & contributing

Read [`SECURITY.md`](SECURITY.md) for the full safety model and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the rules (the big one: **never commit a
live malware sample** — fingerprints only).

## License

[MIT](LICENSE).
