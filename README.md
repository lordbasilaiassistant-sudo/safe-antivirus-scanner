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

- **Signature detection** — known-bad byte patterns and full-file SHA-256 hashes.
  Ships with the industry-standard, harmless **EICAR** test signature so you can
  prove it works.
- **Heuristics** (review-only signals, not verdicts):
  - high **entropy** in an executable → possible packing/encryption
  - Office documents containing **VBA macros**
  - **scripts** combining obfuscation / download-and-execute markers
  - **deceptive double extensions** like `invoice.pdf.exe`
- **Review-first results** in three tiers: `THREAT` (known-bad) · `REVIEW`
  (heuristic, unconfirmed) · `TEST` (harmless EICAR).
- **Quarantine** that is opt-in, confirmed, reversible (move, not delete), and
  limited to known-bad matches.

## What it is NOT

Not a real-time/on-access antivirus and **not** a replacement for Microsoft
Defender. It installs no driver and runs nothing in the background — that's the
class of software that can break a PC, and it deliberately avoids it. Treat it as
an **on-demand triage scanner**.

---

## Run it

### The app (no Python needed)

Double-click **`AntivirusScanner.exe`** (in `dist/` after building, or from a
release). Pick a folder → **Scan** → review results → optionally **Quarantine**.

### From source (Python 3.11+)

```powershell
# GUI
py -m antivirus

# CLI -- scan a folder, read-only, just report
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
  analyzers.py    heuristic analyzers (PE / script / macro / double-extension)
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
