"""Heuristic analyzers.

Each analyzer inspects a FileContext (gathered during the scanner's single
read-only pass) and returns zero or more SUSPICIOUS detections. Heuristics are
intentionally conservative and clearly labelled "Heuristic.*" so a human knows
these are *signals to review*, not confirmed malware. Nothing here writes, runs,
or modifies a file; the Office analyzer re-opens the file with zipfile in
read-only mode only.

Why these heuristics: they target the cheap, high-signal tricks real malware
uses -- packing/encryption (high entropy in an executable), VBA macros in Office
docs, obfuscated scripts, and deceptive double extensions -- without needing a
live malware corpus we'd never ship in an open-source repo.
"""

from __future__ import annotations

import re
import zipfile

from .models import SUSPICIOUS, Detection, FileContext

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Final extensions that mean "this can execute on Windows".
EXECUTABLE_EXTS = {
    ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".drv", ".efi",
}
SCRIPT_EXTS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".sh", ".py",
}
OFFICE_MACRO_EXTS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".xlam", ".ppam",
    ".doc", ".xls", ".ppt",  # legacy OLE formats can carry macros too
}
# Extensions that look harmless and are commonly used to disguise an executable.
DECEPTIVE_FIRST_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".gif",
    ".txt", ".mp3", ".mp4", ".zip", ".invoice", ".receipt",
}

_PE_MAGIC = b"MZ"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_MAGIC = b"PK\x03\x04"

# Script-obfuscation markers. Presence of several, or of a long base64 blob,
# is a classic dropper smell.
_SCRIPT_MARKERS = [
    rb"FromBase64String",
    rb"-enc(?:odedcommand)?\b",
    rb"\bIEX\b",
    rb"Invoke-Expression",
    rb"-nop\b.*-w(?:indowstyle)?\s+hidden",
    rb"DownloadString",
    rb"DownloadFile",
    rb"WScript\.Shell",
    rb"eval\(unescape",
    rb"powershell.*-e[ncods]*\s",
    rb"cmd(?:\.exe)?\s*/c",
]
_LONG_B64 = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")


def _ext_chain(name: str) -> list[str]:
    """Return lowercase extensions, e.g. 'invoice.pdf.exe' -> ['.pdf', '.exe']."""
    parts = name.lower().split(".")
    return ["." + p for p in parts[1:]] if len(parts) > 1 else []


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------

def analyze_double_extension(ctx: FileContext) -> list[Detection]:
    """invoice.pdf.exe -- a harmless-looking name hiding an executable final ext."""
    exts = _ext_chain(ctx.path.name)
    if len(exts) < 2:
        return []
    final = exts[-1]
    prev = exts[-2]
    if final in (EXECUTABLE_EXTS | SCRIPT_EXTS) and prev in DECEPTIVE_FIRST_EXTS:
        return [Detection(
            path=ctx.path,
            signature="Heuristic.DeceptiveDoubleExtension",
            method="heuristic",
            severity=SUSPICIOUS,
            description="Filename hides an executable behind a harmless-looking extension.",
            evidence=f"name ends in '{prev}{final}'",
        )]
    return []


def analyze_pe(ctx: FileContext) -> list[Detection]:
    """Windows executable that is highly compressed/encrypted -> likely packed."""
    if not ctx.head.startswith(_PE_MAGIC):
        return []
    # Confirm it's a real PE (the MZ header points to a 'PE\0\0' signature).
    is_pe = b"PE\x00\x00" in ctx.head[:4096] or ctx.path.suffix.lower() in EXECUTABLE_EXTS
    if not is_pe:
        return []
    findings = []
    if ctx.entropy >= 7.2 and ctx.size > 4096:
        findings.append(Detection(
            path=ctx.path,
            signature="Heuristic.Packed.PE",
            method="heuristic",
            severity=SUSPICIOUS,
            description="Executable has very high entropy -- consistent with packing/encryption "
                        "(also true of some legitimate installers).",
            evidence=f"PE, entropy {ctx.entropy:.2f}/8.0",
        ))
    return findings


def analyze_script(ctx: FileContext) -> list[Detection]:
    """Scripts carrying obfuscation / download-and-execute markers."""
    if ctx.path.suffix.lower() not in SCRIPT_EXTS:
        return []
    head = ctx.head
    hits = [m.decode("latin-1") for m in _SCRIPT_MARKERS_COMPILED_iter(head)]
    if _LONG_B64.search(head):
        hits.append("long base64 blob")
    if len(hits) >= 2:
        return [Detection(
            path=ctx.path,
            signature="Heuristic.Obfuscated.Script",
            method="heuristic",
            severity=SUSPICIOUS,
            description="Script combines multiple obfuscation / remote-execution markers.",
            evidence=", ".join(sorted(set(hits))[:5]),
        )]
    return []


_SCRIPT_MARKERS_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SCRIPT_MARKERS]


def _SCRIPT_MARKERS_COMPILED_iter(head: bytes):
    for rx in _SCRIPT_MARKERS_COMPILED:
        m = rx.search(head)
        if m:
            yield m.group(0)


def analyze_office_macros(ctx: FileContext) -> list[Detection]:
    """Office documents that contain VBA macros (the #1 phishing payload vector)."""
    if ctx.path.suffix.lower() not in OFFICE_MACRO_EXTS:
        return []
    has_macro = False
    evidence = ""
    # Legacy OLE format: presence of OLE magic + macro-enabled ext is the signal.
    if ctx.head.startswith(_OLE_MAGIC):
        has_macro = True
        evidence = "OLE compound document (legacy macro-capable format)"
    # Modern OOXML zip: look for a vbaProject.bin member (definitive macro marker).
    elif ctx.head.startswith(_ZIP_MAGIC):
        try:
            with zipfile.ZipFile(ctx.path) as zf:   # read-only
                if any(n.lower().endswith("vbaproject.bin") for n in zf.namelist()):
                    has_macro = True
                    evidence = "contains vbaProject.bin (embedded VBA macros)"
        except (zipfile.BadZipFile, OSError):
            return []
    if has_macro:
        return [Detection(
            path=ctx.path,
            signature="Heuristic.Office.Macro",
            method="heuristic",
            severity=SUSPICIOUS,
            description="Office document contains macros. Macros are frequently used to "
                        "deliver malware; only enable them from sources you trust.",
            evidence=evidence,
        )]
    return []


# The ordered analyzer pipeline.
ANALYZERS = [
    analyze_double_extension,
    analyze_pe,
    analyze_script,
    analyze_office_macros,
]


def run_analyzers(ctx: FileContext) -> list[Detection]:
    findings: list[Detection] = []
    for analyzer in ANALYZERS:
        try:
            findings.extend(analyzer(ctx))
        except Exception:
            # A heuristic must never crash a scan. Worst case: we miss a signal.
            continue
    return findings
