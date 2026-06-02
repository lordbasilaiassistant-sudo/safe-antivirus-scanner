"""Deep PE (Windows executable) analysis -- behaviour, not just bytes.

The cheap heuristics in analyzers.py ask "does this look packed?". This module
asks the more powerful question: "what is this binary *built to do*?" It reads
the import table and sections with `pefile` and looks for capability combinations
that are hallmarks of malware:

  * process injection   (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
  * keylogging          (SetWindowsHookEx / GetAsyncKeyState / RawInput)
  * anti-analysis        (IsDebuggerPresent, NtQueryInformationProcess, anti-VM)
  * privilege / persistence  (AdjustTokenPrivileges, CreateService)
  * runtime code loading + RWX memory (GetProcAddress + VirtualProtect on packed)

Each signal carries a SCORE; the scanner combines scores and weighs them against
the file's code-signing trust. Everything here is read-only -- pefile parses the
file from disk and never executes it. If pefile is unavailable, this degrades to
a no-op so the scanner still runs.
"""

from __future__ import annotations

from pathlib import Path

from .models import SUSPICIOUS, Detection

try:
    import pefile  # type: ignore
    _HAVE_PEFILE = True
except Exception:  # pragma: no cover
    _HAVE_PEFILE = False

# Don't parse absurdly large binaries (bounded work).
_MAX_PE_BYTES = 128 * 1024 * 1024

# Capability groups: name -> (set of API substrings, how many must be present, score, why)
_CAPABILITIES = {
    "process-injection": (
        {"virtualallocex", "writeprocessmemory", "createremotethread",
         "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread",
         "ntmapviewofsection", "setthreadcontext"},
        3, 45,
        "imports APIs used to inject code into another process",
    ),
    "keylogger": (
        {"setwindowshookex", "getasynckeystate", "getkeystate",
         "registerrawinputdevices", "getrawinputdata"},
        2, 35,
        "imports APIs used to capture keystrokes",
    ),
    "anti-analysis": (
        {"isdebuggerpresent", "checkremotedebuggerpresent",
         "ntqueryinformationprocess", "outputdebugstring",
         "ntsetinformationthread", "createtoolhelp32snapshot"},
        2, 20,
        "imports anti-debugging / sandbox-evasion APIs",
    ),
    "dynamic-exec": (
        {"loadlibrary", "getprocaddress", "virtualprotect", "virtualalloc"},
        4, 10,  # weak/common on its own -- only meaningful as a corroborating signal
        "resolves APIs at runtime and changes memory protections (common in packers/loaders)",
    ),
    "privilege-persistence": (
        {"adjusttokenprivileges", "createservice", "openscmanager",
         "lookupprivilegevalue", "regsetvalueex"},
        2, 15,
        "imports APIs used to gain privileges or persist",
    ),
    "credential-access": (
        {"cryptunprotectdata", "lsaretrieveprivatedata", "samconnect",
         "netusergetinfo"},
        1, 25,
        "imports APIs associated with stealing stored credentials",
    ),
}

_STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc",
    ".reloc", ".tls", ".bss", ".debug", ".didat", ".gfids", ".sdata", ".00cfg",
}


def looks_like_pe(head: bytes) -> bool:
    return head[:2] == b"MZ"


def analyze_pe_file(path: Path, size: int) -> list[Detection]:
    if not _HAVE_PEFILE or size > _MAX_PE_BYTES:
        return []
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return []
    findings: list[Detection] = []
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ])
        imported = _collect_imports(pe)
        findings.extend(_capability_findings(path, imported))
        findings.extend(_section_findings(path, pe))
    except Exception:
        return findings
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return findings


def _collect_imports(pe) -> set[str]:
    names: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                names.add(imp.name.decode("latin-1", "ignore").lower())
    return names


def _capability_findings(path: Path, imported: set[str]) -> list[Detection]:
    out: list[Detection] = []
    for cap, (apis, need, score, why) in _CAPABILITIES.items():
        hits = {a for a in apis if any(a in name for name in imported)}
        if len(hits) >= need:
            out.append(Detection(
                path=path,
                signature=f"Heuristic.Behavior.{cap}",
                method="heuristic",
                severity=SUSPICIOUS,
                description=why,
                evidence=f"{len(hits)} matching imports: " + ", ".join(sorted(hits)[:6]),
                score=score,
            ))
    return out


def _section_findings(path: Path, pe) -> list[Detection]:
    out: list[Detection] = []
    IMAGE_SCN_MEM_WRITE = 0x80000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    weird_names = []
    wx_section = None
    for sec in getattr(pe, "sections", []):
        raw = sec.Name.rstrip(b"\x00").decode("latin-1", "ignore")
        low = raw.lower()
        if low and low not in _STANDARD_SECTIONS:
            weird_names.append(raw)
        chars = sec.Characteristics
        if (chars & IMAGE_SCN_MEM_WRITE) and (chars & IMAGE_SCN_MEM_EXECUTE):
            wx_section = raw or "<unnamed>"

    # Known packer section names are a strong signal.
    packer_markers = {"upx0", "upx1", "upx2", ".themida", ".vmp0", ".vmp1",
                      ".aspack", ".petite", ".mpress1", ".enigma1"}
    found_packer = [n for n in weird_names if n.lower() in packer_markers]
    if found_packer:
        out.append(Detection(
            path=path,
            signature="Heuristic.Packer.KnownSection",
            method="heuristic",
            severity=SUSPICIOUS,
            description="Executable has sections named by a known packer/protector.",
            evidence="sections: " + ", ".join(found_packer),
            score=30,
        ))
    if wx_section:
        out.append(Detection(
            path=path,
            signature="Heuristic.PE.WritableExecutableSection",
            method="heuristic",
            severity=SUSPICIOUS,
            description="A section is both writable and executable (W^X violation) -- "
                        "typical of self-modifying / unpacking code.",
            evidence=f"section '{wx_section}' is RWX",
            score=20,
        ))
    return out
