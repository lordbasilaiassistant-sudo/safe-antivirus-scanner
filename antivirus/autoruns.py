r"""Autoruns enumeration -- find what launches automatically, because that's where
persistent malware lives.

Most malware that matters survives a reboot, which means it has registered itself
in a small set of well-known launch points. We read those points (READ-ONLY) and
resolve each to the executable it runs, so the scanner can prioritise those files.

Covered launch points:
  * HKLM/HKCU  ...\Run and ...\RunOnce      (registry, via winreg read-only)
  * the per-user and all-users Startup folders
  * (best-effort) scheduled tasks listed by schtasks

We never write to the registry or modify a task. We only look.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]


@dataclass(frozen=True)
class AutorunEntry:
    location: str        # where it was registered, e.g. "HKCU\\...\\Run"
    name: str            # value/entry name
    command: str         # raw command line
    target: Path | None  # resolved executable path, if found on disk


def _extract_exe_path(command: str) -> Path | None:
    """Pull the executable path out of a command line."""
    command = command.strip()
    if not command:
        return None
    # Quoted path first.
    m = re.match(r'^"([^"]+)"', command)
    if m:
        cand = m.group(1)
    else:
        # Take up to the first .exe / .dll / .scr / .bat / .cmd, else first token.
        m = re.match(r'^(.*?\.(?:exe|dll|scr|bat|cmd|com|pif))(\s|$)', command,
                     re.IGNORECASE)
        cand = m.group(1) if m else command.split()[0]
    cand = os.path.expandvars(cand)
    p = Path(cand)
    return p if p.exists() and p.is_file() else None


def _read_registry_runs() -> list[AutorunEntry]:
    out: list[AutorunEntry] = []
    if not sys.platform.startswith("win"):
        return out
    try:
        import winreg
    except ImportError:
        return out
    roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    for root_name, subkey in _RUN_KEYS:
        try:
            with winreg.OpenKey(roots[root_name], subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    out.append(AutorunEntry(
                        location=f"{root_name}\\{subkey}",
                        name=str(name),
                        command=str(value),
                        target=_extract_exe_path(str(value)),
                    ))
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return out


def _read_startup_folders() -> list[AutorunEntry]:
    out: list[AutorunEntry] = []
    folders = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for folder in folders:
        fp = Path(folder)
        if not fp.is_dir():
            continue
        try:
            for item in fp.iterdir():
                if item.is_file():
                    out.append(AutorunEntry(
                        location=str(fp),
                        name=item.name,
                        command=str(item),
                        target=item if item.suffix.lower() != ".lnk" else None,
                    ))
        except OSError:
            continue
    return out


def _read_scheduled_tasks(timeout: float = 20.0) -> list[AutorunEntry]:
    out: list[AutorunEntry] = []
    if not sys.platform.startswith("win"):
        return out
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return out
    lines = proc.stdout.splitlines()
    if not lines:
        return out
    header = [h.strip('"') for h in lines[0].split('","')]
    try:
        name_i = header.index("TaskName")
        run_i = header.index("Task To Run")
    except ValueError:
        return out
    for line in lines[1:]:
        cols = line.split('","')
        if len(cols) <= max(name_i, run_i):
            continue
        cmd = cols[run_i].strip('"')
        target = _extract_exe_path(cmd)
        if target is None:
            continue
        out.append(AutorunEntry(
            location="ScheduledTask",
            name=cols[name_i].strip('"'),
            command=cmd,
            target=target,
        ))
    return out


def collect_autoruns(include_tasks: bool = True) -> list[AutorunEntry]:
    entries = _read_registry_runs() + _read_startup_folders()
    if include_tasks:
        entries += _read_scheduled_tasks()
    return entries


def autorun_target_files(include_tasks: bool = True) -> list[Path]:
    """Unique, existing executable files referenced by autorun entries."""
    seen: set[Path] = set()
    files: list[Path] = []
    for e in collect_autoruns(include_tasks=include_tasks):
        if e.target and e.target.exists() and e.target not in seen:
            seen.add(e.target)
            files.append(e.target)
    return files
