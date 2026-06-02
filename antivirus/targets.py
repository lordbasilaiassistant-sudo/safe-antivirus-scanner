"""Scan targets -- so the user never has to know *where* to scan.

A "profile" expands to a deduplicated list of existing roots:

  QUICK -- the places malware actually lands and hides: temp dirs, Downloads,
           Desktop, the per-user AppData trees, Startup folders, browser caches,
           and the Recycle Bin. Fast, high-yield.
  FULL  -- every fixed (non-removable, non-network) drive. Thorough, slow.
  CUSTOM-- a path the user explicitly chooses (the original behaviour).

All paths are environment-expanded, de-duplicated, and filtered to ones that
exist. Nothing here reads file contents; it only decides *which* roots the
read-only scanner will walk.
"""

from __future__ import annotations

import os
import string
from pathlib import Path

QUICK = "quick"
FULL = "full"
CUSTOM = "custom"


def _expand(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if not p:
            continue
        expanded = Path(os.path.expandvars(p))
        if expanded.exists():
            out.append(expanded)
    return out


def _dedupe_roots(roots: list[Path]) -> list[Path]:
    """Drop any root that is already contained within another root, so we don't
    scan the same files twice (e.g. Desktop inside the user profile in a Full scan)."""
    resolved = []
    seen = set()
    for r in roots:
        try:
            rp = r.resolve()
        except OSError:
            rp = r
        if rp in seen:
            continue
        seen.add(rp)
        resolved.append(rp)
    resolved.sort(key=lambda p: len(str(p)))
    kept: list[Path] = []
    for r in resolved:
        if any(_is_within(r, k) for k in kept):
            continue
        kept.append(r)
    return kept


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def quick_scan_roots() -> list[Path]:
    """High-risk, high-yield locations for a fast scan."""
    candidates = [
        r"%TEMP%",
        r"%TMP%",
        r"%USERPROFILE%\Downloads",
        r"%USERPROFILE%\Desktop",
        r"%USERPROFILE%\Documents",
        r"%LOCALAPPDATA%\Temp",
        r"%APPDATA%",
        r"%LOCALAPPDATA%",
        r"%PROGRAMDATA%",
        # Auto-run launch points -- classic persistence.
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
        r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
        # Browser download/cache areas where droppers land.
        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache",
        r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache",
        # Recycle Bin (malware sometimes runs from here).
        r"%SystemDrive%\$Recycle.Bin",
    ]
    return _dedupe_roots(_expand(candidates))


def fixed_drives() -> list[Path]:
    """Every fixed local drive (skips removable, network, and CD-ROM)."""
    drives: list[Path] = []
    try:
        import ctypes

        GetDriveType = ctypes.windll.kernel32.GetDriveTypeW
        DRIVE_FIXED = 3
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root) and GetDriveType(root) == DRIVE_FIXED:
                drives.append(Path(root))
    except Exception:
        # Non-Windows or API unavailable: fall back to the system drive.
        sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
        if os.path.exists(sysdrive):
            drives.append(Path(sysdrive))
    return drives


def full_scan_roots() -> list[Path]:
    return _dedupe_roots(fixed_drives())


def resolve_profile(
    profile: str,
    custom_path: str | None = None,
    include_autoruns: bool = True,
) -> list[Path]:
    """Return the roots/files to scan for a profile.

    Quick and Full also fold in autorun target files (Run keys, Startup,
    scheduled tasks), so persistence locations get covered even when they live
    outside the walked roots (e.g. in Program Files).
    """
    if profile == QUICK:
        roots = quick_scan_roots()
    elif profile == FULL:
        roots = full_scan_roots()
    elif profile == CUSTOM:
        if not custom_path:
            return []
        p = Path(custom_path)
        return [p] if p.exists() else []
    else:
        raise ValueError(f"unknown scan profile: {profile!r}")

    if include_autoruns:
        try:
            from .autoruns import autorun_target_files
            existing = {str(r).lower() for r in roots}
            for f in autorun_target_files():
                # Skip files already inside a walked root (avoid double work).
                if not any(str(f).lower().startswith(e) for e in existing):
                    roots.append(f)
        except Exception:
            pass
    return roots
