"""Authenticode (code-signing) trust checks.

Real antivirus engines lean heavily on reputation: a file validly signed by a
known publisher is almost never the thing you're hunting. We use that to KILL
false positives -- a signed-by-trusted-publisher installer should not be flagged
just for being compressed.

Cost control: signature verification is comparatively expensive, so we run it
LAZILY -- only on files a heuristic already flagged -- and we batch many paths
into a single PowerShell call. Results are cached by (path, size, mtime).

This is read-only: Get-AuthenticodeSignature inspects the file's embedded
certificate; it never modifies anything.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SignatureInfo:
    status: str          # "Valid", "NotSigned", "HashMismatch", "Unknown", ...
    signer: str = ""     # certificate subject, when present

    @property
    def is_trusted(self) -> bool:
        # "Valid" from Get-AuthenticodeSignature means the chain verified to a
        # trusted root and the file's hash matches its signature.
        return self.status == "Valid"


# (path, size, mtime_ns) -> SignatureInfo
_CACHE: dict[tuple, SignatureInfo] = {}

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = $input | Where-Object { $_ -ne $null -and $_ -ne '' }
$out = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{
    path   = $p
    status = if ($null -ne $s.Status) { $s.Status.ToString() } else { 'Unknown' }
    signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
  }
}
$out | ConvertTo-Json -Compress -Depth 3
"""


def _cache_key(path: Path) -> tuple | None:
    try:
        st = path.stat()
        return (str(path), st.st_size, st.st_mtime_ns)
    except OSError:
        return None


def verify_batch(paths: list[Path], timeout: float = 60.0) -> dict[Path, SignatureInfo]:
    """Verify many files in one PowerShell invocation. Windows only; on any other
    platform or failure, every path comes back as 'Unknown' (never crashes)."""
    result: dict[Path, SignatureInfo] = {}
    to_query: list[Path] = []
    for p in paths:
        key = _cache_key(p)
        if key and key in _CACHE:
            result[p] = _CACHE[key]
        else:
            to_query.append(p)

    if not to_query:
        return result

    if not sys.platform.startswith("win"):
        for p in to_query:
            result[p] = SignatureInfo("Unknown")
        return result

    by_str = {str(p): p for p in to_query}
    stdin_data = "\n".join(by_str.keys())
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else []
        if isinstance(parsed, dict):   # single result -> ConvertTo-Json emits an object
            parsed = [parsed]
        for row in parsed:
            sp = row.get("path", "")
            p = by_str.get(sp)
            if not p:
                continue
            info = SignatureInfo(status=row.get("status", "Unknown"),
                                 signer=row.get("signer", "") or "")
            result[p] = info
            key = _cache_key(p)
            if key:
                _CACHE[key] = info
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        for p in to_query:
            result.setdefault(p, SignatureInfo("Unknown"))
    # Anything PowerShell didn't return -> Unknown.
    for p in to_query:
        result.setdefault(p, SignatureInfo("Unknown"))
    return result


def verify(path: Path) -> SignatureInfo:
    return verify_batch([path]).get(path, SignatureInfo("Unknown"))
