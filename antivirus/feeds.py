"""Threat-intelligence feeds -- real known-bad coverage, for free.

The scanner is only as good as what it knows is bad. EICAR proves it works, but to
actually catch malware in the wild it needs a corpus of real fingerprints. This
module pulls them from free, reputable sources and an optional cloud second
opinion:

  * MalwareBazaar (abuse.ch) -- a public, CC0 feed of SHA-256 hashes of malware
    samples seen in the wild. We import the *hashes only* (fingerprints, never
    samples) into a JSON signature pack the scanner already auto-loads.
  * VirusTotal -- optional, opt-in, HASH-ONLY lookup. We send a SHA-256 (a
    fingerprint), never your file, and only when you provide an API key. It gives
    a "X of N engines flagged this" second opinion.

Everything here is network I/O and therefore opt-in / on-demand -- a normal scan
never touches the network. Importing hashes is safe to redistribute; downloading
the full feed locally is left to the user (it's large and changes constantly).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

MALWAREBAZAAR_RECENT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
MALWAREBAZAAR_FULL = "https://bazaar.abuse.ch/export/txt/sha256/full/"

_USER_AGENT = "safe-antivirus-scanner/0.3 (+https://github.com/lordbasilaiassistant-sudo/safe-antivirus-scanner)"
_SHA256_LEN = 64


def _http_get(url: str, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_sha256_list(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip().strip('"').lower()
        if len(line) == _SHA256_LEN and not line.startswith("#"):
            try:
                int(line, 16)
            except ValueError:
                continue
            out.append(line)
    return out


def fetch_malwarebazaar(full: bool = False, timeout: float = 120.0) -> list[str]:
    """Download SHA-256 hashes of recent (or full) malware samples. Returns []
    on any network/parse error -- a feed outage must never break the scanner.

    The 'full' export is a zip; 'recent' is plain text.
    """
    url = MALWAREBAZAAR_FULL if full else MALWAREBAZAAR_RECENT
    try:
        raw = _http_get(url, timeout=timeout)
    except (urllib.error.URLError, OSError, TimeoutError):
        return []
    if full or raw[:2] == b"PK":  # zipped
        import io
        import zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                name = zf.namelist()[0]
                text = zf.read(name).decode("utf-8", "ignore")
        except (zipfile.BadZipFile, IndexError, OSError):
            return []
    else:
        text = raw.decode("utf-8", "ignore")
    return _parse_sha256_list(text)


def write_signature_pack(hashes: list[str], out_path: Path, name: str,
                         description: str) -> int:
    """Write a hash list into the scanner's JSON signature-pack format."""
    pack = {
        "name": name,
        "_comment": "Auto-generated from a public threat-intel feed. "
                    "Fingerprints (SHA-256) only -- never live malware.",
        "patterns": [],
        "hashes": [
            {"name": f"MalwareBazaar.{h[:12]}", "sha256": h,
             "description": description, "severity": "malware"}
            for h in dict.fromkeys(hashes)  # dedupe, preserve order
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(pack, indent=0), encoding="utf-8")
    return len(pack["hashes"])


def update_local_db(full: bool = False, db_dir: Path | None = None) -> tuple[int, Path]:
    """Fetch MalwareBazaar and write it as a signature pack the scanner loads.

    Returns (hash_count, path). Count 0 means the fetch failed (offline, etc.).
    """
    from .signatures import default_db_dir
    db_dir = db_dir or default_db_dir()
    hashes = fetch_malwarebazaar(full=full)
    # The full feed is large and local-only (gitignored); the recent feed is the
    # small committed baseline so detection works out of the box.
    out = db_dir / ("malwarebazaar-full.json" if full else "malwarebazaar.json")
    if not hashes:
        return 0, out
    count = write_signature_pack(
        hashes, out,
        name="malwarebazaar",
        description="Known malware sample (SHA-256) from abuse.ch MalwareBazaar.",
    )
    return count, out


# --------------------------------------------------------------------------
# VirusTotal -- optional, hash-only, opt-in cloud second opinion.
# --------------------------------------------------------------------------

@dataclass
class VTReputation:
    sha256: str
    malicious: int       # number of engines flagging it
    total: int           # engines that returned a verdict
    error: str = ""

    @property
    def is_flagged(self) -> bool:
        return self.malicious > 0


def virustotal_lookup(sha256: str, api_key: str | None = None,
                      timeout: float = 30.0) -> VTReputation:
    """Look up a file HASH on VirusTotal. Never uploads the file -- only the
    fingerprint. api_key falls back to the VT_API_KEY environment variable.
    Disabled (returns an error result) if no key is configured."""
    key = api_key or os.environ.get("VT_API_KEY")
    if not key:
        return VTReputation(sha256, 0, 0, error="no API key (set VT_API_KEY)")
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": key, "User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        return VTReputation(sha256, malicious, total)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return VTReputation(sha256, 0, 0, error="not found on VirusTotal")
        return VTReputation(sha256, 0, 0, error=f"HTTP {e.code}")
    except (urllib.error.URLError, OSError, KeyError, ValueError, TimeoutError) as e:
        return VTReputation(sha256, 0, 0, error=str(e))
