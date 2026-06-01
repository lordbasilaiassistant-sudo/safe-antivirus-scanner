"""The scanning engine.

Safety guarantees enforced here:
  * Files are opened read-only ("rb"). There is no code path that writes,
    truncates, deletes, or executes a scanned file.
  * Reads are streamed in fixed-size chunks, so a multi-GB file never loads fully
    into memory. Pattern matching keeps a small overlap so signatures that
    straddle a chunk boundary are still found. Entropy is computed from a running
    256-bucket byte histogram, never by holding the whole file.
  * Symlinks / junctions are not followed -- the walk cannot escape the scan root
    or get caught in a cycle.
  * Any per-file error (permission denied, file vanished, device busy) is caught
    and recorded as a skip. One bad file never aborts a scan or crashes.

Detection layers, in order: known byte-pattern signatures, known full-file hash,
then heuristic analyzers (entropy/PE/script/macro). Signatures are high-confidence
(severity malware/test); heuristics are review-only (severity suspicious).
"""

from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
from typing import Callable, Iterator

from .analyzers import run_analyzers
from .models import Detection, FileContext, ScanResult
from .signatures import (
    HashSignature,
    PatternSignature,
    load_all_signatures,
)

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _entropy_from_histogram(hist: list[int], total: int) -> float:
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in hist:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


class Scanner:
    def __init__(
        self,
        patterns: list[PatternSignature] | None = None,
        hashes: list[HashSignature] | None = None,
        max_file_bytes: int | None = None,
        enable_heuristics: bool = True,
    ):
        if patterns is None or hashes is None:
            default_patterns, default_hashes = load_all_signatures()
            patterns = patterns if patterns is not None else default_patterns
            hashes = hashes if hashes is not None else default_hashes
        self.patterns = patterns
        self.hashes = hashes
        self._hash_index = {h.sha256.lower(): h for h in self.hashes}
        self.max_file_bytes = max_file_bytes
        self.enable_heuristics = enable_heuristics
        self._max_pattern_len = max((len(s.pattern) for s in self.patterns), default=0)
        self._overlap = max(self._max_pattern_len - 1, 0)

    # -- public API ---------------------------------------------------------

    def scan_path(
        self,
        target: str | os.PathLike,
        progress: Callable[[Path], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> ScanResult:
        """Scan a file or recurse a directory, read-only.

        progress(path)   -- optional callback invoked before each file (for a UI).
        should_stop()     -- optional; if it returns True the scan stops cleanly.
        """
        result = ScanResult()
        root = Path(target)
        if root.is_file():
            if not (should_stop and should_stop()):
                if progress:
                    progress(root)
                self._scan_file(root, result)
        elif root.is_dir():
            for file_path in self._walk(root):
                if should_stop and should_stop():
                    break
                if progress:
                    progress(file_path)
                self._scan_file(file_path, result)
        else:
            result.skipped.append((root, "not a file or directory"))
        return result

    # -- internals ----------------------------------------------------------

    def _walk(self, root: Path) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))
            ]
            for name in filenames:
                p = Path(dirpath) / name
                if p.is_symlink():
                    continue
                yield p

    def _scan_file(self, path: Path, result: ScanResult) -> None:
        try:
            if path.is_symlink():
                result.skipped.append((path, "symlink"))
                return
            size = path.stat().st_size
            if self.max_file_bytes is not None and size > self.max_file_bytes:
                result.skipped.append((path, f"exceeds size limit ({size} bytes)"))
                return

            sha = hashlib.sha256()
            histogram = [0] * 256
            tail = b""
            head = b""
            matched_patterns: set[str] = set()

            with open(path, "rb") as fh:   # read-only; the only file access we do
                while True:
                    chunk = fh.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if not head:
                        head = chunk
                    sha.update(chunk)
                    for b in chunk:
                        histogram[b] += 1
                    window = tail + chunk
                    for sig in self.patterns:
                        if sig.name in matched_patterns:
                            continue
                        if sig.pattern in window:
                            matched_patterns.add(sig.name)
                            result.detections.append(Detection(
                                path=path,
                                signature=sig.name,
                                method="pattern",
                                severity=sig.severity,
                                description=sig.description,
                            ))
                    tail = window[-self._overlap:] if self._overlap else b""

            digest = sha.hexdigest()
            hit = self._hash_index.get(digest)
            if hit:
                result.detections.append(Detection(
                    path=path,
                    signature=hit.name,
                    method="hash",
                    severity=hit.severity,
                    description=hit.description,
                ))

            if self.enable_heuristics:
                ctx = FileContext(
                    path=path,
                    size=size,
                    head=head,
                    entropy=_entropy_from_histogram(histogram, size),
                    sha256=digest,
                )
                result.detections.extend(run_analyzers(ctx))

            result.files_scanned += 1
            result.bytes_scanned += size

        except (OSError, PermissionError) as e:
            result.skipped.append((path, type(e).__name__))
