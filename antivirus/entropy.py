"""Shannon entropy, used as a heuristic signal.

High entropy (close to 8.0 bits/byte) means the data looks random -- which is
what you get from compression or encryption. Most legitimate code/text is well
below 8.0; packed or encrypted malware payloads tend to be very high. On its own
this proves nothing (a .zip is high-entropy and harmless), so we only ever raise
it as a low-confidence "suspicious" signal, never as a confirmed threat.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return bits-of-entropy-per-byte in [0.0, 8.0]. Empty data -> 0.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy
