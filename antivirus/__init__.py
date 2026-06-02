"""A safe, read-only antivirus scanner.

Design promise: a scan never modifies the system. It opens files read-only,
streams them in chunks, never follows symlinks out of the scan root, and never
deletes anything. Detections are *reported* for human review, not acted on.
"""

__version__ = "0.3.0"
