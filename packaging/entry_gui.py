"""PyInstaller entry point for the GUI build.

A tiny top-level script (PyInstaller prefers a real module entry, not `-m`).
"""

from antivirus.gui import main

if __name__ == "__main__":
    main()
