# PyInstaller spec -- builds the GUI scanner into a single Windows .exe.
#
# Build with (from the project root):
#     py -m PyInstaller packaging/antivirus.spec --noconfirm
# Output:
#     dist/AntivirusScanner.exe
#
# The signature DB (antivirus/db/*.json) is bundled as data so the .exe ships
# self-contained. We bundle ONLY the harmless EICAR fingerprints -- never a live
# sample (see antivirus/db/README.md).

import os

PROJECT_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

block_cipher = None

# Bundle the JSON signature DB and its README into antivirus/db inside the exe.
db_dir = os.path.join(PROJECT_ROOT, "antivirus", "db")
datas = [
    (os.path.join(db_dir, f), os.path.join("antivirus", "db"))
    for f in os.listdir(db_dir)
    if f.endswith((".json", ".md")) and f != "malwarebazaar-full.json"
]
# Bundle YARA rules into antivirus/rules inside the exe.
rules_dir = os.path.join(PROJECT_ROOT, "antivirus", "rules")
if os.path.isdir(rules_dir):
    datas += [
        (os.path.join(rules_dir, f), os.path.join("antivirus", "rules"))
        for f in os.listdir(rules_dir)
        if f.endswith((".yar", ".yara"))
    ]

a = Analysis(
    [os.path.join(SPECPATH, "entry_gui.py")],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "antivirus.gui", "antivirus.cli", "antivirus.scanner",
        "antivirus.analyzers", "antivirus.pe_analyze", "antivirus.scoring",
        "antivirus.trust", "antivirus.targets", "antivirus.autoruns",
        "antivirus.feeds", "antivirus.yara_scan", "pefile", "yara",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="AntivirusScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,            # do NOT pack our own exe -- packing trips AV heuristics
    runtime_tmpdir=None,
    console=False,        # GUI app -- no console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
