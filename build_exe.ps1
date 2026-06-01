# Build the standalone Windows .exe.
#
# Usage (from the project root):
#     powershell -ExecutionPolicy Bypass -File build_exe.ps1
#
# Produces: dist\AntivirusScanner.exe
#
# Reproducible by design: anyone can run this and rebuild the exact binary from
# source. No "trust me" prebuilt binaries.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> Running test suite first (a build should never ship failing tests)"
& py -m unittest discover -s tests
if ($LASTEXITCODE -ne 0) { throw "Tests failed -- aborting build." }

Write-Host "==> Ensuring PyInstaller is installed"
& py -m pip install --user --quiet pyinstaller
if ($LASTEXITCODE -ne 0) { throw "Failed to install PyInstaller." }

Write-Host "==> Building exe"
& py -m PyInstaller packaging/antivirus.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }

Write-Host "==> Done. Output: dist\AntivirusScanner.exe"
