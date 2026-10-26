# VoidTrace fresh build script.
# Usage: right-click -> Run with PowerShell. Or in a terminal:
#   powershell -ExecutionPolicy Bypass -File BUILD.ps1
#
# What it does:
#   1. Pulls the latest branch from GitHub (so you always get the
#      newest source - nothing left stale).
#   2. Wipes bin/ and obj/ (so Visual Studio can't cache an old build).
#   3. Locates MSBuild via vswhere and does a full Rebuild from the
#      command line (bypasses every VS UI cache).
#   4. Prints the path to VoidTrace.exe when done.

$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot
Write-Host ""
Write-Host "=== VoidTrace fresh build ===" -ForegroundColor Cyan
Write-Host ""

# ----- 1. Pull latest ---------------------------------------------------
Write-Host "[1/4] git pull..." -ForegroundColor Yellow
git fetch origin claude/laughing-hypatia-mnje1j 2>&1 | Out-Host
git checkout claude/laughing-hypatia-mnje1j 2>&1 | Out-Host
git pull --rebase origin claude/laughing-hypatia-mnje1j 2>&1 | Out-Host

# ----- 2. Wipe build output --------------------------------------------
Write-Host ""
Write-Host "[2/4] Clean..." -ForegroundColor Yellow
Remove-Item -Recurse -Force bin, obj -ErrorAction SilentlyContinue
Write-Host "  cleared"

# ----- 3. Make sure Luau sources are present ---------------------------
Write-Host ""
Write-Host "[3/4] Luau sources..." -ForegroundColor Yellow
if (-not (Test-Path "external\luau\Compiler\src")) {
    Remove-Item -Recurse -Force external -ErrorAction SilentlyContinue
    git clone --depth 1 https://github.com/luau-lang/luau external\luau 2>&1 | Out-Host
    Write-Host "  cloned"
} else {
    Write-Host "  already present"
}

# ----- 4. Find MSBuild + build -----------------------------------------
Write-Host ""
Write-Host "[4/4] MSBuild Rebuild..." -ForegroundColor Yellow

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere not found. Install Visual Studio 2022 with C++ workload."
}

$vsPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) {
    Write-Error "No VS install with MSBuild found."
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path $msbuild)) {
    Write-Error "MSBuild.exe not found at $msbuild"
}

Write-Host "  using $msbuild"

& $msbuild "VoidTrace executor roblox.slnx" `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /t:Rebuild `
    /m `
    /v:minimal

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "BUILD FAILED - exit code $LASTEXITCODE" -ForegroundColor Red
    Write-Host "Scroll up to see the first error." -ForegroundColor Red
    exit 1
}

# ----- 5. Report --------------------------------------------------------
$exe = Get-ChildItem -Recurse -Filter VoidTrace.exe -ErrorAction SilentlyContinue |
       Where-Object { $_.FullName -like "*Release*" } |
       Select-Object -First 1

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
if ($exe) {
    Write-Host "VoidTrace.exe is at:" -ForegroundColor Green
    Write-Host "  $($exe.FullName)" -ForegroundColor White
    Write-Host ""
    Write-Host "Right-click it, Run as administrator." -ForegroundColor White
} else {
    Write-Host "Build reported success but no VoidTrace.exe found. Odd - tell Claude." -ForegroundColor Yellow
}
Write-Host ""
