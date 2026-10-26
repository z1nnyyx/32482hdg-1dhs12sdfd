# VoidTrace fresh build script.
# Usage: in PowerShell from the repo folder:
#   powershell -ExecutionPolicy Bypass -File BUILD.ps1

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

Set-Location $PSScriptRoot
Write-Host ""
Write-Host "=== VoidTrace fresh build ===" -ForegroundColor Cyan
Write-Host ""

# ----- 1. Pull latest ---------------------------------------------------
Write-Host "[1/4] git pull..." -ForegroundColor Yellow
cmd /c "git fetch origin claude/laughing-hypatia-mnje1j 2>&1"
cmd /c "git checkout claude/laughing-hypatia-mnje1j 2>&1"
cmd /c "git pull --rebase origin claude/laughing-hypatia-mnje1j 2>&1"

# ----- 2. Wipe build output --------------------------------------------
Write-Host ""
Write-Host "[2/4] Clean..." -ForegroundColor Yellow
Remove-Item -Recurse -Force bin, obj -ErrorAction SilentlyContinue
Write-Host "  cleared"

# ----- 3. Make sure zstd sources are present ---------------------------
# The vcxproj compiles zstd from source via hardcoded vcpkg buildtree paths.
# We satisfy that by cloning zstd 1.5.7 to the expected folder.
Write-Host ""
Write-Host "[3/4] zstd sources..." -ForegroundColor Yellow
$zstdRoot = "vcpkg\buildtrees\zstd\src\v1.5.7-bb6cae2b2e.clean"
if (-not (Test-Path "$zstdRoot\lib\common\error_private.h")) {
    Remove-Item -Recurse -Force $zstdRoot -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path "vcpkg\buildtrees\zstd\src" | Out-Null
    cmd /c "git clone --branch v1.5.7 --depth 1 https://github.com/facebook/zstd `"$zstdRoot`" 2>&1"
    Write-Host "  cloned zstd 1.5.7"
} else {
    Write-Host "  already present"
}

# ----- 4. Find MSBuild + build -----------------------------------------
Write-Host ""
Write-Host "[4/4] MSBuild Rebuild..." -ForegroundColor Yellow

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Host "vswhere not found. Install Visual Studio 2022 with C++ workload." -ForegroundColor Red
    exit 1
}

$vsPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath
if (-not $vsPath) {
    Write-Host "No VS install with MSBuild found." -ForegroundColor Red
    exit 1
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path $msbuild)) {
    Write-Host "MSBuild.exe not found at $msbuild" -ForegroundColor Red
    exit 1
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
    Write-Host "Build reported success but no VoidTrace.exe found. Tell Claude." -ForegroundColor Yellow
}
Write-Host ""
