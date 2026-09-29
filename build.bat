@echo off
setlocal
cd /d "%~dp0"

set MSBUILD="C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2^>nul`) do (
        if exist "%%i\MSBuild\Current\Bin\MSBuild.exe" set MSBUILD="%%i\MSBuild\Current\Bin\MSBuild.exe"
    )
)

echo === Building VoidTrace ===
%MSBUILD% "VoidTrace executor roblox\VoidTrace executor roblox.vcxproj" /p:Configuration=Release /p:Platform=x64 /nologo /v:minimal
if errorlevel 1 (
    echo.
    echo BUILD FAILED
    pause
    exit /b 1
)

echo.
echo === Build OK ===
echo   DLL: obj\embed\VoidTrace.dll
echo   EXE: bin\x64\Release\VoidTrace.exe
echo.
echo Launching VoidTrace.exe...
start "" "bin\x64\Release\VoidTrace.exe"
endlocal
