@echo off
:: build.bat - Build memoric kernel driver
:: Run from a WDK / VS Developer Command Prompt (x64 Native Tools)
::
:: Prerequisites:
::   - Visual Studio 2019/2022 with C++ Desktop workload
::   - Windows Driver Kit (WDK) 10 installed
::   - Run from "x64 Native Tools Command Prompt for VS 20xx"
::     or "Enterprise WDK" command prompt

setlocal enabledelayedexpansion

:: Auto-detect Visual Studio build tools if cl.exe not in PATH
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo [*] cl.exe not found in PATH, searching for Visual Studio...
    set "VCVARS="
    for %%Y in (2022 2019) do (
        for %%E in (Enterprise Professional Community BuildTools) do (
            set "CANDIDATE=C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            if exist "!CANDIDATE!" (
                set "VCVARS=!CANDIDATE!"
                goto :found_vcvars
            )
            set "CANDIDATE=C:\Program Files (x86)\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            if exist "!CANDIDATE!" (
                set "VCVARS=!CANDIDATE!"
                goto :found_vcvars
            )
        )
    )
    :found_vcvars
    if not defined VCVARS (
        echo ERROR: Visual Studio with C++ workload not found
        echo Install VS 2019/2022 with "Desktop development with C++" or run from
        echo "x64 Native Tools Command Prompt for VS"
        exit /b 1
    )
    echo [*] Found: !VCVARS!
    call "!VCVARS!" x64 >nul 2>&1
    where cl.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Failed to initialize VS build environment
        exit /b 1
    )
    echo [*] VS x64 build environment initialized
)

:: Auto-detect WDK include/lib paths
set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"

:: Find latest WDK version
for /d %%i in ("%WDK_ROOT%\Include\10.*") do set "WDK_INC=%%~i"
for /d %%i in ("%WDK_ROOT%\Lib\10.*") do set "WDK_LIB=%%~i"

if not defined WDK_INC (
    echo ERROR: WDK not found at "%WDK_ROOT%"
    echo Install WDK from: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

echo [*] WDK Include: %WDK_INC%
echo [*] WDK Lib:     %WDK_LIB%

:: Compile
del /q memoric.obj 2>nul
echo [*] Compiling memoric.c ...
cl.exe /kernel /W4 /WX- /O2 /GS- /Gz ^
    /D _AMD64_ /D AMD64 /D _WIN64 /D NTDDI_VERSION=0x0A00000C ^
    /I "%WDK_INC%\km" ^
    /I "%WDK_INC%\shared" ^
    /I "%WDK_INC%\um" ^
    /I "." ^
    /c memoric.c /Fomemoric.obj

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

:: Link
echo [*] Linking memoric.sys ...
link.exe /DRIVER:WDM /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
    /MACHINE:X64 /RELEASE /OPT:REF /OPT:ICF ^
    /OUT:memoric.sys ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    memoric.obj ^
    ntoskrnl.lib hal.lib wdm.lib BufferOverflowFastFailK.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

:: Sign with test certificate
echo [*] Test-signing memoric.sys ...
where signtool >nul 2>&1
if errorlevel 1 (
    echo WARNING: signtool not found, skipping signing
    echo You can sign manually with:
    echo   signtool sign /v /s PrivateCertStore /n MemoricTestCert /fd sha256 memoric.sys
) else (
    :: Create test certificate if not exists
    makecert -r -pe -ss PrivateCertStore -n "CN=MemoricTestCert" MemoricTest.cer >nul 2>&1
    signtool sign /v /a /s PrivateCertStore /n MemoricTestCert /fd sha256 memoric.sys
    if errorlevel 1 (
        echo WARNING: Signing failed - you may need to sign manually
    )
)

:: Cleanup
del /q memoric.obj 2>nul

echo.
echo [+] Build complete: memoric.sys
echo [+] Size: 
for %%F in (memoric.sys) do echo     %%~zF bytes
echo.
echo Next steps:
echo   1. Ensure test signing is enabled:  bcdedit /set testsigning on
echo   2. Disable Secure Boot in BIOS/UEFI
echo   3. Disable HVCI:  reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
echo   4. Load the driver:                 load.bat
echo   5. Verify in DebugView:             Look for [memoric] messages
echo   6. To hide test signing watermark:  memoric.exe (testsign_hide stealth action)

endlocal
