@echo off
:: load.bat - Load/unload memoric kernel driver
:: Must be run as Administrator
::
:: Usage:
::   load.bat              - Load the driver
::   load.bat unload       - Unload the driver
::   load.bat status       - Check driver status
::   load.bat reload       - Unload then reload
::   load.bat enable-ts    - Enable test signing + reboot prompt
::   load.bat setup        - Full setup: enable test signing, disable HVCI, prompt reboot

setlocal

set SERVICE_NAME=memoric
set DRIVER_FILE=%~dp0memoric.sys
set DRIVER_DEST=C:\Windows\System32\drivers\memoric.sys

:: Check admin
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script requires Administrator privileges
    echo Right-click and "Run as administrator"
    exit /b 1
)

if "%1"=="unload" goto :unload
if "%1"=="status" goto :status
if "%1"=="reload" (
    call :unload
    timeout /t 2 /nobreak >nul
    goto :load
)
if "%1"=="enable-ts" goto :enable_testsign
if "%1"=="setup" goto :full_setup
goto :load

:load
echo [*] Loading memoric driver...

:: Check driver file exists
if not exist "%DRIVER_FILE%" (
    echo ERROR: memoric.sys not found at %DRIVER_FILE%
    echo Build the driver first with build.bat
    exit /b 1
)

:: Check test signing
bcdedit /enum {current} | findstr /i "testsigning.*Yes" >nul 2>&1
if errorlevel 1 (
    echo WARNING: Test signing may not be enabled
    echo Run: load.bat enable-ts  (or: bcdedit /set testsigning on + reboot^)
    echo Or run: load.bat setup   (full setup^)
)

:: Copy driver to System32\drivers
echo [*] Copying driver to %DRIVER_DEST%
copy /y "%DRIVER_FILE%" "%DRIVER_DEST%" >nul

:: Create service
echo [*] Creating service %SERVICE_NAME%...
sc create %SERVICE_NAME% type=kernel binPath="%DRIVER_DEST%" >nul 2>&1

:: Start service
echo [*] Starting service...
sc start %SERVICE_NAME%
if errorlevel 1 (
    echo.
    echo ERROR: Failed to start driver. Common causes:
    echo   - Test signing not enabled (bcdedit /set testsigning on + reboot)
    echo   - Driver not properly signed
    echo   - HVCI/VBS enabled (disable in Windows Security)
    echo   - Check DebugView for [memoric] error messages
    exit /b 1
)

echo.
echo [+] memoric driver loaded successfully
echo [+] Device path: \\.\Memoric
echo [+] Check DebugView for kernel debug output
goto :eof

:unload
echo [*] Unloading memoric driver...
sc stop %SERVICE_NAME% >nul 2>&1
sc delete %SERVICE_NAME% >nul 2>&1
del /q "%DRIVER_DEST%" 2>nul
echo [+] Driver unloaded and service removed
goto :eof

:status
echo [*] Checking memoric driver status...
sc query %SERVICE_NAME% 2>nul
if errorlevel 1 (
    echo Driver service not installed
) else (
    echo.
    echo Device test:
    powershell -c "try { $h = [System.IO.File]::Open('\\.\Memoric','Open','ReadWrite'); $h.Close(); Write-Host '[+] Device \\.\Memoric is accessible' } catch { Write-Host '[-] Device not accessible:' $_.Exception.Message }"
)
goto :eof

:enable_testsign
echo [*] Enabling test signing mode...
bcdedit /set testsigning on
if errorlevel 1 (
    echo ERROR: Failed to set test signing. Ensure Secure Boot is disabled in BIOS.
    exit /b 1
)
echo [+] Test signing enabled. Reboot required.
echo.
echo NOTE: After reboot, a "Test Mode" watermark will appear on the desktop.
echo       Use memoric's testsign_hide stealth action to conceal it.
echo.
set /p REBOOT="Reboot now? (y/N): "
if /i "%REBOOT%"=="y" (
    shutdown /r /t 5 /c "Rebooting for test signing mode"
)
goto :eof

:full_setup
echo [*] Full memoric driver setup...
echo.

:: 1. Enable test signing
echo [1/3] Enabling test signing...
bcdedit /set testsigning on >nul 2>&1
if errorlevel 1 (
    echo WARNING: Failed to enable test signing (Secure Boot may be enabled)
) else (
    echo [+] Test signing enabled
)

:: 2. Disable HVCI
echo [2/3] Disabling HVCI/VBS...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] HVCI disabled (if it was enabled)

:: 3. Disable Credential Guard
echo [3/3] Disabling Credential Guard...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] VBS disabled (if it was enabled)

echo.
echo [+] Setup complete. A reboot is required for changes to take effect.
echo.
set /p REBOOT="Reboot now? (y/N): "
if /i "%REBOOT%"=="y" (
    shutdown /r /t 5 /c "Rebooting for memoric driver setup"
)
goto :eof

endlocal
