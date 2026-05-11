# memoric.ps1 - Load/unload memoric kernel driver (PowerShell)
# Must be run as Administrator
#
# Usage:
#   .\memoric.ps1 load     - Load the driver
#   .\memoric.ps1 unload   - Unload the driver
#   .\memoric.ps1 reload   - Unload then reload
#   .\memoric.ps1 status   - Check driver status

param(
    [Parameter(Position=0)]
    [ValidateSet("load", "unload", "reload", "status")]
    [string]$Action = "load"
)

$ServiceName = "memoric"
$DriverFile = Join-Path $PSScriptRoot "memoric.sys"

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Requires Administrator. Right-click PowerShell -> Run as administrator" -ForegroundColor Red
    exit 1
}

function Get-ServiceState {
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        return $svc.Status.ToString()
    } catch {
        return $null
    }
}

function Wait-ServiceState {
    param([string]$DesiredState, [int]$TimeoutSeconds = 10)
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $state = Get-ServiceState
        if ($state -eq $DesiredState -or $state -eq $null) { return $true }
        Start-Sleep -Milliseconds 500
        $elapsed++
    }
    return $false
}

function Stop-MemoricDriver {
    $state = Get-ServiceState
    if ($state -eq $null) {
        Write-Host "[*] Service '$ServiceName' not found, nothing to stop" -ForegroundColor Gray
        return $true
    }

    if ($state -eq "Stopped") {
        Write-Host "[*] Service already stopped" -ForegroundColor Gray
    } elseif ($state -eq "Running") {
        Write-Host "[*] Stopping service..."
        sc.exe stop $ServiceName | Out-Null
        if (-not (Wait-ServiceState "Stopped" 15)) {
            $s = Get-ServiceState
            Write-Host "ERROR: Service stuck in state '$s' - close any programs using \\.\Memoric" -ForegroundColor Red
            return $false
        }
        Write-Host "[+] Service stopped" -ForegroundColor Green
    } else {
        Write-Host "[!] Service in state '$state', waiting..." -ForegroundColor Yellow
        if (-not (Wait-ServiceState "Stopped" 15)) {
            Write-Host "ERROR: Service stuck in state '$state'" -ForegroundColor Red
            return $false
        }
    }

    # Delete service
    Write-Host "[*] Deleting service..."
    sc.exe delete $ServiceName 2>$null | Out-Null

    # Wait for service to fully disappear (handles DELETE_PENDING)
    $retries = 0
    while ($retries -lt 20) {
        $s = Get-ServiceState
        if ($s -eq $null) { break }
        Start-Sleep -Milliseconds 500
        $retries++
    }

    if ((Get-ServiceState) -ne $null) {
        Write-Host "ERROR: Service marked for deletion but not yet removed." -ForegroundColor Red
        Write-Host "       Close all handles to \\.\Memoric and try again, or reboot." -ForegroundColor Red
        return $false
    }

    Write-Host "[+] Service deleted" -ForegroundColor Green
    return $true
}

function Start-MemoricDriver {
    if (-not (Test-Path $DriverFile)) {
        Write-Host "ERROR: $DriverFile not found. Build the driver first." -ForegroundColor Red
        return $false
    }

    # Check if service already exists
    $state = Get-ServiceState
    if ($state -ne $null) {
        Write-Host "ERROR: Service '$ServiceName' already exists (state=$state). Run '.\memoric.ps1 unload' first." -ForegroundColor Red
        return $false
    }

    # Create service pointing directly to the driver file (no copy needed)
    $fullPath = (Resolve-Path $DriverFile).Path
    Write-Host "[*] Creating service: binPath=$fullPath"
    sc.exe create $ServiceName type= kernel binPath= "$fullPath" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create service (exit=$LASTEXITCODE)" -ForegroundColor Red
        return $false
    }

    # Start service
    Write-Host "[*] Starting service..."
    $result = sc.exe start $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to start driver:" -ForegroundColor Red
        $result | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        Write-Host ""
        Write-Host "Common causes:" -ForegroundColor Yellow
        Write-Host "  - Test signing not enabled: bcdedit /set testsigning on" -ForegroundColor Yellow
        Write-Host "  - Driver not signed: run build.bat to rebuild + sign" -ForegroundColor Yellow
        Write-Host "  - HVCI enabled: disable in Windows Security" -ForegroundColor Yellow
        sc.exe delete $ServiceName | Out-Null
        return $false
    }

    Write-Host "[+] memoric driver loaded successfully" -ForegroundColor Green
    Write-Host "[+] Device: \\.\Memoric" -ForegroundColor Green
    return $true
}

function Show-Status {
    $state = Get-ServiceState
    if ($state -eq $null) {
        Write-Host "[-] Service '$ServiceName' not installed" -ForegroundColor Gray
        return
    }

    Write-Host "[*] Service state: $state"
    sc.exe qc $ServiceName

    if ($state -eq "Running") {
        try {
            $h = [System.IO.File]::Open("\\.\Memoric", "Open", "ReadWrite")
            $h.Close()
            Write-Host "[+] Device \\.\Memoric is accessible" -ForegroundColor Green
        } catch {
            Write-Host "[-] Device not accessible: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Main
switch ($Action) {
    "load"   { Start-MemoricDriver }
    "unload" { Stop-MemoricDriver }
    "reload" {
        if (Stop-MemoricDriver) {
            Start-MemoricDriver
        }
    }
    "status" { Show-Status }
}
