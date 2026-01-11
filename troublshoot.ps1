# Master IT Support Toolkit - C:\ LOGGING VERSION
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$LogFolder = "C:\SupportLogs"
$LogFile = Join-Path $LogFolder "Support_Log_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"

if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
New-Item -Path $LogFile -ItemType File -Force | Out-Null
"--- REMOTE SESSION LOG: $env:COMPUTERNAME ---" | Out-File -FilePath $LogFile -Encoding UTF8

# Use 'UTF8' (no BOM) for the most reliable Notepad experience
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

# 1. Create/Reset the file with clean encoding
[System.IO.File]::WriteAllLines($LogFile, "--- SESSION LOG: $env:COMPUTERNAME ---", $Utf8NoBom)

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $FullLine = "[$Timestamp] $Message"
    
    # Append to file using the same clean encoding
    Add-Content -Path $LogFile -Value $FullLine -Encoding UTF8
    Write-Host $Message -ForegroundColor Cyan
}

function Show-Menu {
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host "   REMOTE TOOLKIT (LOGGING TO C:\SupportLogs)" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "1) Network: Flush DNS"
    Write-Host "2) Repair: Run SFC Scan"
    Write-Host "3) Cleanup: Clear Temp & Recycle Bin"
    Write-Host "4) Full System Audit"
    Write-Host "5) Speed Test: Local Link Speed"
    Write-Host "6) Health: Pending Reboot & Battery"
    Write-Host "7) Display: GPU Driver Status"
    Write-Host "Q) Quit and Open Log"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        '1' {
            Write-Log "Action: Flushing DNS..."
            ipconfig /flushdns | Out-File -FilePath $LogFile -Append
        }
        '2' {
            Write-Log "Action: Starting SFC Scan..."
            sfc /scannow | Out-File -FilePath $LogFile -Append
        }
        '3' {
            Write-Log "Action: Cleaning Temp Files..."
            $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
            foreach ($path in $tempPaths) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
            Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
            "Cleanup completed." | Out-File -FilePath $LogFile -Append
        }
        '4' {
            Write-Log "Action: System Audit"
            $cs = Get-CimInstance Win32_ComputerSystem
            $serial = (Get-CimInstance Win32_Bios).SerialNumber
            $audit = "Model: $($cs.Model) | Serial: $serial | RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2))GB"
            $audit | Out-File -FilePath $LogFile -Append
            Write-Host $audit
        }
        '5' {
            Write-Log "Action: Checking Link Speeds"
            Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed | Out-String | Out-File -FilePath $LogFile -Append
        }
        '6' {
            Write-Log "Action: Health Checks"
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            "Pending Reboot: $reboot" | Out-File -FilePath $LogFile -Append
            Get-CimInstance -ClassName Win32_Battery | Select-Object EstimatedChargeRemaining, Status | Out-String | Out-File -FilePath $LogFile -Append
        }
        '7' {
            Write-Log "Action: GPU Check"
            Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, Status | Out-String | Out-File -FilePath $LogFile -Append
        }
    }
} while ($choice -ne 'q')

# Open the log file for the technician before finishing
if (Test-Path $LogFile) { notepad.exe $LogFile }
