<# 
.SYNOPSIS
Remote Support Toolkit - Final Production Version
#>

# 1. FORCE PIPELINE ENCODING (Prevents spaced-out letters in command output)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'

# 2. Setup Log Folder & File
$LogFolder = "C:\SupportLogs"
if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogFolder "Support_Log_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"

# Create fresh log file
Set-Content -Path $LogFile -Value "--- IT SUPPORT SESSION: $env:COMPUTERNAME ---" -Encoding UTF8
Add-Content -Path $LogFile -Value "Started at: $(Get-Date)"

function Write-Log {
    param([string]$Message, [switch]$NoConsole)
    $Timestamp = Get-Date -Format "HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$Timestamp] $Message"
    if (!$NoConsole) { Write-Host $Message -ForegroundColor Cyan }
}

function Show-Menu {
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host "   REMOTE TOOLKIT (LOGGING TO C:\SupportLogs)" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "1) Network: Flush DNS (Safe)"
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
            # Using Out-String forces the external command to become a clean string
            ipconfig /flushdns | Out-String | Add-Content -Path $LogFile
        }
        '2' {
            Write-Log "Action: Starting SFC Scan..."
            sfc /scannow | Out-String | Add-Content -Path $LogFile
        }
        '3' {
            Write-Log "Action: Cleaning Temp Files..."
            $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
            foreach ($path in $tempPaths) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
            Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Cleanup completed."
        }
        '4' {
            Write-Log "Action: System Audit"
            $cs = Get-CimInstance Win32_ComputerSystem
            $serial = (Get-CimInstance Win32_Bios).SerialNumber
            $audit = "Model: $($cs.Model) | Serial: $serial | RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2))GB"
            Write-Log $audit
        }
        '5' {
            Write-Log "Action: Checking Link Speeds"
            Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed | Out-String | Add-Content -Path $LogFile
        }
        '6' {
            Write-Log "Action: Health Checks"
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            Write-Log "Pending Reboot: $reboot"
            Get-CimInstance -ClassName Win32_Battery | Select-Object EstimatedChargeRemaining, Status | Out-String | Add-Content -Path $LogFile
        }
        '7' {
            Write-Log "Action: GPU Check"
            Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, Status | Out-String | Add-Content -Path $LogFile
        }
    }
} while ($choice -ne 'q')

# Final Log check and open
if (Test-Path $LogFile) { 
    Write-Host "Log saved to $LogFile" -ForegroundColor Yellow
    notepad.exe $LogFile 
}
