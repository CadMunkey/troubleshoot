<# 
.SYNOPSIS
Remote Support Toolkit - High-Level Activity Logger
#>

# 1. Encoding & Path Setup
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$LogFolder = "C:\SupportLogs"
if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogFolder "Support_Summary_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"

# Create fresh log file
Set-Content -Path $LogFile -Value "--- IT SUPPORT ACTIVITY SUMMARY: $env:COMPUTERNAME ---" -Encoding UTF8
Add-Content -Path $LogFile -Value "Technician Session: $(Get-Date)`n"

function Write-Log {
    param([string]$Action, [string]$Status = "INFO")
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $Line = "[$Timestamp] [$Status] - $Action"
    
    # Write to Console for you to see
    $Color = if ($Status -eq "SUCCESS") { "Green" } elseif ($Status -eq "FAILED") { "Red" } else { "Cyan" }
    Write-Host $Line -ForegroundColor $Color
    
    # Write to Log File
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Show-Menu {
    Write-Host "`n==============================================" -ForegroundColor White
    Write-Host "   REMOTE SUPPORT MENU (CLEAN LOGGING)" -ForegroundColor White
    Write-Host "==============================================" -ForegroundColor White
    Write-Host "1) Network: Flush DNS"
    Write-Host "2) Repair: Run SFC Scan (Background)"
    Write-Host "3) Cleanup: Clear Temp & Recycle Bin"
    Write-Host "4) Audit: System Info & GPU"
    Write-Host "5) Check: Pending Reboot"
    Write-Host "Q) Quit and Open Summary"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        '1' {
            Write-Log "Flushing DNS Cache..."
            try {
                ipconfig /flushdns | Out-Null
                Write-Log "DNS Flush" "SUCCESS"
            } catch {
                Write-Log "DNS Flush" "FAILED"
            }
        }
        '2' {
            Write-Log "Starting SFC Repair (This runs in background)..."
            try {
                sfc /scannow | Out-Null
                Write-Log "SFC System Repair" "SUCCESS"
            } catch {
                Write-Log "SFC System Repair" "FAILED"
            }
        }
        '3' {
            Write-Log "Cleaning Temp Files..."
            try {
                $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
                foreach ($path in $tempPaths) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
                Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "System Cleanup" "SUCCESS"
            } catch {
                Write-Log "System Cleanup" "FAILED"
            }
        }
        '4' {
            Write-Log "Gathering System Audit..."
            try {
                $cs = Get-CimInstance Win32_ComputerSystem
                $serial = (Get-CimInstance Win32_Bios).SerialNumber
                $gpu = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
                $data = "Model: $($cs.Model) | Serial: $serial | GPU: $gpu"
                Write-Log "Audit Data: $data" "SUCCESS"
            } catch {
                Write-Log "System Audit" "FAILED"
            }
        }
        '5' {
            Write-Log "Checking Pending Reboot..."
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $status = if ($reboot) { "REBOOT REQUIRED" } else { "NO REBOOT NEEDED" }
            Write-Log "Reboot Status: $status" "SUCCESS"
        }
    }
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
