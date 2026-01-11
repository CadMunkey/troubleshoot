# Master IT Support Toolkit - REMOTE SAFE with LOGGING
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Setup Log File on Desktop
$LogFile = "$env:USERPROFILE\Desktop\Support_Log_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
"IT Support Session Log - $(Get-Date)" | Out-File -FilePath $LogFile
"----------------------------------------------" | Out-File -FilePath $LogFile -Append

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "HH:mm:ss"
    "[$Timestamp] $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message -ForegroundColor Cyan
}

function Show-Menu {
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host "   REMOTE TOOLKIT (LOGGING TO DESKTOP)" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "1) Network: Flush DNS (Safe)"
    Write-Host "2) Repair: Run SFC Scan"
    Write-Host "3) Cleanup: Clear Temp & Recycle Bin"
    Write-Host "4) Full System Audit"
    Write-Host "5) Speed Test: Local Link Speed"
    Write-Host "6) Health: Pending Reboot & Battery"
    Write-Host "7) Display: GPU Driver Status"
    Write-Host "Q) Quit"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        '1' {
            Write-Log "Action: Flushing DNS..."
            ipconfig /flushdns | Out-File -FilePath $LogFile -Append
            Write-Host "Done." -ForegroundColor Green
        }
        '2' {
            Write-Log "Action: Starting SFC Scan..."
            sfc /scannow | Out-File -FilePath $LogFile -Append
            Write-Host "Scan Finished. Check log for details." -ForegroundColor Green
        }
        '3' {
            Write-Log "Action: Cleaning Temp Files..."
            $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
            foreach ($path in $tempPaths) { 
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue 
            }
            Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
            "Temp files and Recycle Bin cleared." | Out-File -FilePath $LogFile -Append
            Write-Host "Cleanup done." -ForegroundColor Green
        }
        '4' {
            Write-Log "Action: System Audit"
            $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version
            $cs = Get-CimInstance Win32_ComputerSystem | Select-Object Model, TotalPhysicalMemory
            $serial = (Get-CimInstance Win32_Bios).SerialNumber
            
            $audit = "PC: $env:COMPUTERNAME | Model: $($cs.Model) | Serial: $serial | OS: $($os.Caption)"
            $audit | Out-File -FilePath $LogFile -Append
            Write-Host $audit
        }
        '5' {
            Write-Log "Action: Checking Link Speeds"
            $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed
            $adapters | Out-File -FilePath $LogFile -Append
            $adapters | Format-Table | Out-String | Write-Host
        }
        '6' {
            Write-Log "Action: Health Checks"
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $msg = "Pending Reboot: $reboot"
            $msg | Out-File -FilePath $LogFile -Append
            Write-Host $msg
            
            Get-CimInstance -ClassName Win32_Battery | Select-Object EstimatedChargeRemaining, Status | Out-File -FilePath $LogFile -Append
        }
        '7' {
            Write-Log "Action: GPU Check"
            $gpu = Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, Status
            $gpu | Out-File -FilePath $LogFile -Append
            $gpu | Format-Table | Out-String | Write-Host
        }
    }
} while ($choice -ne 'q')

Write-Log "Session Ended."
Write-Host "Log saved to: $LogFile" -ForegroundColor Yellow
