<# 
.SYNOPSIS
Remote Support Toolkit - Fixed Option 6 & Encoding
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
    param(
        [string]$Message, 
        [string]$Status = "INFO",
        [switch]$IsData 
    )
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $LogLine = "[$Timestamp] [$Status] - $Message"
    
    Add-Content -Path $LogFile -Value $LogLine -Encoding UTF8
    
    if ($IsData) {
        Write-Host "`n>>> DATA REPORT:" -ForegroundColor Yellow
        Write-Host $Message -ForegroundColor White
    } else {
        $Color = if ($Status -eq "SUCCESS") { "Green" } elseif ($Status -eq "FAILED") { "Red" } else { "Cyan" }
        Write-Host $LogLine -ForegroundColor $Color
    }
}

function Show-Menu {
    Write-Host "`n==============================================" -ForegroundColor White
    Write-Host "   REMOTE SUPPORT MENU (SMART LOGGING)" -ForegroundColor White
    Write-Host "==============================================" -ForegroundColor White
    Write-Host "1) Network: Flush DNS"
    Write-Host "2) Repair: Run SFC Scan (Silent)"
    Write-Host "3) Cleanup: Clear Temp & Recycle Bin"
    Write-Host "4) Audit: Show System Info & GPU (Visible)"
    Write-Host "5) Check: Pending Reboot Status"
    Write-Host "6) Check: Ping and DNS Test"
    Write-Host "Q) Quit and Open Summary"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        '1' {
            Write-Log "Flushing DNS Cache..."
            try { ipconfig /flushdns | Out-Null; Write-Log "DNS Flush" "SUCCESS" } catch { Write-Log "DNS Flush" "FAILED" }
        }
        '2' {
            Write-Log "Starting SFC Repair (Silent)..."
            try { sfc /scannow | Out-Null; Write-Log "SFC System Repair" "SUCCESS" } catch { Write-Log "SFC System Repair" "FAILED" }
        }
        '3' {
            Write-Log "Cleaning Temp Files..."
            try {
                $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
                foreach ($path in $tempPaths) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
                Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "System Cleanup" "SUCCESS"
            } catch { Write-Log "System Cleanup" "FAILED" }
        }
        '4' {
            Write-Log "Gathering System Audit..."
            try {
                $cs = Get-CimInstance Win32_ComputerSystem
                $serial = (Get-CimInstance Win32_Bios).SerialNumber
                $gpu = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
                $auditData = "Model: $($cs.Model) | Serial: $serial | GPU: $gpu | RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2))GB"
                Write-Log -Message $auditData -Status "SUCCESS" -IsData
            } catch { Write-Log "System Audit" "FAILED" }
        }
        '5' {
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $statusText = if ($reboot) { "REBOOT REQUIRED" } else { "NO REBOOT NEEDED" }
            Write-Log -Message "Reboot Status: $statusText" -Status "SUCCESS" -IsData
        }
        '6' {
            Write-Log "Testing Network Connectivity (Ping)..."
            try {
                $ipToPing = "8.8.8.8"
                $urlToPing = "www.bbc.co.uk"
                
                # Test connection returns True/False
                $pingIP = Test-Connection -ComputerName $ipToPing -Count 2 -Quiet
                $pingURL = Test-Connection -ComputerName $urlToPing -Count 2 -Quiet
                
                $resIP = if($pingIP) {"SUCCESS"} else {"FAILED"}
                $resURL = if($pingURL) {"SUCCESS"} else {"FAILED"}
                
                $pingResults = "Ping 8.8.8.8: $resIP | Ping BBC: $resURL"
                Write-Log -Message $pingResults -Status "SUCCESS" -IsData
            } catch { 
                Write-Log "Network Connectivity Test" "FAILED" 
            }
        }
    }
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
