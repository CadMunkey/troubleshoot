<# 
.SYNOPSIS
Remote Support Toolkit - Hybrid Logging (Silent Actions + Visible Data)
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
        [switch]$IsData # Use this to show full output in console
    )
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $LogLine = "[$Timestamp] [$Status] - $Message"
    
    # 1. Log to File
    Add-Content -Path $LogFile -Value $LogLine -Encoding UTF8
    
    # 2. Display to Console
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
    Write-Host "6) Check: Ping and DNS"
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
                
                # Using -IsData shows it in the console and logs it
                Write-Log -Message $auditData -Status "SUCCESS" -IsData
            } catch { Write-Log "System Audit" "FAILED" }
        }
        '5' {
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            $statusText = if ($reboot) { "REBOOT REQUIRED" } else { "NO REBOOT NEEDED" }
            Write-Log -Message "Reboot Status: $statusText" -Status "SUCCESS" -IsData
        }
        '6' {
            Write-Log "Gathering System Audit..."
            try {
                $ipToPing="8.8.8.8"
                $urltoPing= "http://www.bbc.co.uk"
                ping $ipToPing
                ping $urlToPing
                $auditData = "Pinged: $ipToPing | Pinged: $urlToPing"
                
                # Using -IsData shows it in the console and logs it
                Write-Log -Message $auditData -Status "SUCCESS" -IsData
            } catch { Write-Log "System Audit" "FAILED" }
        }}
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
