<# 
.SYNOPSIS
Remote Support Toolkit - Production V2 (Modular & Safe)
#>

# --- 1. GLOBAL SETUP ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$LogFolder = "C:\SupportLogs"
if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogFolder "Support_Summary_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"

Set-Content -Path $LogFile -Value "--- IT SUPPORT ACTIVITY SUMMARY: $env:COMPUTERNAME ---" -Encoding UTF8
Add-Content -Path $LogFile -Value "Technician Session: $(Get-Date)`n"

# --- 2. CORE LOGGING FUNCTION ---
function Write-Log {
    param([string]$Message, [string]$Status = "INFO", [switch]$IsData)
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

# --- 3. THE TOOLBOX ---

function Invoke-DnsFlush {
    Write-Log "Flushing DNS Cache..."
    try { ipconfig /flushdns | Out-Null; Write-Log "DNS Flush" "SUCCESS" } 
    catch { Write-Log "DNS Flush" "FAILED" }
}

function Invoke-SfcRepair {
    Write-Log "Starting SFC Repair (Background)..."
    try { sfc /scannow | Out-Null; Write-Log "SFC System Repair" "SUCCESS" } 
    catch { Write-Log "SFC System Repair" "FAILED" }
}

function Invoke-SystemCleanup {
    Write-Log "Cleaning Temp Files..."
    try {
        $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
        foreach ($path in $tempPaths) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
        Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "System Cleanup" "SUCCESS"
    } catch { Write-Log "System Cleanup" "FAILED" }
}

function Get-SystemAudit {
    Write-Log "Gathering System Audit..."
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $serial = (Get-CimInstance Win32_Bios).SerialNumber
        $gpu = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
        $auditData = "Model: $($cs.Model) | Serial: $serial | GPU: $gpu | RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2))GB"
        Write-Log -Message $auditData -Status "SUCCESS" -IsData
    } catch { Write-Log "System Audit" "FAILED" }
}

function Check-RebootStatus {
    $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $statusText = if ($reboot) { "REBOOT REQUIRED" } else { "NO REBOOT NEEDED" }
    Write-Log -Message "Reboot Status: $statusText" -Status "SUCCESS" -IsData
}

function Test-NetworkHealth {
    Write-Log "Testing Network Connectivity..."
    try {
        $pingIP = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet
        $pingURL = Test-Connection -ComputerName "www.google.com" -Count 2 -Quiet
        $res = "Ping 8.8.8.8: $(if($pingIP){'OK'}else{'FAIL'}) | Ping Google: $(if($pingURL){'OK'}else{'FAIL'})"
        Write-Log -Message $res -Status "SUCCESS" -IsData
    } catch { Write-Log "Network Test" "FAILED" }
}

function Analyze-EventLogs {
    Write-Log "Analyzing Event Logs (Last 24 Hours)..."
    try {
        $last24 = (Get-Date).AddDays(-1)
        $sys = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=$last24} -ErrorAction SilentlyContinue).Count
        $app = (Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=$last24} -ErrorAction SilentlyContinue).Count
        Write-Log -Message "System Errors: $sys | App Errors: $app" -Status "SUCCESS" -IsData
    } catch { Write-Log "Event Log Analysis" "FAILED" }
}

function Analyze-Bsod {
    Write-Log "Searching for recent BSOD codes..."
    try {
        $crash = Get-WinEvent -FilterHashtable @{LogName='System'; ID=1001} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($crash -and ($crash.Message -match "0x[0-9a-fA-F]+")) {
            $code = $matches[0]
            Write-Log -Message "Last Crash Code: $code" -Status "SUCCESS" -IsData
        } else { Write-Log "No recent BSOD found." "SUCCESS" }
    } catch { Write-Log "BSOD Analysis" "FAILED" }
}

function Check-DiskHealth {
    Write-Log "Checking S.M.A.R.T. Status..."
    try {
        $diskHealth = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
        if ($null -eq $diskHealth) {
            Write-Log "No S.M.A.R.T. data available (Likely a Virtual Machine)." "INFO"
        } else {
            foreach ($disk in $diskHealth) {
                $status = if ($disk.PredictFailure) { "FAILING" } else { "HEALTHY" }
                Write-Log -Message "Disk Status: $status" -Status (if($disk.PredictFailure){"FAILED"}else{"SUCCESS"}) -IsData
            }
        }
    } catch { Write-Log "Disk Health Check" "FAILED" }
}
# --- NEW FUNCTIONS TO ADD TO YOUR TOOLBOX SECTION ---

function Get-UserUptime {
    Write-Log "Checking User Sessions and Uptime..."
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $uptime = (Get-Date) - $os.LastBootUpTime
        $uptimeString = "$($uptime.Days) Days, $($uptime.Hours) Hours, $($uptime.Minutes) Minutes"
        
        $users = Get-CimInstance Win32_LogonSession | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount
        $userList = ($users.Name -unique) -join ", "
        
        $report = "System Uptime: $uptimeString | Logged Users: $userList"
        Write-Log -Message $report -Status "SUCCESS" -IsData
    } catch { Write-Log "User/Uptime Check" "FAILED" }
}

function Find-LargeFiles {
    Write-Log "Scanning for Large Files (>500MB) in User Profile..."
    try {
        $userProfile = $env:USERPROFILE
        $bigFiles = Get-ChildItem -Path $userProfile -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Length -gt 500MB } | 
                    Sort-Object Length -Descending | 
                    Select-Object -First 5
        
        if ($bigFiles) {
            foreach ($file in $bigFiles) {
                $sizeGB = [math]::Round($file.Length / 1GB, 2)
                Write-Log -Message "Found: $($file.Name) ($sizeGB GB) in $($file.DirectoryName)" -Status "INFO" -IsData
            }
        } else {
            Write-Log "No files larger than 500MB found in user profile." "SUCCESS"
        }
    } catch { Write-Log "Large File Scan" "FAILED" }
}

# --- UPDATE YOUR MENU ---
# 10) User & Uptime        11) Large File Scan

# --- UPDATE YOUR SWITCH ---
# '10' { Get-UserUptime }
# '11' { Find-LargeFiles }

# --- 4. THE MENU SYSTEM ---
function Show-Menu {
    Write-Host "`n==============================================" -ForegroundColor White
    Write-Host "   REMOTE SUPPORT TOOLKIT (MODULAR V2)" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor White
    Write-Host "1) Flush DNS              5)  Reboot Status"
    Write-Host "2) SFC Repair             6)  Ping Test"
    Write-Host "3) System Cleanup         7)  Event Errors"
    Write-Host "4) System Audit           8)  BSOD Analysis"
    Write-Host "9) Disk Health (SMART)    10) Check Large Files"
    Write-Host "Q) Quit and Open Summary"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"
    switch ($choice) {
        '1' { Invoke-DnsFlush }
        '2' { Invoke-SfcRepair }
        '3' { Invoke-SystemCleanup }
        '4' { Get-SystemAudit }
        '5' { Check-RebootStatus }
        '6' { Test-NetworkHealth }
        '7' { Analyze-EventLogs }
        '8' { Analyze-Bsod }
        '9' { Check-DiskHealth }
        '10' { Find-LargeFiles }
    }
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
