<# 
.SYNOPSIS
Complete Forensic Toolkit - All Expanded Modules Included.
Features: Stability, Storage, Networking, Security, and Repairs.
#>

# --- 1. GLOBAL SETUP & LOGGING ---
$LogFolder = "C:\SupportLogs"
if (!(Test-Path $LogFolder)) { New-Item $LogFolder -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogFolder "Master_Support_Final.txt"

"--- MASTER FORENSIC SESSION: $env:COMPUTERNAME ---" | Out-File $LogFile -Encoding UTF8
"Started: $(Get-Date)`n" | Out-File $LogFile -Append -Encoding UTF8

function Write-Log {
    param([string]$Message, [string]$Status = "INFO", [switch]$IsData)
    $Time = Get-Date -Format "HH:mm:ss"
    $Line = "[$Time] [$Status] - $Message"
    $Line | Out-File $LogFile -Append -Encoding UTF8
    if ($IsData) {
        Write-Host "`n>>> DATA REPORT:" -ForegroundColor Yellow; Write-Host $Message -ForegroundColor White
    } else {
        $Col = switch($Status) { "SUCCESS" {"Green"} "FAILED" {"Red"} "WARN" {"Yellow"} Default {"Cyan"} }
        Write-Host $Line -ForegroundColor $Col
    }
}

# --- 2. EXPANDED FORENSIC FUNCTIONS ---

function Analyze-SystemStability-Forensic {
    Write-Log "!!! EXECUTING FULL FORENSIC STABILITY AUDIT !!!" -Status "INFO"
    $RecentUpdates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
    $LastUpdateDate = if ($RecentUpdates) { $RecentUpdates[0].InstalledOn } else { [DateTime]::MinValue }
    $startTime = (Get-Date).AddDays(-1)
    $eventMap = @{ 1001="FATAL_BSOD"; 161="LIVE_KERNEL_RESET"; 41="DIRTY_SHUTDOWN"; 7="DISK_BAD_BLOCK"; 55="NTFS_CORRUPTION"; 153="DISK_RETRY_OPER" }

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=$eventMap.Keys; StartTime=$startTime} -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending
        if ($events) {
            foreach ($event in $events) {
                $type = $eventMap[$event.Id]
                $errorCode = "0x0"; $culprit = "Unknown"
                if ($event.Message -match "(0x[0-9a-fA-F]+)") { $errorCode = $matches[1].ToUpper() }
                if ($event.Message -match "([a-zA-Z0-9._-]+\.(sys|dll|exe))") { $culprit = $matches[1] }
                $isPostUpdate = if ($event.TimeCreated -gt $LastUpdateDate) { "YES" } else { "NO" }

                Write-Log "------------------------------------------------------------"
                Write-Log "EVENT: [$type] @ $($event.TimeCreated) | Post-Update: $isPostUpdate"
                if ($culprit -ne "Unknown") {
                    $file = Get-ChildItem -Path "$env:SystemRoot\System32" -Filter $culprit -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($file) {
                        $v = $file.VersionInfo
                        $ageDays = ((Get-Date) - $file.LastWriteTime).Days
                        Write-Log "CULPRIT: $culprit | Age: $ageDays days | Provider: $($v.CompanyName)"
                    }
                }
                Write-Log "RESEARCH: https://learn.microsoft.com/en-us/search/?terms=$($errorCode -replace '0x0+', '0x')"
            }
        }
    } catch { Write-Log "Forensic Loop Failed" "FAILED" }
}

function Check-Disk-Forensic {
    Write-Log "Analyzing Physical Storage Reliability..." -Status "INFO"
    
    try {
        Get-PhysicalDisk | ForEach-Object {
            $rel = Get-StorageReliabilityCounter -PhysicalDisk $_
            $data = "Disk: $($_.FriendlyName) | Health: $($_.HealthStatus) | Wear: $($rel.Wear)% | Temp: $($rel.Temperature)C | Total Read Errors: $($rel.ReadErrorsTotal)"
            Write-Log $data -IsData
        }
        $diskEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(129, 153, 154); StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
        if ($diskEvents) { Write-Log "!!! WARNING: Found $($diskEvents.Count) Controller Timeouts in 24h !!!" "FAILED" }
    } catch { Write-Log "Disk Audit Failed" "FAILED" }
}

function Test-Network-Forensic {
    Write-Log "Analyzing Network Path & Interface Stability..." -Status "INFO"
    try {
        $nic = Get-NetAdapterStatistics | Where-Object { $_.ReceivedBytes -gt 0 }
        $dnsStart = Get-Date; [System.Net.Dns]::GetHostAddresses("www.google.com") | Out-Null
        $dnsTime = ((Get-Date) - $dnsStart).TotalMilliseconds
        $nicResets = Get-WinEvent -FilterHashtable @{LogName='System'; Id=10400; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
        
        Write-Log "NIC: $($nic.Name) | DNS Time: $($dnsTime)ms | PacketErrors: $($nic.ReceivedPacketErrors)" -IsData
        if ($nicResets) { Write-Log "NIC Resets in 24h: $($nicResets.Count)" "WARN" }
    } catch { Write-Log "Network Forensic Failed" "FAILED" }
}

function Invoke-SystemRepair {
    Write-Log "Executing System Maintenance (SFC & Temp Cleanup)..." -Status "IN_PROGRESS"
    sfc /scannow | Out-Null
    $paths = "$env:TEMP\*", "C:\Windows\Temp\*"
    foreach ($p in $paths) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Log "Maintenance Complete." "SUCCESS"
}

function Update-Nvidia-Manual {
    $SearchUrl = "https://www.nvidia.com/en-us/geforce/drivers/results/260405/"
    Write-Log "Launching NVIDIA Driver Intelligence Page..." -Status "SUCCESS"
    Start-Process $SearchUrl
}

function Fetch-DDU {
    $dest = Join-Path ([Environment]::GetFolderPath("Desktop")) "DDU_Setup.exe"
    Write-Log "Downloading DDU to Desktop..." -Status "IN_PROGRESS"
    try {
        Invoke-WebRequest -Uri "https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.9.1.exe" -OutFile $dest -UserAgent "Mozilla/5.0"
        Write-Log "DDU Downloaded Successfully." "SUCCESS"
    } catch { Write-Log "DDU Download Failed." "FAILED" }
}

# --- 3. MENU SYSTEM ---
function Show-Menu {
    Clear-Host
    Write-Host "==================================================" -ForegroundColor White
    Write-Host "      STEELY'S TROUBLE SHOOTING TOOLKIT : 26.01.001" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor White
    Write-Host "1) Stability Audit (BSOD & Updates)"
    Write-Host "2) Disk Forensic (Wear & Errors)"
    Write-Host "3) Network Path Analysis (NIC/DNS)"
    Write-Host "4) System Maintenance (SFC & Cleanup)"
    Write-Host "5) Driver Tools (NVIDIA & DDU)"
    Write-Host "6) Security & AV Posture"
    Write-Host "7) Failed Update Scan"
    Write-Host "--------------------------------------------------"
    Write-Host "Q) Quit and Open Summary Log"
}

do {
    Show-Menu
    $choice = Read-Host "`nEnter Choice"
    switch ($choice) {
        '1' { Analyze-SystemStability-Forensic }
        '2' { Check-Disk-Forensic }
        '3' { Test-Network-Forensic }
        '4' { Invoke-SystemRepair }
        '5' { 
            Write-Host "1) NVIDIA Page | 2) Download DDU"
            $d = Read-Host "Choice"
            if($d -eq '1'){Update-Nvidia-Manual}elseif($d -eq '2'){Fetch-DDU}
        }
        '6' { 
            $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
            Write-Log "AV: $($av.displayName) | State: $($av.productState)" -IsData
        }
        '7' {
            $failed = Get-WinEvent -FilterHashtable @{LogName='Setup'; Level=2; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
            if($failed){$failed | ForEach-Object {Write-Log "Failed: $($_.Message.Substring(0,60))" "WARN"}} else {Write-Log "No failed updates." "SUCCESS"}
        }
    }
    if ($choice -ne 'q') { Read-Host "`nPress Enter to return to menu..." }
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
