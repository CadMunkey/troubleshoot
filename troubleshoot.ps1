<# 
.SYNOPSIS
Unrestricted System Forensic Toolkit 
Combines Hardware, Storage, Network, and Stability Analysis.
#>

# --- 1. GLOBAL SETUP ---
$LogFolder = "C:\SupportLogs"
if (!(Test-Path $LogFolder)) { New-Item $LogFolder -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogFolder "System_Forensic_Final.txt"

"--- OVERLORD FORENSIC SESSION: $env:COMPUTERNAME ---" | Out-File $LogFile -Encoding UTF8
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

# --- 2. THE FORENSIC MODULES ---

function Analyze-SystemStability-Forensic {
    Write-Log "Initializing Full Stability & Crash Correlation..." -Status "INFO"
    $RecentUpdates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3
    $LastUpdate = if ($RecentUpdates) { $RecentUpdates[0].InstalledOn } else { [DateTime]::MinValue }
    $eventMap = @{ 1001="BSOD"; 161="LIVE_KERNEL"; 41="DIRTY_POWER"; 7="BAD_BLOCK"; 153="DISK_RETRY" }

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=$eventMap.Keys; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending
        foreach ($event in $events) {
            $errorCode = "0x0"; $culprit = "Unknown"
            if ($event.Message -match "(0x[0-9a-fA-F]+)") { $errorCode = $matches[1].ToUpper() }
            if ($event.Message -match "([a-zA-Z0-9._-]+\.(sys|dll|exe))") { $culprit = $matches[1] }
            
            Write-Log "[$($eventMap[$event.Id])] @ $($event.TimeCreated) | After Update: $($event.TimeCreated -gt $LastUpdate) | Code: $errorCode | File: $culprit"
            if ($culprit -ne "Unknown") {
                $f = Get-ChildItem "$env:SystemRoot\System32" -Filter $culprit -Recurse -ErrorAction SilentlyContinue | Select -First 1
                if ($f) { Write-Log "   Module Detail: $(($f.VersionInfo).CompanyName) | Age: $(((Get-Date)-$f.LastWriteTime).Days) days" -Status "SUCCESS" }
            }
        }
    } catch { Write-Log "Stability Forensic Failed" "FAILED" }
}

function Check-Disk-Forensic {
    Write-Log "Analyzing Storage Reliability Counters..." -Status "INFO"
    
    try {
        Get-PhysicalDisk | ForEach-Object {
            $rel = Get-StorageReliabilityCounter -PhysicalDisk $_
            $msg = "Disk: $($_.FriendlyName) | Health: $($_.HealthStatus) | Wear: $($rel.Wear)% | Temp: $($rel.Temperature)C | Errors: $($rel.ReadErrorsTotal)"
            Write-Log $msg -IsData
            if ($rel.Wear -gt 90 -or $rel.Temperature -gt 70) { Write-Log "CRITICAL: Disk threshold reached!" "FAILED" }
        }
    } catch { Write-Log "Disk Audit Failed" "FAILED" }
}

function Test-Network-Forensic {
    Write-Log "Analyzing Network Path & NIC Stability..." -Status "INFO"
    try {
        $nic = Get-NetAdapterStatistics | Where-Object { $_.ReceivedBytes -gt 0 }
        $dnsStart = Get-Date; [System.Net.Dns]::GetHostAddresses("www.google.com") | Out-Null
        $dnsTime = ((Get-Date) - $dnsStart).TotalMilliseconds
        
        Write-Log "NIC: $($nic.Name) | Errors(Rx): $($nic.ReceivedPacketErrors) | DNS: $($dnsTime)ms" -IsData
        $resets = Get-WinEvent -FilterHashtable @{LogName='System'; Id=10400; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
        if ($resets) { Write-Log "Detected $($resets.Count) NIC resets in 24h!" "WARN" }
    } catch { Write-Log "Network Forensic Failed" "FAILED" }
}

function Get-SecurityPosture {
    Write-Log "Auditing Security & Antivirus State..." -Status "INFO"
    
    try {
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
        $fw = Get-NetFirewallProfile | Select-Object Name, Enabled
        $data = "AV: $($av.displayName) | State: $($av.productState) | FW: $($fw[0].Enabled)"
        Write-Log $data -IsData
    } catch { Write-Log "Security Audit Failed" "FAILED" }
}

function Analyze-UpdateConflicts {
    Write-Log "Scanning for Failed Windows Updates..." -Status "INFO"
    try {
        $failed = Get-WinEvent -FilterHashtable @{LogName='Setup'; Level=2; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
        if ($failed) {
            foreach($f in $failed) { Write-Log "Failed Update: $($f.TimeCreated) - $($f.Message.Substring(0,50))..." "WARN" }
        } else { Write-Log "No failed updates in last 7 days." "SUCCESS" }
    } catch { Write-Log "Update Audit Failed" "FAILED" }
}

# --- 3. MENU SYSTEM ---
function Show-Menu {
    Clear-Host
    Write-Host "==================================================" -ForegroundColor White
    Write-Host "      SYSTEM FORENSIC OVERLORD TOOLKIT" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor White
    Write-Host "1) FULL STABILITY (BSOD/Update Correlation)"
    Write-Host "2) DISK FORENSIC (SMART/Wear/Temp)"
    Write-Host "3) NETWORK PATH (Errors/DNS/NIC Resets)"
    Write-Host "4) SECURITY POSTURE (AV/Firewall State)"
    Write-Host "5) UPDATE CONFLICTS (Failed Patches)"
    Write-Host "6) SYSTEM CLEANUP & SFC REPAIR"
    Write-Host "7) DRIVER TOOLS (DDU/Nvidia)"
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
        '4' { Get-SecurityPosture }
        '5' { Analyze-UpdateConflicts }
        '6' { sfc /scannow; Write-Log "SFC Complete" "SUCCESS" }
        '7' { Write-Log "Please use specific sub-menu for drivers." }
    }
    if ($choice -ne 'q') { Read-Host "`nPress Enter to return to menu..." }
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
