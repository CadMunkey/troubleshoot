<# 
.SYNOPSIS
Complete Remote Support Toolkit - All Functions Included
Features: Logging, Audit, Repairs, Networking, Event Analysis, and Disk Health.
#>

# --- 1. GLOBAL SETUP & ENCODING ---
$LogFolder = "C:\SupportLogs"
if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogFolder "Support_Final_Summary.txt"

# Ensure clean UTF8 encoding for the log file
"--- IT SUPPORT SESSION: $env:COMPUTERNAME ---" | Out-File -FilePath $LogFile -Encoding UTF8
"Started: $(Get-Date)`n" | Out-File -FilePath $LogFile -Append -Encoding UTF8

function Write-Log {
    param([string]$Message, [string]$Status = "INFO", [switch]$IsData)
    $Time = Get-Date -Format "HH:mm:ss"
    $Line = "[$Time] [$Status] - $Message"
    $Line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    
    if ($IsData) {
        Write-Host "`n>>> DATA REPORT:" -ForegroundColor Yellow
        Write-Host $Message -ForegroundColor White
    } else {
        $Col = if($Status -eq "SUCCESS"){"Green"}elseif($Status -eq "FAILED"){"Red"}else{"Cyan"}
        Write-Host $Line -ForegroundColor $Col
    }
}

# --- 2. THE TOOLSET ---

function Invoke-DnsFlush {
    Write-Log "Flushing DNS..."
    try { ipconfig /flushdns | Out-Null; Write-Log "DNS Flush" "SUCCESS" } catch { Write-Log "DNS Flush" "FAILED" }
}

function Invoke-SfcRepair {
    Write-Log "Starting SFC (Silent)..."
    try { sfc /scannow | Out-Null; Write-Log "SFC Repair" "SUCCESS" } catch { Write-Log "SFC Repair" "FAILED" }
}

function Invoke-Cleanup {
    Write-Log "Cleaning Temp Files..."
    try {
        $paths = "$env:TEMP\*", "C:\Windows\Temp\*"
        foreach ($p in $paths) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
        Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "System Cleanup" "SUCCESS"
    } catch { Write-Log "System Cleanup" "FAILED" }
}

function Get-SystemAudit {
    Write-Log "Gathering System Audit..."
    try {
        $comp = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_Bios
        $gpu = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
        $data = "Model: $($comp.Model) | Serial: $($bios.SerialNumber) | RAM: $([math]::Round($comp.TotalPhysicalMemory / 1GB))GB | GPU: $gpu"
        Write-Log -Message $data -Status "SUCCESS" -IsData
    } catch { Write-Log "Audit" "FAILED" }
}

function Check-RebootStatus {
    $r = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $msg = if($r){"REBOOT REQUIRED"}else{"NO REBOOT NEEDED"}
    Write-Log -Message "Reboot Status: $msg" -Status "SUCCESS" -IsData
}

function Test-Network {
    Write-Log "Testing Pings..."
    try {
        $p1 = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet
        $p2 = Test-Connection -ComputerName "www.google.com" -Count 2 -Quiet
        $res = "IP Ping: $(if($p1){'OK'}else{'FAIL'}) | DNS Ping: $(if($p2){'OK'}else{'FAIL'})"
        Write-Log -Message $res -Status "SUCCESS" -IsData
    } catch { Write-Log "Network Test" "FAILED" }
}

function Analyze-Events {
    Write-Log "Checking Errors (Last 24h)..."
    try {
        $time = (Get-Date).AddDays(-1)
        $sys = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=$time} -ErrorAction SilentlyContinue).Count
        $app = (Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=$time} -ErrorAction SilentlyContinue).Count
        Write-Log -Message "System Errors: $sys | App Errors: $app" -Status "SUCCESS" -IsData
    } catch { Write-Log "Event Analysis" "FAILED" }
}

function Analyze-Bsod {
    Write-Log "Performing broad-spectrum BSOD analysis with Driver Lookup..."
    
    $StopCodeLookup = @{
        "0xA"   = "IRQL_NOT_LESS_OR_EQUAL (Driver/Memory conflict)"
        "0x1E"  = "KMODE_EXCEPTION_NOT_HANDLED (Faulty driver/service)"
        "0x3B"  = "SYSTEM_SERVICE_EXCEPTION (Graphics/System call error)"
        "0x4E"  = "PFN_LIST_CORRUPT (Bad RAM/Memory corruption)"
        "0x50"  = "PAGE_FAULT_IN_NONPAGED_AREA (Invalid memory reference)"
        "0x139" = "KERNEL_SECURITY_CHECK_FAILURE (Data corruption)"
        "0xD1"  = "DRIVER_IRQL_NOT_LESS_OR_EQUAL (Driver memory error)"
        "0x7E"  = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (Driver error)"
        "0x9F"  = "DRIVER_POWER_STATE_FAILURE (Power/Sleep issue)"
        "0x133" = "DPC_WATCHDOG_VIOLATION (System hang/SSD issue)"
        "0x124" = "WHEA_UNCORRECTABLE_ERROR (Hardware Failure)"
        "0x7B"  = "INACCESSIBLE_BOOT_DEVICE (Storage/Boot error)"
        "0xEF"  = "CRITICAL_PROCESS_DIED (System process failure)"
        "0x116" = "VIDEO_TDR_FAILURE (GPU Driver timeout)"
        "0x24"  = "NTFS_FILE_SYSTEM (Disk corruption)"
    }

    try {
        $startTime = (Get-Date).AddDays(-1)
        $crashes = Get-WinEvent -FilterHashtable @{
            LogName = 'System'; Id = 1001; StartTime = $startTime
        } -ErrorAction SilentlyContinue

        if ($crashes) {
            foreach ($crash in $crashes) {
                # --- 1. Identify Error Code ---
                $errorCode = "Unknown"
                if ($crash.Message -match "(0x[0-9a-fA-F]+)") {
                    $rawHex = $matches[1]
                    $errorCode = "0x" + ([Convert]::ToString([Convert]::ToInt64($rawHex, 16), 16)).ToUpper()
                }

                $shortHex = $errorCode -replace "0x0+", "0x"
                $friendlyName = $StopCodeLookup[$shortHex] ?? "Unknown BugCheck"

                # --- 2. Identify Potential Driver/Module ---
                $culprit = "Unknown"
                if ($crash.Message -match "Failure bucket ([^, ]+)") {
                    # Often looks like 'LKD_0x133_DPC_atikmdag!unknown_function'
                    # We strip it down to the likely filename
                    $culprit = ($matches[1] -split "_")[-1].Split('!')[0]
                }

                # --- 3. Deep Dive: Find the driver on disk ---
                $driverInfo = "No local file info found."
                if ($culprit -match "\.sys$|\.exe$|\.dll$") {
                    $file = Get-ChildItem -Path "C:\Windows\System32" -Filter $culprit -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($file) {
                        $ver = $file.VersionInfo
                        $driverInfo = "Source: $($ver.CompanyName) | Desc: $($ver.FileDescription) | Ver: $($ver.FileVersion)"
                    }
                }

                # --- 4. Final Log Output ---
                $logMsg = "BSOD [$errorCode] $friendlyName | Likely Module: $culprit | $driverInfo"
                Write-Log -Message $logMsg -Status "SUCCESS" -IsData
            }
        } else {
            Write-Log "No BSOD events detected in the last 24 hours." "SUCCESS"
        }
    } catch {
        Write-Log "Error during BSOD Analysis: $($_.Exception.Message)" "FAILED"
    }
}

function Check-Disk {
    Write-Log "Checking SMART Status..."
    try {
        $d = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
        if ($null -eq $d) { Write-Log "No SMART data available." }
        else {
            $stat = if($d.PredictFailure){"FAILING"}else{"HEALTHY"}
            Write-Log "Disk Health: $stat" (if($d.PredictFailure){"FAILED"}else{"SUCCESS"}) -IsData
        }
    } catch { Write-Log "Disk Check" "FAILED" }
}

function Get-UserUptime {
    Write-Log "Checking Uptime & Users..."
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $up = (Get-Date) - $os.LastBootUpTime
        
        # Fixed logic for wider compatibility
        $allUsers = Get-CimInstance Win32_LogonSession | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount
        $userNames = $allUsers.Name | Select-Object -Unique
        $userString = $userNames -join ", "
        
        $data = "Uptime: $($up.Days)d $($up.Hours)h | Users: $userString"
        Write-Log -Message $data -Status "SUCCESS" -IsData
    } catch { Write-Log "Uptime Check" "FAILED" }
}

function Find-BigFiles {
    Write-Log "Scanning User Profile for files > 500MB..."
    try {
        $files = Get-ChildItem -Path $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue | 
                 Where-Object { $_.Length -gt 500MB } | Sort-Object Length -Descending | Select-Object -First 3
        if($files){
            foreach($f in $files){ Write-Log "Found: $($f.Name) ($([math]::Round($f.Length/1GB,2))GB)" "INFO" -IsData }
        } else { Write-Log "No large files found." "SUCCESS" }
    } catch { Write-Log "File Scan" "FAILED" }
}

function Update-NvidiaDriver {
    Write-Log "Starting NVIDIA Silent Update..."
    try {
        $SearchUrl = "https://www.nvidia.com/Download/processFind.aspx?psid=101&pfid=845&osid=57&lid=1&whql=1&dtcid=1"
        $Page = Invoke-WebRequest -Uri $SearchUrl -UseBasicParsing -ErrorAction Stop

        if ($Page.Content -match 'url=(?<url>https://[^\s&]+)') {
            $DownloadUrl = [uri]::UnescapeDataString($Matches['url'])
            $TempPath = Join-Path $env:TEMP "NvidiaDriver.exe"

            Write-Log "Downloading: $DownloadUrl" -Status "IN_PROGRESS"
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath -ErrorAction Stop

            # -s: Silent | -n: No Reboot
            Write-Log "Executing Silent Install. Expect connection flicker." -Status "IN_PROGRESS"
            $Process = Start-Process -FilePath $TempPath -ArgumentList "-s", "-n" -Wait -PassThru
            
            Write-Log "NVIDIA Result: $($Process.ExitCode)" -Status "SUCCESS" -IsData
            Remove-Item $TempPath -Force
        }
    } catch { Write-Log "NVIDIA Update" "FAILED" }
}
function Fetch-DDU {
    # Define the folder path on the Desktop
    $folderName = "DDU_Download"
    $desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop", $folderName)

    # Create the folder if it doesn't exist
    if (-not (Test-Path $desktopPath)) {
        New-Item -Path $desktopPath -ItemType Directory | Out-Null
        Write-Host "Created folder at $desktopPath" -ForegroundColor Cyan
    }

    # Target URL for the DDU self-extracting executable
    $url = "https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.9.1.exe"
    $destination = Join-Path $desktopPath "DDU_Setup.exe"

    Write-Host "Downloading DDU... please wait." -ForegroundColor Yellow

    try {
        # Download the file
        Invoke-WebRequest -Uri $url -OutFile $destination
        Write-Host "Success! DDU saved to: $destination" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download DDU. Check your internet connection or the URL."
    }
}

# --- 3. MENU SYSTEM ---

function Show-Menu {
    Write-Host "`n==================================================" -ForegroundColor White
    Write-Host "      REMOTE SUPPORT TOOLKIT - FULL BUILD" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor White
    Write-Host "0) Nothing                10) User & Uptime             "
    Write-Host "1) Flush DNS              11) Large File Scan"
    Write-Host "2) SFC Repair             12) Get Nvidia Drivers"
    Write-Host "3) System Cleanup         13) Get DDU"
    Write-Host "4) System Audit           14) ---"
    Write-Host "5) Reboot Status          15) ---"
    Write-Host "6) Test Connectivity      16) ---"
    Write-Host "7) Event Errors (24h)     17) ---"
    Write-Host "8) BSOD Analysis          18) ---"
    Write-Host "9) Disk Health (SMART)    19) ---"
    Write-Host "--------------------------------------------------"
    Write-Host "Q) Quit and Open Summary Log"
    Write-Host "=================================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"
    switch ($choice) {
        '1' { Invoke-DnsFlush }
        '2' { Invoke-SfcRepair }
        '3' { Invoke-Cleanup }
        '4' { Get-SystemAudit }
        '5' { Check-RebootStatus }
        '6' { Test-Network }
        '7' { Analyze-Events }
        '8' { Analyze-Bsod }
        '9' { Check-Disk }
        '10' { Get-UserUptime }
        '11' { Find-BigFiles }
        '12' { Update-NvidiaDriver }
        '13' { Fetch-DDU }
    }
} while ($choice -ne 'q')

if (Test-Path $LogFile) { notepad.exe $LogFile }
