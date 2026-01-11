# Master IT Support Toolkit - REMOTE SAFE VERSION
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Show-Menu {
    Clear-Host
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "   REMOTE SUPPORT TOOLKIT - SESSION: $(Get-Date)" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "1) Network: Flush DNS (Safe for Remote)"
    Write-Host "2) Repair: Run SFC Scan (System File Check)"
    Write-Host "3) Cleanup: Clear Temp Files & Recycle Bin"
    Write-Host "4) Full System Audit (Hardware, GPU, IP, RAM)"
    Write-Host "5) Speed Test: Check Local Link Speed"
    Write-Host "6) Health: Check Pending Reboot & Battery"
    Write-Host "7) Display: Check GPU Driver Status"
    Write-Host "Q) Quit"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        '1' {
            Write-Host "Flushing DNS Cache..." -ForegroundColor Yellow
            ipconfig /flushdns
            Write-Host "DNS Flush complete. (Connection remains active)" -ForegroundColor Green
            Pause
        }
        '2' {
            Write-Host "Running SFC Scan. This will not affect your connection..." -ForegroundColor Yellow
            sfc /scannow
            Pause
        }
        '3' {
            Write-Host "Cleaning Temp folders..." -ForegroundColor Yellow
            $tempPaths = "$env:TEMP\*", "C:\Windows\Temp\*"
            foreach ($path in $tempPaths) { 
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue 
            }
            Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Cleanup finished." -ForegroundColor Green
            Pause
        }
        '4' {
            Write-Host "--- System Audit ---" -ForegroundColor Cyan
            $os = Get-CimInstance Win32_OperatingSystem
            $cs = Get-CimInstance Win32_ComputerSystem
            $serial = (Get-CimInstance Win32_Bios).SerialNumber
            
            Write-Host "PC Name:    $($env:COMPUTERNAME)"
            Write-Host "Model:      $($cs.Model)"
            Write-Host "Serial:     $serial"
            Write-Host "RAM:        $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB"
            Write-Host "OS:         $($os.Caption)"
            Write-Host "--------------------" -ForegroundColor Cyan
            Pause
        }
        '5' {
            Write-Host "--- Local Network Speeds ---" -ForegroundColor Cyan
            Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed | Format-Table -AutoSize
            Pause
        }
        '6' {
            Write-Host "--- Status Checks ---" -ForegroundColor Cyan
            $reboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            if ($reboot) { Write-Host "REBOOT REQUIRED: Yes" -ForegroundColor Red } else { Write-Host "REBOOT REQUIRED: No" -ForegroundColor Green }
            
            Write-Host "`n--- Battery Health ---" -ForegroundColor Cyan
            Get-CimInstance -ClassName Win32_Battery | Select-Object EstimatedChargeRemaining, Status | Format-Table
            Pause
        }
        '7' {
            Write-Host "--- GPU Driver Info ---" -ForegroundColor Cyan
            Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, Status | Format-Table -AutoSize
            Pause
        }
    }
} while ($choice -ne 'q')
