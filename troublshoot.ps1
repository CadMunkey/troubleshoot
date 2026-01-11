# Master Troubleshooting Toolkit
Clear-Host
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   IT SUPPORT TOOLKIT - SESSION: $(Get-Date)" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

function Show-Menu {
    Write-Host "1) Network: Flush DNS & Reset Stack"
    Write-Host "2) System: Run SFC Scan (Repair Files)"
    Write-Host "3) Cleanup: Clear Temp Files & Recycle Bin"
    Write-Host "4) Info: Show IP, Serial Number, & RAM"
    Write-Host "5) Update: Force Windows Update Search"
    Write-Host "Q) Quit"
    Write-Host "=============================================="
}

do {
    Show-Menu
    $input = Read-Host "Select an option"

    switch ($input) {
        '1' {
            Write-Host "Resetting Network..." -ForegroundColor Yellow
            ipconfig /flushdns; netsh winsock reset
            Write-Host "Done! Please reboot if issues persist." -ForegroundColor Green
        }
        '2' {
            Write-Host "Starting System File Check (SFC)..." -ForegroundColor Yellow
            sfc /scannow
        }
        '3' {
            Write-Host "Cleaning Temp Files..." -ForegroundColor Yellow
            Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Cleanup Complete." -ForegroundColor Green
        }
        '4' {
            $serial = (Get-CimInstance Win32_Bios).SerialNumber
            $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$.InterfaceAlias -notlike "*Loopback*"}).IPAddress[0]
            Write-Host "Serial: $serial" -ForegroundColor White
            Write-Host "IP Address: $ip" -ForegroundColor White
        }
        '5' {
            Write-Host "Checking for updates..." -ForegroundColor Yellow
            Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction SilentlyContinue
            Get-WindowsUpdate -Install -AcceptAll -AutoReboot
        }
    }
    Write-Host ""
} while ($input -ne 'q')