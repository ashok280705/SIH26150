Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Multi-Vendor DVR/NVR Forensic Platform - Workstation Launcher" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Set-Location -Path $PSScriptRoot
Start-Process -FilePath ".\forensic-api.exe" -NoNewWindow
Start-Sleep -Seconds 2
Start-Process "http://localhost:3000"
Write-Host "Platform is active on http://localhost:3000" -ForegroundColor Green
