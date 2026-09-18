@echo off
title Multi-Vendor DVR/NVR Forensic Analysis Platform
echo =====================================================================
echo  Multi-Vendor DVR/NVR Forensic Platform - Workstation Launcher
echo =====================================================================
echo Starting Forensic Backend Engine on port 3000...
cd /d "%~dp0"
start "Forensic Engine API" /b "forensic-api.exe"
timeout /t 2 /nobreak >nul
echo Opening Workstation in your default browser...
start http://localhost:3000
echo.
echo Platform is active and listening on http://localhost:3000
echo Close this window to stop the background engine.
pause
