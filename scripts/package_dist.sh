#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== 1. Building Frontend ==="
(cd apps/frontend && npm run build)

echo "=== 2. Building Release Binaries ==="
cargo build --release -p forensic-api
cargo build --release --target x86_64-pc-windows-gnu -p forensic-api

PACKAGES_DIR="$ROOT_DIR/packages"
rm -rf "$PACKAGES_DIR"
mkdir -p "$PACKAGES_DIR/windows-x64" "$PACKAGES_DIR/dmg_root"

echo "=== 3. Packaging Windows x64 Distribution ==="
WIN_DIR="$PACKAGES_DIR/ForensicWorkstation-Windows-x64"
mkdir -p "$WIN_DIR"
cp "target/x86_64-pc-windows-gnu/release/forensic-api.exe" "$WIN_DIR/"
cp -r "apps/frontend/dist" "$WIN_DIR/frontend"
cp -r "profiles" "$WIN_DIR/profiles"
cp -r "evidence_samples" "$WIN_DIR/evidence_samples"

cat <<'EOF' > "$WIN_DIR/start_forensic_workstation.bat"
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
EOF

cat <<'EOF' > "$WIN_DIR/start_forensic_workstation.ps1"
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Multi-Vendor DVR/NVR Forensic Platform - Workstation Launcher" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Set-Location -Path $PSScriptRoot
Start-Process -FilePath ".\forensic-api.exe" -NoNewWindow
Start-Sleep -Seconds 2
Start-Process "http://localhost:3000"
Write-Host "Platform is active on http://localhost:3000" -ForegroundColor Green
EOF

cat <<'EOF' > "$WIN_DIR/README.txt"
Multi-Vendor DVR/NVR Forensic Analysis Platform (SIH-2026)
==========================================================
Windows x86_64 Standalone Portable Edition

INSTRUCTIONS:
1. Double-click `start_forensic_workstation.bat` (or run `forensic-api.exe`).
2. Your web browser will automatically open to http://localhost:3000.
3. Test sample raw images are included in the `evidence_samples\` folder.

OEM Storage Support:
- Dahua (DHFS)
- Hikvision (HIKBTREE / HKSEG)
- CP Plus (UBS)
- Uniview (UBIFS)
- Honeywell (MAXPRO)
EOF

echo "Creating Windows ZIP Archive..."
(cd "$PACKAGES_DIR" && zip -r "ForensicWorkstation-Windows-x64.zip" "ForensicWorkstation-Windows-x64")

echo "=== 4. Packaging macOS Application (.app) & DMG (.dmg) ==="
APP_DIR="$PACKAGES_DIR/dmg_root/ForensicWorkstation.app"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "target/release/forensic-api" "$APP_DIR/Contents/Resources/"
cp -r "apps/frontend/dist" "$APP_DIR/Contents/Resources/frontend"
cp -r "profiles" "$APP_DIR/Contents/Resources/profiles"
cp -r "evidence_samples" "$APP_DIR/Contents/Resources/evidence_samples"

cat <<'EOF' > "$APP_DIR/Contents/MacOS/ForensicWorkstation"
#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESOURCES_DIR="$DIR/../Resources"
cd "$RESOURCES_DIR"

# Kill any previous instance running on port 3000
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

"$RESOURCES_DIR/forensic-api" &
API_PID=$!

sleep 1
open "http://localhost:3000"

wait $API_PID
EOF
chmod +x "$APP_DIR/Contents/MacOS/ForensicWorkstation"

cat <<'EOF' > "$APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ForensicWorkstation</string>
    <key>CFBundleIdentifier</key>
    <string>org.forensics.dvr-nvr-workstation</string>
    <key>CFBundleName</key>
    <string>ForensicWorkstation</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Symlink to /Applications inside dmg_root for drag-and-drop installation
ln -s /Applications "$PACKAGES_DIR/dmg_root/Applications"

echo "Creating macOS DMG Image..."
rm -f "$PACKAGES_DIR/ForensicWorkstation-macOS.dmg"
hdiutil create -volname "ForensicWorkstation" -srcfolder "$PACKAGES_DIR/dmg_root" -ov -format UDZO "$PACKAGES_DIR/ForensicWorkstation-macOS.dmg"

echo "=== Package Generation Complete! ==="
ls -lh "$PACKAGES_DIR"/*.zip "$PACKAGES_DIR"/*.dmg "$WIN_DIR/forensic-api.exe"
