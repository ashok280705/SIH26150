# One-time bootstrap for Windows: download the Ollama runtime into the project and
# pull the quantized assistant model into the project-local model store.
#
# Usage (PowerShell):
#   scripts\ollama\setup.ps1
#   $env:ASSISTANT_MODEL='qwen2.5:3b-instruct'; scripts\ollama\setup.ps1
$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$Vendor      = Join-Path $ProjectRoot 'vendor\ollama'
$Bin         = Join-Path $Vendor 'bin'
$Dist        = Join-Path $Vendor 'dist'
$Models      = Join-Path $Vendor 'models'

$Model = if ($env:ASSISTANT_MODEL) { $env:ASSISTANT_MODEL } else { 'llama3.2:3b' }
if (-not $env:OLLAMA_HOST) { $env:OLLAMA_HOST = '127.0.0.1:11434' }
$env:OLLAMA_MODELS = $Models

New-Item -ItemType Directory -Force -Path $Bin, $Dist, $Models | Out-Null

$asset = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'ollama-windows-arm64.zip' } else { 'ollama-windows-amd64.zip' }
$exe = Join-Path $Bin 'ollama.exe'

if (-not (Test-Path $exe)) {
  $url = "https://github.com/ollama/ollama/releases/latest/download/$asset"
  $zip = Join-Path $Dist $asset
  Write-Host "==> Downloading Ollama runtime"
  Write-Host "    $url"
  Invoke-WebRequest -Uri $url -OutFile $zip
  Write-Host "==> Extracting into $Bin"
  Expand-Archive -Path $zip -DestinationPath $Bin -Force
}

if (-not (Test-Path $exe)) {
  $found = Get-ChildItem -Path $Bin -Recurse -Filter 'ollama.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($found) { $exe = $found.FullName } else { throw "ollama.exe not found after extraction under $Bin" }
}
Write-Host "==> Ollama binary: $exe"

$daemon = Start-Process -FilePath $exe -ArgumentList 'serve' -PassThru -WindowStyle Hidden
try {
  Write-Host -NoNewline '==> Starting local daemon'
  $ready = $false
  for ($i = 0; $i -lt 60; $i++) {
    try {
      Invoke-WebRequest -UseBasicParsing "http://$($env:OLLAMA_HOST)/api/tags" -TimeoutSec 2 | Out-Null
      $ready = $true; break
    } catch { Write-Host -NoNewline '.'; Start-Sleep -Milliseconds 500 }
  }
  Write-Host ''
  if (-not $ready) { throw 'Daemon did not become ready.' }

  Write-Host "==> Pulling quantized model into the project store: $Model"
  & $exe pull $Model
}
finally {
  if ($daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host "Done."
Write-Host "  Binary : $exe"
Write-Host "  Models : $Models"
Write-Host "  Model  : $Model"
Write-Host ''
Write-Host "Start the assistant runtime any time with:  scripts\ollama\serve.ps1"
