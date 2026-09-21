# Start the PROJECT-LOCAL Ollama daemon on Windows (localhost, in-project model store).
# Run scripts\ollama\setup.ps1 first.
$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$Vendor      = Join-Path $ProjectRoot 'vendor\ollama'
$Models      = Join-Path $Vendor 'models'

if (-not $env:OLLAMA_HOST) { $env:OLLAMA_HOST = '127.0.0.1:11434' }
$env:OLLAMA_MODELS = $Models

$exe = Get-ChildItem -Path (Join-Path $Vendor 'bin') -Recurse -Filter 'ollama.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $exe) { throw "Bundled Ollama not found under $Vendor. Run scripts\ollama\setup.ps1 first." }

Write-Host "Serving bundled Ollama on http://$($env:OLLAMA_HOST)"
Write-Host "  binary : $($exe.FullName)"
Write-Host "  models : $Models"
& $exe.FullName serve
