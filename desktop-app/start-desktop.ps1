[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$appRoot = Split-Path -Parent $PSCommandPath
$python = Join-Path $appRoot '.venv\Scripts\python.exe'
$app = Join-Path $appRoot 'app.py'
$logPath = Join-Path $env:LOCALAPPDATA 'SEDWTIAR\logs\desktop.log'

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Desktop Python environment was not found: $python"
}

if (-not (Test-Path -LiteralPath $app -PathType Leaf)) {
    throw "Desktop application entry point was not found: $app"
}

& $python $app
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host "SEDWTIAR stopped with exit code $exitCode." -ForegroundColor Red
    Write-Host "Diagnostic log: $logPath" -ForegroundColor Yellow
}

exit $exitCode
