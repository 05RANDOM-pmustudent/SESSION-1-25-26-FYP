$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$awarelinkPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $awarelinkPython)) {
    & python -m venv (Join-Path $PSScriptRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated Python environment.' }
}
& $awarelinkPython -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Runtime package installation failed.' }
Write-Host 'Setup complete. Run .\start.ps1 and open http://127.0.0.1:8765.'
