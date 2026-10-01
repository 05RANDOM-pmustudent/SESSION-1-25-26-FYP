$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$awarelinkPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $awarelinkPython)) {
    throw 'Run .\setup.ps1 first to create the isolated environment.'
}
& $awarelinkPython -m awarelink @args
if ($LASTEXITCODE -ne 0) { throw 'AwareLink exited with an error.' }
