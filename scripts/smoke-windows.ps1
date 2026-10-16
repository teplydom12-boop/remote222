# Local Windows validation: opens Notepad and types a message into the active window.
# Run manually in a normal interactive desktop. The Notepad window remains open.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Common.ps1"
$python = Find-RemotePython
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    & $python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Protocol tests failed.' }
    & $python "$PSScriptRoot\windows_smoke.py"
    if ($LASTEXITCODE -ne 0) { throw 'Desktop smoke check failed.' }
} finally { Pop-Location }
