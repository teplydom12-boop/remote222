$ErrorActionPreference = 'Stop'
$path = Join-Path $env:LOCALAPPDATA 'Remote222\access.token'
if (-not (Test-Path $path)) { throw 'Start the agent once to generate an access key.' }
Set-Clipboard -Value (Get-Content $path -Raw).Trim()
Write-Host 'Access key copied. Paste it into the REMOTE222_TOKEN secret in environment settings, not into chat.'
Write-Host 'After saving the secret, clear the clipboard with: Set-Clipboard -Value ""'
