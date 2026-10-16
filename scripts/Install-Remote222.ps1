# Run in a normal Windows PowerShell terminal, not as Administrator.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Common.ps1"
if ($env:OS -ne 'Windows_NT') { throw 'This installer is for Windows.' }
if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
    throw 'Install App Installer from Microsoft Store to obtain winget, or install Python 3.12+ and cloudflared manually from their official sites.'
}
try { $python = Find-RemotePython } catch {
    & winget.exe install --id Python.Python.3.12 --exact --source winget --scope user --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { throw 'Python installation failed.' }
    $python = Find-RemotePython
}
try { $tunnel = Find-RemoteTunnel } catch {
    & winget.exe install --id Cloudflare.cloudflared --exact --source winget --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { throw 'cloudflared installation failed.' }
}
Write-Host 'Installed. Open a new PowerShell terminal, then run scripts\Start-Remote222.ps1.'
Write-Host 'No service, scheduled task or automatic startup was installed.'
