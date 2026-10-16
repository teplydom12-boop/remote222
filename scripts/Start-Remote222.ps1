param([ValidateRange(1024,65535)][int] $Port = 8765)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Common.ps1"
$root = Split-Path $PSScriptRoot -Parent
$state = Join-Path $env:LOCALAPPDATA 'Remote222'
$python = Find-RemotePython
$cloudflared = Find-RemoteTunnel
Protect-RemoteState $state

if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
    throw "Port $Port is already in use. Stop the previous agent or choose -Port."
}
Push-Location $root
$agent = $null
$tunnel = $null
try {
    & $python -m remote222.agent --state-dir $state --init-only
    if ($LASTEXITCODE -ne 0) { throw 'Agent initialization failed.' }
    # Start-Process needs explicit quotes around Windows arguments containing spaces.
    $agentArguments = "-m remote222.agent --allow-full-control --port $Port --state-dir `"$state`""
    $agent = Start-Process -FilePath $python -ArgumentList $agentArguments -WorkingDirectory $root -PassThru
    $headers = @{ Authorization = 'Bearer ' + (Get-Content (Join-Path $state 'access.token') -Raw).Trim() }
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($agent.HasExited) { throw 'Agent exited during startup.' }
        try {
            $info = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/v1/info" -Headers $headers -TimeoutSec 2
            if ($info.ok) { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw 'Agent did not become ready.' }
    $log = Join-Path $state 'tunnel.log'
    $output = Join-Path $state 'tunnel-output.log'
    $tunnel = Start-Process -FilePath $cloudflared -ArgumentList "tunnel --url http://127.0.0.1:$Port --no-autoupdate" -RedirectStandardError $log -RedirectStandardOutput $output -PassThru -NoNewWindow
    $url = $null
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        if ($tunnel.HasExited) { throw "Tunnel exited. See $log" }
        if (Test-Path $log) {
            $match = [regex]::Match((Get-Content $log -Raw), 'https://[a-z0-9-]+\.trycloudflare\.com')
            if ($match.Success) { $url = $match.Value; break }
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $url) { throw "Tunnel URL not received. See $log" }
    Write-Host ''
    Write-Host "REMOTE222_URL: $url"
    Write-Host 'Send this URL in chat. Do NOT send the access key in chat.'
    Write-Host "To copy the access key locally: powershell -File `"$PSScriptRoot\Copy-AccessKey.ps1`""
    Write-Host 'Paste it into the REMOTE222_TOKEN secret in cloud environment settings.'
    Write-Host 'Allow the secret only for the hostname in the URL above.'
    Write-Host 'Full account control is active. Keep these windows open.'
    Write-Host 'Press Enter here to disconnect (or close the agent window).'
    $null = Read-Host
} finally {
    foreach ($process in @($tunnel, $agent)) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -ErrorAction SilentlyContinue }
    }
    Pop-Location
}
