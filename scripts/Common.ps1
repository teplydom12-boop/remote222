$ErrorActionPreference = 'Stop'

function Find-RemotePython {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $result = & $launcher.Source -3 -c "import sys; print(sys.executable if sys.version_info >= (3,12) else '')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $result) { return $result.Trim() }
    }
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe"
    )
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command -and $command.Source -notlike '*\WindowsApps\*') { $candidates += $command.Source }
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $result = & $candidate -c "import sys; print(sys.executable if sys.version_info >= (3,12) else '')"
            if ($LASTEXITCODE -eq 0 -and $result) { return $result.Trim() }
        }
    }
    throw 'Python 3.12+ was not found. Run scripts\Install-Remote222.ps1 first.'
}

function Find-RemoteTunnel {
    $command = Get-Command cloudflared.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($candidate in @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\cloudflared.exe",
        "$env:ProgramFiles\cloudflared\cloudflared.exe",
        "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe"
    )) {
        if (Test-Path $candidate) { return $candidate }
    }
    throw 'cloudflared was not found. Run Install-Remote222.ps1, then open a new terminal.'
}

function Protect-RemoteState([string] $Directory) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $Directory /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict access to the agent key directory.' }
}
