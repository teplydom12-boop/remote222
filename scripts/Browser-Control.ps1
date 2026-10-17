param([Parameter(Mandatory=$true)][string]$RequestBase64)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$script:socket = $null
$script:messageId = 0
$script:navigation = $null

function Get-ChromePath([string]$preferred) {
    $paths = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
        if ($root) { $paths += Join-Path $root 'Google\Chrome\Application\chrome.exe' }
    }
    foreach ($key in @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe', 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe')) {
        $candidate = [Microsoft.Win32.Registry]::GetValue($key, '', $null)
        if ($candidate) { $paths += [string]$candidate }
    }
    if ($preferred) { $paths = @($preferred) }
    foreach ($candidate in $paths) {
        if ([IO.Path]::GetFileName($candidate) -ieq 'chrome.exe' -and [IO.File]::Exists($candidate)) {
            $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($candidate)
            if ($version.ProductName -eq 'Google Chrome' -and $version.CompanyName -match '^Google (LLC|Inc\.)$') { return [IO.Path]::GetFullPath($candidate) }
        }
    }
    if ($preferred) { throw 'The explicit chrome_path is not an installed Google Chrome executable' }
    throw 'Installed Google Chrome was not found'
}

function Get-DownloadsDirectory {
    $value = [Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders', '{374DE290-123F-4565-9164-39C4925E467B}', $null)
    if (-not $value) { $value = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads' }
    return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$value))
}

function Get-ProfileDirectory([string]$value) {
    $parent = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Remote222')).TrimEnd('\')
    if (-not $value) { $value = Join-Path $parent 'ChromeAutomation' }
    if (-not [IO.Path]::IsPathRooted($value) -or $value -match '[\x00-\x1f"]') { throw 'An absolute dedicated browser profile is required' }
    $path = [IO.Path]::GetFullPath($value).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($path) -ine $parent -or [IO.Path]::GetFileName($path) -notmatch '^ChromeAutomation(?:-[A-Za-z0-9_-]+)?$') {
        throw 'Use a dedicated LOCALAPPDATA\Remote222\ChromeAutomation[-name] profile'
    }
    foreach ($existing in @($parent, $path)) {
        if ([IO.Directory]::Exists($existing) -and ((Get-Item -LiteralPath $existing -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Browser profile directories must not be links'
        }
    }
    return $path
}

function Get-Json([string]$path) {
    $response = Invoke-WebRequest -UseBasicParsing -Uri ('http://127.0.0.1:' + $script:port + $path) -TimeoutSec 4 -MaximumRedirection 0
    if ($response.Content.Length -gt 1048576) { throw 'Browser discovery response is too large' }
    $parsed = ConvertFrom-Json -InputObject $response.Content
    return $parsed
}

function Get-BrowserConnection([string]$profile) {
    $active = Join-Path $profile 'DevToolsActivePort'
    if (-not [IO.File]::Exists($active)) { return $null }
    try {
        $lines = [IO.File]::ReadAllLines($active)
        $portValue = 0
        if ($lines.Count -lt 2 -or -not [int]::TryParse($lines[0], [ref]$portValue) -or $portValue -lt 1 -or $portValue -gt 65535 -or $lines[1] -notmatch '^/devtools/browser/[A-Za-z0-9-]{1,128}$') { return $null }
        $script:port = $portValue
        $version = Get-Json '/json/version'
        $uri = [Uri]$version.webSocketDebuggerUrl
        if ($uri.Scheme -ne 'ws' -or $uri.Host -notin @('127.0.0.1', 'localhost') -or $uri.Port -ne $portValue -or $uri.AbsolutePath -cne $lines[1] -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) { return $null }
        return @{port=$portValue; browser=[string]$version.Browser; websocket=$uri.AbsoluteUri; profile_directory=$profile}
    } catch { return $null }
}

function Start-Browser([string]$profile, [string]$chrome) {
    $connection = Get-BrowserConnection $profile
    if ($connection) { return $connection }
    [void][IO.Directory]::CreateDirectory($profile)
    $arguments = '--remote-debugging-address=127.0.0.1 --remote-debugging-port=0 --user-data-dir="' + $profile + '" --no-first-run --no-default-browser-check about:blank'
    $process = Start-Process -FilePath $chrome -ArgumentList $arguments -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    do {
        Start-Sleep -Milliseconds 200
        $connection = Get-BrowserConnection $profile
        if ($connection) { return $connection }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The dedicated Chrome profile did not expose its local debugging endpoint'
}

function Open-Socket([string]$address, [string]$expectedPath) {
    if ($script:socket) { $script:socket.Dispose(); $script:socket = $null }
    $uri = [Uri]$address
    if ($uri.Scheme -ne 'ws' -or $uri.Host -notin @('127.0.0.1', 'localhost') -or $uri.Port -ne $script:port -or $uri.AbsolutePath -cne $expectedPath -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) { throw 'Unexpected local browser debugging address' }
    $script:socket = [Net.WebSockets.ClientWebSocket]::new()
    $cancellation = [Threading.CancellationTokenSource]::new(10000)
    try { [void]$script:socket.ConnectAsync($uri, $cancellation.Token).GetAwaiter().GetResult() }
    finally { $cancellation.Dispose() }
}

function Invoke-CDP([string]$method, [hashtable]$parameters) {
    $script:messageId++
    $wanted = $script:messageId
    $json = ConvertTo-Json -InputObject @{id=$wanted;method=$method;params=$parameters} -Depth 25 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $cancellation = [Threading.CancellationTokenSource]::new(15000)
    try {
        [void]$script:socket.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, $cancellation.Token).GetAwaiter().GetResult()
        while ($true) {
            $stream = [IO.MemoryStream]::new()
            try {
                do {
                    $buffer = [byte[]]::new(65536)
                    $received = $script:socket.ReceiveAsync([ArraySegment[byte]]::new($buffer), $cancellation.Token).GetAwaiter().GetResult()
                    if ($received.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw 'Chrome closed the local debugging connection' }
                    $stream.Write($buffer, 0, $received.Count)
                    if ($stream.Length -gt 33554432) { throw 'Browser response exceeds 32 MiB' }
                } while (-not $received.EndOfMessage)
                $message = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($stream.ToArray()))
            } finally { $stream.Dispose() }
            if ($message.id -ne $wanted) { continue }
            if ($message.error) { throw ('Browser command failed: ' + [string]$message.error.message) }
            if ($message.result.exceptionDetails) { throw ('Browser script failed: ' + [string]$message.result.exceptionDetails.text) }
            return $message.result
        }
    } finally { $cancellation.Dispose() }
}

function Get-Target([string]$id) {
    if ($id -notmatch '^[A-Za-z0-9_-]{1,128}$') { throw 'An exact browser target_id is required' }
    $tabs = @(Get-Json '/json/list')
    foreach ($tab in $tabs) {
        if ($tab.type -eq 'page' -and $tab.id -ceq $id) { return $tab }
    }
    throw 'The requested browser tab is no longer available; inspect tabs before selecting another'
}

function Connect-Target([string]$id) {
    $tab = Get-Target $id
    Open-Socket ([string]$tab.webSocketDebuggerUrl) ('/devtools/page/' + $id)
}

function New-Target($connection, [string]$url) {
    $checked = Check-URL $url
    Open-Socket $connection.websocket ([Uri]$connection.websocket).AbsolutePath
    $created = Invoke-CDP 'Target.createTarget' @{url='about:blank';background=$false}
    $id = [string]$created.targetId
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    do {
        try { Connect-Target $id; break }
        catch {
            if ([DateTime]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Milliseconds 150
        }
    } while ($true)
    Navigate-Target $checked
    return $id
}

function Check-URL([string]$value) {
    $uri = $null
    if ($value -eq 'about:blank') { return $value }
    if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo) { throw 'Use an absolute HTTP(S) URL without embedded credentials' }
    return $uri.AbsoluteUri
}

function Navigate-Target([string]$url) {
    $checked = Check-URL $url
    [void](Invoke-CDP 'Page.enable' @{})
    $response = Invoke-CDP 'Page.navigate' @{url=$checked}
    if ($response.errorText) { throw ('Chrome navigation failed: ' + [string]$response.errorText) }
    $script:navigation = @{loader_id=[string]$response.loaderId;frame_id=[string]$response.frameId;url=$checked}
}

function Wait-Page([int]$milliseconds) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($milliseconds)
    $state = @{url='';title='';ready_state='loading';body_text_length=0;navigation_confirmed=$false}
    do {
        try {
            $parameters = @{expression='({url:location.href,title:document.title,ready_state:document.readyState,body_text_length:document.body?document.body.innerText.length:0})';returnByValue=$true}
            $confirmed = $true
            if ($script:navigation) {
                $state.navigation_confirmed = $false
                $state.ready_state = 'loading'
                $state.title = ''
                $tree = Invoke-CDP 'Page.getFrameTree' @{}
                $frame = $tree.frameTree.frame
                $state.url = [string]$frame.url
                $confirmed = $frame.id -ceq $script:navigation.frame_id -and (-not $script:navigation.loader_id -or $frame.loaderId -ceq $script:navigation.loader_id)
                if ($confirmed) {
                    # Bind evaluation to this frame's current document, rather
                    # than an old default JS context during a navigation.
                    $world = Invoke-CDP 'Page.createIsolatedWorld' @{frameId=$frame.id;worldName='remote222-readiness'}
                    $parameters.contextId = $world.executionContextId
                }
            }
            if ($confirmed) {
                $response = Invoke-CDP 'Runtime.evaluate' $parameters
                $observed = $response.result.value
                if ($script:navigation -and -not $script:navigation.loader_id -and $observed.url -cne $script:navigation.url) { $confirmed = $false }
                if ($confirmed) {
                    $state = @{url=$observed.url;title=$observed.title;ready_state=$observed.ready_state;body_text_length=$observed.body_text_length;navigation_confirmed=$true}
                    if ($state.ready_state -eq 'complete') { $script:navigation=$null; return $state }
                }
            }
        } catch {
            if ($_.Exception.Message -notmatch 'Cannot find context|context.*destroyed|Execution context|Inspected target navigated|frame.*not found') { throw }
        }
        if ([DateTime]::UtcNow -ge $deadline) { return $state }
        Start-Sleep -Milliseconds 200
    } while ($true)
}

function Inspect-Target([string]$id, [int]$wait) {
    $state = Wait-Page $wait
    if (-not $state.navigation_confirmed) { return @{target_id=$id;url=$state.url;title=$state.title;ready_state='loading';navigation_confirmed=$false;text='';inputs=@()} }
    $expression = '({url:location.href,title:document.title,ready_state:document.readyState,text:document.body?document.body.innerText.slice(0,12000):"",inputs:Array.from(document.querySelectorAll("input,textarea,select,button,[role=button]")).slice(0,80).map(e=>({tag:e.tagName.toLowerCase(),id:e.id,name:e.name||"",type:e.type||"",placeholder:e.getAttribute("placeholder")||"",aria_label:e.getAttribute("aria-label")||"",text:(e.tagName==="BUTTON"||e.getAttribute("role")==="button")?(e.innerText||"").slice(0,120):""}))})'
    $response = Invoke-CDP 'Runtime.evaluate' @{expression=$expression;returnByValue=$true}
    $value = $response.result.value
    return @{target_id=$id;url=$value.url;title=$value.title;ready_state=$value.ready_state;navigation_confirmed=$true;text=$value.text;inputs=@($value.inputs)}
}

function New-FileBytes([string]$path, [byte[]]$bytes) {
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($bytes, 0, $bytes.Length) } finally { $file.Dispose() }
}

function Hash-Text([string]$value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Save-HTML($request, [string]$profile, [int]$wait) {
    $id = [string]$request.request_id
    if ($id -notmatch '^[A-Za-z0-9_-]{8,80}$') { throw 'save_html requires a stable request_id of 8 to 80 URL-safe characters' }
    $directory = [string]$request.output_directory
    if (-not $directory) { $directory = Join-Path (Get-DownloadsDirectory) 'Remote222' }
    if (-not [IO.Path]::IsPathRooted($directory)) { throw 'Export directory must be an absolute path' }
    $directory = [IO.Path]::GetFullPath($directory)
    [void][IO.Directory]::CreateDirectory($directory)
    $html = Join-Path $directory ('page-' + $id + '.html')
    $gzip = $html + '.gz'
    $receipt = $html + '.json'
    $fingerprint = Hash-Text (ConvertTo-Json -InputObject ([ordered]@{profile=$profile;target_id=[string]$request.target_id;url=[string]$request.url;wait_ms=$wait;directory=$directory}) -Compress)
    if ([IO.File]::Exists($receipt)) {
        $previous = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receipt))
        if ($previous.fingerprint -cne $fingerprint -or $previous.result.html_path -ine $html -or $previous.result.gzip_path -ine $gzip) { throw 'Export request_id conflict; the previous request selected different inputs' }
        if (-not [IO.File]::Exists($html) -or -not [IO.File]::Exists($gzip) -or (Get-FileHash -LiteralPath $html -Algorithm SHA256).Hash.ToLowerInvariant() -cne $previous.result.html_sha256 -or (Get-FileHash -LiteralPath $gzip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $previous.result.gzip_sha256) { throw 'Previously exported files are missing or changed; they will not be overwritten' }
        $previous.result.reused = $true
        return $previous.result
    }
    $lock = $html + '.lock'
    if ([IO.File]::Exists($lock) -or [IO.File]::Exists($html) -or [IO.File]::Exists($gzip)) { throw 'An earlier export with this request_id is incomplete; inspect existing files before a new request' }
    $connection = Get-BrowserConnection $profile
    if (-not $connection -and $request.url) { $connection = Start-Browser $profile (Get-ChromePath ([string]$request.chrome_path)) }
    if (-not $connection) { throw 'The dedicated Chrome profile is not running; use start or supply a URL' }
    $target = [string]$request.target_id
    if (-not $target -and -not $request.url) { throw 'save_html requires target_id or a URL' }
    if ($request.url) { [void](Check-URL ([string]$request.url)) }
    if ($target) { [void](Get-Target $target) }
    New-FileBytes $lock ([Text.Encoding]::UTF8.GetBytes($fingerprint))
    if (-not $target) { $target = New-Target $connection ([string]$request.url) }
    else {
        Connect-Target $target
        if ($request.url) { Navigate-Target ([string]$request.url) }
    }
    $state = Wait-Page $wait
    if (-not $state.navigation_confirmed) { throw 'Navigation did not commit within wait_ms; the previous document was not exported' }
    $expression = 'JSON.stringify({url:location.href,title:document.title,ready_state:document.readyState,html:(document.doctype?new XMLSerializer().serializeToString(document.doctype)+"\n":"")+(document.documentElement?document.documentElement.outerHTML:"")})'
    $response = Invoke-CDP 'Runtime.evaluate' @{expression=$expression;returnByValue=$true}
    $page = ConvertFrom-Json -InputObject $response.result.value
    $bytes = ([Text.UTF8Encoding]::new($false)).GetBytes([string]$page.html)
    if ($bytes.Length -gt 16777216) { throw 'HTML export exceeds 16 MiB' }
    New-FileBytes $html $bytes
    $file = [IO.File]::Open($gzip, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $compressor = [IO.Compression.GZipStream]::new($file, [IO.Compression.CompressionMode]::Compress, $true)
        try { $compressor.Write($bytes, 0, $bytes.Length) } finally { $compressor.Dispose() }
    } finally { $file.Dispose() }
    $result = [ordered]@{target_id=$target;url=$page.url;title=$page.title;ready_state=$page.ready_state;html_path=$html;gzip_path=$gzip;html_sha256=(Get-FileHash -LiteralPath $html -Algorithm SHA256).Hash.ToLowerInvariant();gzip_sha256=(Get-FileHash -LiteralPath $gzip -Algorithm SHA256).Hash.ToLowerInvariant();html_bytes=$bytes.Length;gzip_bytes=(Get-Item -LiteralPath $gzip).Length;reused=$false}
    New-FileBytes $receipt ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @{fingerprint=$fingerprint;result=$result} -Depth 10 -Compress)))
    return $result
}

try {
    $requestBytes = [Convert]::FromBase64String($RequestBase64)
    if ($requestBytes.Length -gt 65536) { throw 'Browser request exceeds 64 KiB' }
    $request = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($requestBytes))
    $operation = [string]$request.operation
    if ($operation -notin @('system','start','status','tabs','open','inspect','evaluate','save_html')) { throw 'Unknown browser operation' }
    $profile = Get-ProfileDirectory ([string]$request.profile_directory)
    $wait = 1500
    if ($null -ne $request.wait_ms) {
        if ($request.wait_ms -isnot [int] -and $request.wait_ms -isnot [long]) { throw 'wait_ms must be an integer' }
        $wait = [int]$request.wait_ms
    }
    if ($wait -lt 0 -or $wait -gt 15000) { throw 'wait_ms must be between 0 and 15000' }
    if ($operation -eq 'system') {
        $chrome = $null
        if ($request.chrome_path) { $chrome = Get-ChromePath ([string]$request.chrome_path) }
        else { try { $chrome = Get-ChromePath '' } catch {} }
        $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        $windows = @()
        foreach ($process in (Get-Process)) {
            try {
                if ($process.SessionId -ne $sessionId -or $process.MainWindowHandle -eq 0) { continue }
                $processPath = $null
                try { $processPath = $process.Path } catch {}
                $windows += @{process_id=$process.Id;process_name=$process.ProcessName;title=$process.MainWindowTitle;path=$processPath}
                if ($windows.Count -ge 50) { break }
            } catch {}
        }
        $automation = [Reflection.Assembly]::LoadWithPartialName('UIAutomationClient')
        $result = @{computer=$env:COMPUTERNAME;chrome_path=$chrome;downloads_directory=(Get-DownloadsDirectory);default_profile_directory=$profile;powershell_version=[string]$PSVersionTable.PSVersion;session_id=$sessionId;uiautomation_available=($null -ne $automation);windows=$windows}
    } else {
        $connection = Get-BrowserConnection $profile
        if ($operation -in @('start','open') -and -not $connection) {
            $connection = Start-Browser $profile (Get-ChromePath ([string]$request.chrome_path))
        }
        if ($operation -in @('start','status')) {
            $result = @{running=($null -ne $connection);profile_directory=$profile;computer=$env:COMPUTERNAME}
            if ($connection) { $result.debug_port=$connection.port; $result.browser=$connection.browser }
        } elseif ($operation -eq 'save_html') {
            $result = Save-HTML $request $profile $wait
        } else {
            if (-not $connection) { throw 'The dedicated Chrome profile is not running; use start first' }
            $script:port = $connection.port
            if ($operation -eq 'tabs') {
                $tabs = @(Get-Json '/json/list' | Where-Object { $_.type -eq 'page' } | Select-Object id,type,url,title)
                $result = @{tabs=$tabs}
            } else {
                $target = [string]$request.target_id
                if ($operation -eq 'open' -and -not $target) {
                    $target = New-Target $connection ([string]$request.url)
                } else {
                    Connect-Target $target
                    if ($operation -eq 'open') { Navigate-Target ([string]$request.url) }
                }
                if ($operation -eq 'evaluate') {
                    $expression = [string]$request.expression
                    if (-not $expression -or $expression.Length -gt 24000) { throw 'evaluate requires an expression of at most 24000 characters' }
                    $response = Invoke-CDP 'Runtime.evaluate' @{expression=$expression;returnByValue=$true;awaitPromise=$true;timeout=12000}
                    $result = @{target_id=$target;value=$response.result.value;type=$response.result.type}
                } else { $result = Inspect-Target $target $wait }
            }
        }
    }
    $encoded = ConvertTo-Json -InputObject @{ok=$true;result=$result} -Depth 25 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($encoded) -gt 122880) { throw 'Browser result exceeds 120 KiB; use a smaller expression or HTML export' }
    Write-Output $encoded
} catch {
    $message = [string]$_.Exception.Message
    if ($message.Length -gt 1000) { $message = $message.Substring(0, 1000) }
    ConvertTo-Json -InputObject @{ok=$false;error='browser_error';message=$message} -Compress
} finally {
    if ($script:socket) { $script:socket.Dispose() }
}
