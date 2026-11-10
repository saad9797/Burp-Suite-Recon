$ErrorActionPreference = 'Stop'
$workspacePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$appPort = if ($env:PORT) { $env:PORT } else { '4310' }
$appUrl = "http://127.0.0.1:$appPort"
function Test-Traceglass {
    try { return (Invoke-WebRequest -UseBasicParsing "$appUrl/bootstrap.js" -TimeoutSec 1).Content -match 'CAPTURE_TOKEN' } catch { return $false }
}
if (-not (Test-Traceglass)) {
    $dataPath = Join-Path $workspacePath 'data'
    New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
    $nodePath = (Get-Command node -ErrorAction Stop).Source
    $appProcess = Start-Process -FilePath $nodePath -ArgumentList 'server.js' -WorkingDirectory $workspacePath -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dataPath 'server.log') -RedirectStandardError (Join-Path $dataPath 'server-error.log') -PassThru
    $appProcess.Id | Set-Content (Join-Path $dataPath 'server.pid')
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if (Test-Traceglass) { $ready = $true; break }
        if ($appProcess.HasExited) { throw "Traceglass could not start. See $dataPath/server-error.log" }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) { throw "Traceglass did not become ready. See $dataPath/server-error.log" }
}
Start-Process $appUrl
