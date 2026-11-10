$ErrorActionPreference = 'Stop'
$toolsPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../tools'))
New-Item -ItemType Directory -Force -Path $toolsPath | Out-Null
$release = Invoke-RestMethod 'https://api.github.com/repos/projectdiscovery/httpx/releases/latest'
$asset = $release.assets | Where-Object name -Match 'windows_amd64.zip$' | Select-Object -First 1
if (-not $asset) { throw 'No Windows amd64 httpx release found.' }
$zipPath = Join-Path $toolsPath 'httpx-download.zip'
Invoke-WebRequest -UseBasicParsing $asset.browser_download_url -OutFile $zipPath
$checksums = $release.assets | Where-Object name -Match 'checksums.txt$' | Select-Object -First 1
if (-not $checksums) { throw 'Release checksum file is missing.' }
$checksumText = (Invoke-WebRequest -UseBasicParsing $checksums.browser_download_url).Content
if ($checksumText -is [byte[]]) { $checksumText = [Text.Encoding]::UTF8.GetString($checksumText) }
$expected = ($checksumText -split "`n" | Where-Object { $_ -match [regex]::Escape($asset.name) }) -split '\s+' | Select-Object -First 1
if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -ne $expected) { throw 'httpx checksum verification failed.' }
Expand-Archive -LiteralPath $zipPath -DestinationPath $toolsPath -Force
Remove-Item -LiteralPath $zipPath
& (Join-Path $toolsPath 'httpx.exe') -version
if ($LASTEXITCODE -ne 0) { throw 'httpx installation verification failed.' }
