# Puts the Windows FFmpeg (the video cleaner bundled with the app) into
# vendor\ffmpeg\win64. Its biggest file is too large for GitHub, so it isn't
# in the repository; this script fetches it instead.
#
# 1. If the files there already match vendor\ffmpeg\win64\SHA256SUMS.txt,
#    nothing is downloaded.
# 2. Otherwise it downloads the current FFmpeg 8.1 build from
#    BtbN/FFmpeg-Builds over HTTPS, checks the download against the SHA-256
#    GitHub publishes for it, unpacks it, and records the new fingerprints in
#    SHA256SUMS.txt. The app is compiled with that file and refuses to run
#    any FFmpeg file that doesn't match it.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\get-ffmpeg.ps1 [-Force]

param([switch]$Force)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'vendor\ffmpeg\win64'
$sums = Join-Path $out 'SHA256SUMS.txt'

function Test-Pinned {
    if (-not (Test-Path $sums)) { return $false }
    $any = $false
    foreach ($line in Get-Content $sums) {
        $parts = $line -split '  ', 2
        if ($parts.Count -ne 2) { continue }
        $file = Join-Path $out $parts[1].Trim()
        if (-not (Test-Path $file)) { return $false }
        if ((Get-FileHash -Algorithm SHA256 $file).Hash.ToLower() -ne $parts[0].Trim()) { return $false }
        $any = $true
    }
    return $any
}

if (-not $Force -and (Test-Pinned)) {
    'FFmpeg is already in place and matches SHA256SUMS.txt.'
    return
}

$asset = 'ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip'
'Looking up the current FFmpeg build...'
$release = Invoke-RestMethod -UseBasicParsing 'https://api.github.com/repos/BtbN/FFmpeg-Builds/releases/tags/latest'
$a = $release.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
if (-not $a) { throw "the FFmpeg build $asset wasn't found" }
if ($a.digest -notmatch '^sha256:([0-9a-f]{64})$') { throw 'GitHub gave no fingerprint for the download' }
$expected = $Matches[1]

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-ffmpeg-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
try {
    $zip = Join-Path $tmp $asset
    "Downloading $asset ($([math]::Round($a.size / 1MB)) MB)..."
    Invoke-WebRequest -UseBasicParsing $a.browser_download_url -OutFile $zip
    $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if ($got -ne $expected) { throw "the download doesn't match its published fingerprint (got $got)" }
    Expand-Archive $zip (Join-Path $tmp 'x')
    $top = Get-ChildItem (Join-Path $tmp 'x') -Directory | Select-Object -First 1
    $bin = Join-Path $top.FullName 'bin'

    New-Item -ItemType Directory -Force $out | Out-Null
    Get-ChildItem $out -File | Where-Object { $_.Extension -in '.exe', '.dll' } | Remove-Item -Force
    $files = Get-ChildItem $bin -File | Where-Object { ($_.Extension -eq '.dll') -or ($_.Name -in 'ffmpeg.exe', 'ffprobe.exe') }
    foreach ($f in $files) { Copy-Item $f.FullName $out }
    $lic = Join-Path $top.FullName 'LICENSE.txt'
    if (Test-Path $lic) { Copy-Item $lic $out -Force }

    # The programs first, then the libraries, one "hash  name" per line.
    $ordered = @($files | Where-Object Extension -eq '.exe' | Sort-Object Name) + @($files | Where-Object Extension -eq '.dll' | Sort-Object Name)
    $text = ($ordered | ForEach-Object { (Get-FileHash -Algorithm SHA256 (Join-Path $out $_.Name)).Hash.ToLower() + '  ' + $_.Name }) -join "`n"
    [IO.File]::WriteAllText($sums, $text + "`n")
    "FFmpeg is in place ($($files.Count) files). Download fingerprint: $expected"
    'Rebuild the app so it pins these files (scripts\build-release.ps1 does this).'
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
