# Release build with every local path stripped from the binaries.
#
# Compilers record source file paths (for panic messages and debug info).
# On a developer's machine those paths contain their user name, which would
# ship inside every binary and installer. This script rewrites them to
# neutral prefixes at build time, so no path is written into the repository
# either: the real paths are read from the environment when the script runs.
#
# Usage (from anywhere):  powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
# Then it checks the results and refuses to finish if a user path is left.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$userHome = $env:USERPROFILE
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $userHome '.cargo' }
$rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $userHome '.rustup' }

# The last matching prefix wins, so the most specific ones come last.
$flags = @(
    "--remap-path-prefix=$userHome=home",
    "--remap-path-prefix=$cargoHome=cargo",
    "--remap-path-prefix=$rustupHome=rustup",
    "--remap-path-prefix=$root=sentinel",
    # Record only the debug-symbol file's name, not its full path.
    "-Clink-arg=/PDBALTPATH:%_PDB%"
)
$env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]0x1f

Push-Location $root
try {
    # The bundled FFmpeg (downloaded and checked if it isn't here yet).
    powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'get-ffmpeg.ps1')
    if ($LASTEXITCODE -ne 0) { throw "FFmpeg couldn't be fetched" }
    cargo build --release -p pillar -p sentinel
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    Push-Location (Join-Path $root 'crates\app')
    try {
        cargo tauri build
        if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
    } finally { Pop-Location }

    # Refuse to finish if the user's folder name survived anywhere.
    $needle = [Text.Encoding]::ASCII.GetBytes((Split-Path -Leaf $userHome))
    $files = @('target\release\Sentinel.exe', 'target\release\pillar.exe', 'target\release\sentinel-cli.exe')
    foreach ($f in $files) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $root $f))
        $text = [Text.Encoding]::ASCII.GetString($bytes)
        $hit = $text.IndexOf("\" + [Text.Encoding]::ASCII.GetString($needle) + "\", [StringComparison]::OrdinalIgnoreCase)
        if ($hit -ge 0) { throw "$f still contains a local user path" }
        Write-Host "clean: $f"
    }
} finally { Pop-Location }
