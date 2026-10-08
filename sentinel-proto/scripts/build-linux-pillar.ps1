# The Pillar for Linux (x86-64 and ARM64), built on Windows.
#
# One static file per system: no libraries to install, runs on any Linux
# distribution (and Raspberry Pi / ARM servers). Built with Zig as the
# cross-linker (`scoop install zig`, `cargo install cargo-zigbuild`,
# `rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl`).
#
# Like build-release.ps1, local paths are stripped and the results checked.
# The build folder is outside the project (the linker can't handle spaces in
# paths, and big build files shouldn't sit in a synced folder).
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\build-linux-pillar.ps1 [-Out C:\sb]

param([string]$Out = 'C:\sb')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$userHome = $env:USERPROFILE
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $userHome '.cargo' }
$rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $userHome '.rustup' }
$env:CARGO_ENCODED_RUSTFLAGS = @(
    "--remap-path-prefix=$userHome=home",
    "--remap-path-prefix=$cargoHome=cargo",
    "--remap-path-prefix=$rustupHome=rustup",
    "--remap-path-prefix=$root=sentinel",
    "--remap-path-prefix=$Out=build"
) -join [char]0x1f
$env:CARGO_TARGET_DIR = $Out

Push-Location $root
try {
    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force $dist | Out-Null
    foreach ($t in @('x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl')) {
        cargo zigbuild --release -p pillar --target $t
        if ($LASTEXITCODE -ne 0) { throw "build failed for $t" }
        $bin = Join-Path $Out "$t\release\pillar"
        $name = if ($t -like 'x86_64*') { 'sentinel-pillar-linux-x86_64' } else { 'sentinel-pillar-linux-arm64' }
        Copy-Item $bin (Join-Path $dist $name) -Force
    }
    # Nothing may carry a local path (user name) out of this machine.
    $user = Split-Path -Leaf $userHome
    foreach ($f in Get-ChildItem $dist -Filter 'sentinel-pillar-linux-*') {
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        # Path forms only (the name alone can occur inside ordinary words).
        foreach ($needle in @("\$user\", "/$user/", "Users\$user", "home/$user")) {
            if ($text.Contains($needle)) { throw "local path left in $($f.Name)" }
        }
        "clean: dist\$($f.Name) ($([math]::Round($f.Length / 1MB, 1)) MB)"
    }
} finally {
    Pop-Location
}
