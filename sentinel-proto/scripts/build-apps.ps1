# Builds the apps that ship inside Sentinel (apps\*) to WebAssembly, with
# local paths stripped, into crates\sentinel-core\apps\<name>-<version>.wasm.
#
# A built-in app's identity is the hash of its code, and every member of a
# room must run the same code. So a version, once released, is never
# rebuilt or replaced: change the app, raise its version, and keep the old
# file so rooms using it keep working.
#
# Needs: rustup target add wasm32-unknown-unknown
# Usage: powershell -ExecutionPolicy Bypass -File scripts\build-apps.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$userHome = $env:USERPROFILE
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $userHome '.cargo' }
$env:CARGO_ENCODED_RUSTFLAGS = @(
    "--remap-path-prefix=$userHome=home",
    "--remap-path-prefix=$cargoHome=cargo",
    "--remap-path-prefix=$root=sentinel"
) -join [char]0x1f
$out = Join-Path $root 'crates\sentinel-core\apps'
New-Item -ItemType Directory -Force $out | Out-Null
$user = Split-Path -Leaf $userHome

foreach ($dir in Get-ChildItem (Join-Path $root 'apps') -Directory) {
    $toml = Get-Content -Raw (Join-Path $dir.FullName 'Cargo.toml')
    $crate = [regex]::Match($toml, '(?m)^name\s*=\s*"([^"]+)"').Groups[1].Value
    $major = [regex]::Match($toml, '(?m)^version\s*=\s*"(\d+)\.').Groups[1].Value
    $target = Join-Path $out "$($dir.Name)-$major.wasm"
    Push-Location $dir.FullName
    try {
        cmd /c "cargo build --release --target wasm32-unknown-unknown >nul 2>&1"
        if ($LASTEXITCODE -ne 0) { throw "$($dir.Name) didn't build" }
    } finally { Pop-Location }
    $built = Join-Path $dir.FullName ("target\wasm32-unknown-unknown\release\" + $crate.Replace('-', '_') + '.wasm')
    $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($built))
    foreach ($needle in @("\$user\", "/$user/", "Users\$user")) {
        if ($text.Contains($needle)) { throw "local path left in $($dir.Name)" }
    }
    if ((Test-Path $target) -and ((Get-FileHash $target).Hash -ne (Get-FileHash $built).Hash)) {
        throw "$target already exists with different code: raise the app's version instead of replacing a released one"
    }
    Copy-Item $built $target -Force
    "clean: $target ($([math]::Round((Get-Item $target).Length / 1KB)) KB)"
}
