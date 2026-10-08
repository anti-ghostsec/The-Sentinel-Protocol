# The Android app (APK for phones: 64-bit ARM and older 32-bit ARM), signed
# with the release keystore, local paths stripped and checked.
#
# Needs: Android SDK + NDK, Java 17+, `cargo install tauri-cli`, and
# `rustup target add aarch64-linux-android armv7-linux-androideabi`.
# The keystore stays outside the project (a USB stick is best): every update
# to the app must be signed with the same one, so keep a copy safe.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\build-android.ps1 `
#           -Keystore "E:\android-release.jks" -PasswordFile "E:\android-release.password"

param(
    [Parameter(Mandatory = $true)][string]$Keystore,
    [Parameter(Mandatory = $true)][string]$PasswordFile
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root 'crates\app'
$gradle = Join-Path $app 'gen\android'
if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
if (-not $env:NDK_HOME) { $env:NDK_HOME = (Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') | Sort-Object Name | Select-Object -Last 1).FullName }
if (-not $env:JAVA_HOME) { $env:JAVA_HOME = (Get-ChildItem 'C:\Program Files\Java' -Filter 'jdk-*' | Sort-Object Name | Select-Object -Last 1).FullName }

$userHome = $env:USERPROFILE
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $userHome '.cargo' }
$env:CARGO_ENCODED_RUSTFLAGS = @(
    "--remap-path-prefix=$userHome=home",
    "--remap-path-prefix=$cargoHome=cargo",
    "--remap-path-prefix=$root=sentinel"
) -join [char]0x1f

# Signing details for Gradle (a local, git-ignored file, removed afterwards).
$props = Join-Path $gradle 'keystore.properties'
$pw = (Get-Content -Raw $PasswordFile).Trim()
"storeFile=$($Keystore -replace '\\','/')`npassword=$pw`nkeyAlias=sentinel" | Out-File -Encoding ascii $props
try {
    # Only this build's libraries go in (no leftovers from test builds).
    Remove-Item -Recurse -Force (Join-Path $gradle 'app\src\main\jniLibs') -ErrorAction SilentlyContinue
    Push-Location $app
    $ndkBin = Join-Path $env:NDK_HOME 'toolchains\llvm\prebuilt\windows-x86_64\bin'
    foreach ($t in @(@('aarch64', 'aarch64-linux-android', 'arm64-v8a', 'aarch64-linux-android'), @('armv7', 'armv7-linux-androideabi', 'armeabi-v7a', 'armv7a-linux-androideabi'))) {
        # Tauri builds the library, then tries a symbolic link Windows may
        # refuse without Developer Mode; the library is copied instead.
        # (Run through cmd: Windows PowerShell treats cargo's progress
        # messages as errors.)
        cmd /c "cargo tauri android build --apk --target $($t[0]) >nul 2>&1"
        $so = Join-Path $root "target\$($t[1])\release\libsentinel_app_lib.so"
        if (-not (Test-Path $so)) { throw "the app library for $($t[0]) didn't build" }
        $dir = Join-Path $gradle "app\src\main\jniLibs\$($t[2])"
        New-Item -ItemType Directory -Force $dir | Out-Null
        Copy-Item $so $dir -Force
        # The separate Tor program (see torproc.rs), stripped, shipped as a
        # "library" so the system unpacks it where the app may run it.
        $clang = Join-Path $ndkBin "$($t[3])24-clang.cmd"
        $u = $t[1].Replace('-', '_')
        Set-Item "env:CARGO_TARGET_$($u.ToUpper())_LINKER" $clang
        Set-Item "env:CC_$u" $clang
        Set-Item "env:AR_$u" (Join-Path $ndkBin 'llvm-ar.exe')
        cmd /c "cargo rustc --release -p sentinel-net --bin sentinel-tor --target $($t[1]) -- -C strip=symbols >nul 2>&1"
        $tor = Join-Path $root "target\$($t[1])\release\sentinel-tor"
        if (-not (Test-Path $tor)) { throw "the Tor program for $($t[0]) didn't build" }
        Copy-Item $tor (Join-Path $dir 'libsentinel_tor.so') -Force
    }
    Pop-Location
    Push-Location $gradle
    .\gradlew.bat assembleUniversalRelease -x rustBuildUniversalRelease -x rustBuildArm64Release -x rustBuildArmRelease -x rustBuildX86Release -x rustBuildX86_64Release --no-daemon
    if ($LASTEXITCODE -ne 0) { throw 'gradle failed' }
    Pop-Location
    $apk = Get-ChildItem -Recurse (Join-Path $gradle 'app\build\outputs\apk\universal\release') -Filter *.apk | Select-Object -First 1
    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force $dist | Out-Null
    Copy-Item $apk.FullName (Join-Path $dist 'sentinel-android.apk') -Force
    # The libraries inside must carry no local paths.
    $user = Split-Path -Leaf $userHome
    foreach ($t in @('aarch64-linux-android', 'armv7-linux-androideabi')) {
        foreach ($f in @('libsentinel_app_lib.so', 'sentinel-tor')) {
            $text = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes((Join-Path $root "target\$t\release\$f")))
            foreach ($needle in @("\$user\", "/$user/", "Users\$user")) {
                if ($text.Contains($needle)) { throw "local path left in $f ($t)" }
            }
        }
    }
    "clean: dist\sentinel-android.apk ($([math]::Round((Get-Item (Join-Path $dist 'sentinel-android.apk')).Length / 1MB, 1)) MB)"
} finally {
    Remove-Item -Force $props -ErrorAction SilentlyContinue
    Set-Location $root
}
