@echo off
rem Runs this computer's Pillar as a seed (with an Archive and the credit mint),
rem using its usual data folder, so it keeps the same onion address and keys.
rem Keep this window open and the computer awake: while it's closed, new
rem accounts can't find the network and messages can't be delivered.
rem It runs a copy of pillar.exe, so new builds aren't blocked while it runs;
rem close and reopen this window to switch to a newer build.
title Sentinel seed Pillar - keep this window open
cd /d "%~dp0.."
if not exist target\release\pillar.exe (
  echo Build it first: powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
  pause
  exit /b 1
)
set "RUN=%LOCALAPPDATA%\sentinel-proto\seed-bin"
if not exist "%RUN%" mkdir "%RUN%"
copy /y target\release\pillar.exe "%RUN%\pillar.exe" >nul
"%RUN%\pillar.exe" --archive-gb 20 --mint-interval 1200
echo.
echo The Pillar stopped. Press a key to close this window.
pause >nul
