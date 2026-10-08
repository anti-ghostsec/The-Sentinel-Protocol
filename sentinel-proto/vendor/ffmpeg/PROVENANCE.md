# FFmpeg (bundled)

- Source: BtbN/FFmpeg-Builds, release `latest`, asset
  `ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip` (FFmpeg n8.1.3, built 2026-10-04).
- Downloaded 2026-10-04 over HTTPS from github.com; SHA-256 of the zip
  `1d2e0edcdb7a1ff3556a20405cd0a6859855bde1f1a543d4a653824b4238f5fc`, matching
  the release's `checksums.sha256` (kept here).
- Kept: `ffmpeg.exe`, `ffprobe.exe` and their DLLs (`ffplay.exe` dropped).
  They are not in the repository (one DLL is over GitHub's size limit):
  `scripts/get-ffmpeg.ps1` downloads the current 8.1 build, checks it against
  the SHA-256 GitHub publishes, and rewrites `win64/SHA256SUMS.txt`. If those
  files are missing or changed, the app cleans videos without FFmpeg.
- `win64/SHA256SUMS.txt` is compiled into the app, which re-checks every file
  before each run and refuses to run a modified copy.
- License: GPL build (includes libx264), shipped as separate programs that
  Sentinel runs; see `win64/LICENSE.txt`.

Sentinel runs FFmpeg only on the user's own files, with
`-protocol_whitelist file,pipe` and an explicit input format, so a crafted
file (playlists, concat lists) can never make it open a network connection.
