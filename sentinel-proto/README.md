# Sentinel (prototype)

This is the working prototype of **The Sentinel Protocol**: a social network and messenger that nobody owns, with Tor built in, designed for people whose lives may depend on not being found. The full design, in plain language, is in [How Sentinel works](../DESIGN.md).

**Status:** a prototype. It works over the real Tor network and has been tested end to end, but it has **not been audited**, the network has only one seed Pillar, and only the Windows app, the Android app and the Linux Pillar have been built so far. Don't rely on it where your safety is at stake yet. The design document's section 20 lists what's left.

## What's in here

| Folder | What it is |
|--------|-----------|
| `crates/app` | The desktop app (Windows): accounts, posts, Discover, messages, rooms, media, credits, settings |
| `crates/pillar` | The volunteer node (Pillar, optionally an Archive). Runs as a Tor onion service only; the established (seed) Pillars also issue credits |
| `crates/sentinel-core` | The shared core: sealed objects, accounts, messages, rooms, media cleaning and encryption, erasure coding, credits |
| `crates/sentinel-net` | Built-in Tor (arti), bridges, the circuit pool, the seed list |
| `crates/client` | A command-line client for testing (`sentinel-cli`) |
| `crates/app-sdk` | What a Sentinel App is made of (the commands it gets, the screens it describes) |
| `apps/poll` | Polls, the first Sentinel App (built to WebAssembly by `scripts/build-apps.ps1` into `crates/sentinel-core/apps/`) |
| `vendor/pt` | The Tor Project's signed bridge transport and bridge list (where it came from and its fingerprints are in `PROVENANCE.md`) |
| `vendor/ffmpeg` | The fingerprints of the FFmpeg build used to clean videos. The programs themselves are too big for GitHub: `scripts/get-ffmpeg.ps1` downloads and checks them (the release build does it for you). Without them the app still works, and videos are cleaned without being rebuilt |
| `patches/saturating-time` | A small fix for a library Tor depends on, which hangs forever on Windows (see below) |
| `scripts/build-release.ps1` | The only supported way to build programs you share |

## What works today

Tested over the live Tor network, with several accounts and volunteer nodes:

- **Accounts and profiles**: made on the device, locked with a strong passphrase; name, bio, picture and header; safety numbers; backups (without message history); passphrase change; panic wipe; an **emergency passphrase** that silently erases the real account and opens an empty one (undetectable from the files); **recovery words** (recover on a new device, or move the account to a new key that followers switch to automatically); an optional **key file** (VeraCrypt-style: unlocking needs the passphrase and that file); **disguise mode** (while locked it's a working calculator, with the window and shortcuts renamed; your code then = opens the unlock screen); auto-lock after 15 minutes.
- **Tor, always**: built-in Tor, onion services only, full vanguards, a separate circuit for every unrelated request, no way to connect without Tor. Bridges (Snowflake by default, obfs4, your own) for places where Tor is blocked; dead public bridges are skipped, only the four quickest public obfs4 bridges are kept, and stale bridge memory is cleaned up automatically.
- **Posts and following**: everything stored on Pillars is encrypted; readers need your follow link. Timelines are read from whole "author buckets" shared by many accounts, so a Pillar never learns who you follow. **Approved followers**: a private audience you approve one by one and can remove people from. Discover finds posts by topic without revealing what you read. Follower counts are anonymous. Mute and block stay on your device.
- **Private messages**: end-to-end encrypted, deniable, sender hidden from Pillars, shared mailbox buckets, disappearing after 7 days. Deleting selected messages, whole conversations (optionally on the other side too), room history, or everything (Settings → Privacy).
- **Rooms**: private rooms by link and public rooms listed in Discover; deniable membership; paid rooms (Pass or Membership); moderators named by room-only keys; ask-to-join rooms (requests only the creator and moderators see); leaving rooms; a signed authority log (bans, hidden messages, no back-dated messages after a removal, one agreed message order, a warning if the room's admin key is misused).
- **Photos, videos, files**: cleaned on the device (images re-drawn, video rebuilt with FFmpeg), encrypted, split into identical pieces, spread over at least three Archives with recovery pieces, checked at random times, streamed while downloading.
- **Credits**: quantum-safe anonymous notes (spent with hash-based zero-knowledge proofs against each issuer's signed public list) made of parts from a majority of the established Pillars; no free credits: earned by Archives and Pillars (random checks, weight built over months) or sent by other people in private messages; used for keeping files longer and paid rooms. Credits sent in a message that's never delivered or collected come back to the sender. Proofs are compressed (about 170 KB). Pillar rewards follow a year-long cheater simulation that runs with the tests (`cargo test -p pillar simulation -- --nocapture` prints the table). A Pillar on a server hands its earnings over with `pillar --take-credits <file>` (import in the app: Settings → Credits). `pillar --print-keys` prints a seed's keys for the seed list. Key periods, public supply counts, and payment sizes hidden.
- **High-risk mode**: posts kept out of Discover, random 2–20 minute posting delay, cover traffic, no media cache, no hosting.
- **Windows protections**: screen security against screenshots and Recall, clipboard kept out of history, file dialogs that leave no traces, cloud-folder warnings, no crash reports (including the browser engine's, through `patches/wry`), no form autofill saved, and a refusal to start if a Windows policy tries to change how the browser engine runs.
- **Post-quantum**: private messages and new room keys sealed with hybrid X25519 + ML-KEM-768; an ML-DSA-65 signature inside every post, profile and card, pinned by followers.
- **Sentinel Apps**: small programs that add features to a room, run in a sandbox on every member's device with the same result for everyone (no blockchain). Polls comes with Sentinel. Authors sign their own with `sentinel-cli app-pack --key <file> --wasm <app.wasm> --name <name> --version 1 --out app.sapp`; a room's admin adds it from the file.
- **Several devices**: link codes with a check code; per-device message keys; copies and activity synced between devices.
- **Mixed sending**: two Pillars with random delays (Settings → Privacy, always on in High-risk mode); fixed-size mailbox checks.
- **Android app**: `scripts/build-android.ps1 -Keystore <jks> -PasswordFile <file>` builds a signed APK into `dist/` (needs the Android SDK + NDK, Java and `cargo install tauri-cli`). Tor runs as its own process there too (`sentinel-tor`, shipped as `libsentinel_tor.so`); files are picked and saved through Android's file screens; videos are rebuilt with Media3; updates (`release-pack --product app-android --platform android sentinel.apk=dist/sentinel-android.apk`) go to Android's installer.
- **Linux app**: `bash scripts/build-linux.sh` on Linux or WSL builds a .deb, an AppImage and the static Pillar into `dist/`.
- **Linux Pillar**: `scripts/build-linux-pillar.ps1` builds static `sentinel-pillar-linux-x86_64` and `-arm64` into `dist/` (needs Zig and cargo-zigbuild).
- **Updates**: signed bundles (majority of the release keys in `crates/sentinel-core/data/release_keys.txt`, hybrid Ed25519 + ML-DSA-65), carried by Pillars (`pillar --updates <folder>`) or installed from a file. Release tools: `sentinel-cli release-keygen | release-pack | release-cosign | release-check`.
- **Separate processes**: the account's Tor connection and your own Pillar each run in their own process, apart from the part of the app that holds your keys.
- **Help run Sentinel**: separate switches for running a Pillar or an Archive, each with its risks spelled out before you turn it on (Compute is shown as coming later). Your Pillar runs as its own process, apart from your account.

### Test runs

- **2026-10-08 (later)**: mass deletion over Tor (one message on one side, one on both sides, a room message, everything; nothing came back after a refresh). A credit sent to someone whose app stayed closed came back to the sender by itself (test build, waiting time shortened). Pillar earning live with a test issuer and a sped-up clock: weight built day by day, then 6 quantum-safe parts paid, all found in the issuer's signed list; a real Pillar refused the test issuer's payment. Android emulator: Tor ran as its own process and connected in about a minute and a half; the app's memory dropped from about 670 MB to about 80 MB.

- **2026-10-08**: everything again over Tor: following and posts, private messages both ways, a room with Polls (message, poll, vote seen on both sides). **Quantum-safe credits end to end:** a new Archive was checked and paid by the seed within minutes, its wallet waited for the next signed checkpoint and swapped the note with a zero-knowledge proof, then sent the credit in a private message, and the receiver swapped it into their own wallet (11 minutes). The Android release build (ARM, emulator) connected in 50 seconds with Android backups confirmed off.

- **2026-10-07**: Polls over Tor with three accounts: one asked, the others voted, a member who joined later saw exactly the same result (from the admin's signed snapshot), and nobody could close someone else's poll. The Android release build (ARM, on an emulator) connected in about 30 seconds, joined a room made on a computer and exchanged messages with it. A new room's first message arrives in about 16 seconds.

- **2026-10-04**: a profile with picture and header seen by a follower; deniable first messages and room introductions; messages and rooms over shared mailboxes; a 54 MB video rebuilt by FFmpeg (no encoder, title, GPS or date markers left) and spread evenly over 3 Archives; storage checks passed; free and earned credits; a 1-month pin on 3 Archives; a paid Membership room bought and granted automatically; a removed member could no longer read new messages.
- **Approved followers** (three accounts): the approved follower read an approved-followers post; a follower with only the link could not; after removal, the removed follower could not read the next one but kept what they had already seen.
- **2026-10-05**: with three issuing Pillars and two fresh accounts, free credits came as parts from 2 of the 3 issuers; a 3-credit room pass was paid, every part was redeemed at its own issuer, and the room was granted; a pin on 3 Archives was paid the same way, and every issuer's spent count matched exactly.


## Building and running

**Release builds (anything you share): always use the script.** Compilers record file paths, and on a developer's computer those include the user name. The script removes them from the programs and refuses to finish if any are left:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1
```

This builds the Pillar, the command-line client and the Windows installer (per-user, no admin rights needed; the browser engine's offline installer is bundled, so installing never contacts Microsoft).

**Running a Pillar** (prints its onion address; keep it running):

```bash
./target/release/pillar
```

**Running an Archive** as well (here lending 20 GB; files nobody has fetched for 90 days expire):

```bash
./target/release/pillar --archive-gb 20
```

A Pillar issues credits automatically if its onion address is in the seed list (`crates/sentinel-net/src/seeds.txt`). It prints its credit key when it starts; add that key to its line in the seed list so the app pins it. For a private test network, give every Pillar the same list with `--mints a.onion,b.onion,c.onion`.

**Command-line client** (for testing). Setting it up makes no network connections:

```bash
./target/release/sentinel-cli init
```

Measure Tor speed to a Pillar (uses a throwaway key, never your account):

```bash
./target/release/sentinel-cli bench --pillar <address>.onion
```

Switch to bridges (built in, Snowflake by default):

```bash
./target/release/sentinel-cli mode set tor-bridges
```

Add a private bridge from someone you trust (your own bridges come before the built-in ones):

```bash
./target/release/sentinel-cli bridges add "obfs4 <ip>:<port> <fingerprint> cert=... iat-mode=0"
```

Logging is off by default. `--debug-log` on the Pillar prints Tor's redacted logs to the screen only.

`SENTINEL_PROFILE=<name>` runs a separate local profile (for testing several accounts on one computer).

**Running the seed Pillar on this computer:** double-click `scripts/run-seed.cmd`. It runs a copy of `target/release/pillar.exe` (so builds aren't blocked) with the usual data folder, so it keeps its onion address and credit key. Keep its window open and the computer awake. Don't stop it while cleaning up after tests, and don't leave test Pillars announcing themselves to it (they age out of its list after 3 days).

## Releasing an update

Updates are signed bundles. The app installs one only if a majority of the release keys in `crates/sentinel-core/data/release_keys.txt` signed it (Ed25519 + ML-DSA-65 each) and it's newer than the installed version.

1. Keep each release secret offline (a USB stick). Make one with `sentinel-cli release-keygen <file>` and add the printed line to `release_keys.txt` (that change itself must ship in a release signed by the old keys).
2. Raise the version in `crates/app/Cargo.toml` and `crates/app/tauri.conf.json`, then build with `scripts/build-release.ps1`.
3. Pack the changed files: `sentinel-cli release-pack --secret <file> --version 0.2.0 --notes "What changed" --out app.bin Sentinel.exe=target/release/Sentinel.exe` (add `ffmpeg/<name>=<file>` only if those changed).
4. Other key holders add their signatures: `sentinel-cli release-cosign --secret <file> app.bin`. Check with `sentinel-cli release-check app.bin`.
5. Every Pillar keeps an `updates` folder (in its data folder, or `--updates <folder>`) and passes new releases to other Pillars by itself. Apps take a release only when two Pillars carry it, and offer it after three days.
6. To withdraw a bad release: `sentinel-cli release-revoke --secret <file> --bundle app.bin --out app.revoke` (each key holder, same output file), then put `app.revoke` in a Pillar's update folder.
7. Or hand `app.bin` to people directly (Settings → Connection → *Install from a file…*).

## Speed over Tor (full vanguards on both sides)

| What | Before the circuit pool | After |
|------|------------------------|-------|
| A new private request group | median 57.7 s (either ~6 s or ~60 s) | **median 0.68 s, at most 0.94 s** |
| A new private connection without the pool | 5.6–64 s | 4.8–13.4 s |
| A request on an open connection | median 0.63 s | 0.6–0.9 s |

## A bug we fixed ourselves in a Tor dependency

`saturating-time` 0.5.0, which the Rust version of Tor depends on, searches for the largest and smallest possible time value by halving a step. On Windows, time has 100-nanosecond resolution, so once the step drops below that, the search stops making progress and never ends. In practice, **Tor startup hangs forever at "Looking for a consensus"** with one processor core at 100%.

`patches/saturating-time` treats "no progress" as the end of the search (a two-line change) and adds a Windows test. It's applied through `[patch.crates-io]` in `Cargo.toml`. We keep this fix ourselves, permanently: nothing depends on the Tor project changing anything.
