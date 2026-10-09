<div align="center">

# The Sentinel Protocol

**Say what you think. Nobody needs to know where you are.**

A social network, messenger and group rooms in one app, with Tor built in,<br>run by volunteers instead of a company, and private by design.

Tor built in · No phone number or email · No company servers · Ready for quantum computers

[Get it](#get-it) · [Why it's different](#the-best-of-tor-and-matrix-in-one-app) · [Run a Pillar](#run-a-pillar-the-easy-safe-way-to-help) · [How it works](DESIGN.md) · [Tester guide](TESTER_GUIDE.md)

</div>

---

## What it is

- **A public square:** profiles, posts, photos and videos, following, and a Discover page for finding people and topics. Like Twitter, without the company.
- **A private messenger:** end-to-end encrypted messages only you and the other person can read. Like Signal, without the phone number.
- **Rooms:** group chats, free or paid, private or public, with moderators, ask-to-join and polls.

Everything travels through Tor, everything stored on the network is encrypted, and your account is made on your own device in seconds. No phone number, no email, no sign-up server.

## The best of Tor and Matrix, in one app

Tor hides *where* you are. Matrix-style encryption hides *what* you say. Sentinel builds both in from the start, then goes further, so the network itself learns as little as possible about *who talks to whom*.

| | Tor alone | Matrix alone | **Sentinel** |
|---|:---:|:---:|:---:|
| Hides your internet address from the people and servers you talk to | ✅ | ❌ the server sees it | ✅ |
| End-to-end encrypted messages and group chats | ❌ not a messenger | ✅ | ✅ |
| Servers can't see who messages whom | n/a | ❌ the server sees it | ✅ sealed sender, shared mailboxes |
| Servers can't see who's in a group | n/a | ❌ | ✅ |
| Public posts and following, readable only by people you choose | ❌ | ❌ | ✅ |
| No exit nodes: nothing ever leaves Tor for the open internet | ❌ websites need exits | n/a | ✅ onion services only |
| Messages protected against future quantum computers | ❌ | ❌ | ✅ hybrid ML-KEM |
| Photos and videos cleaned of GPS, device and app traces before sending | ❌ | ❌ | ✅ |
| No company or server that can be shut down or pressured | ✅ | ❌ servers can be | ✅ volunteer Pillars |
| Social network, messenger and rooms in one app | ❌ | ❌ chat only | ✅ |

## Run a Pillar: the easy, safe way to help

The network runs on **Pillars**: computers lent by volunteers that carry encrypted posts and messages. Running one is much simpler, and much safer, than running a Tor relay.

| | Tor relay | Tor exit relay | **Sentinel Pillar** |
|---|:---:|:---:|:---:|
| Your internet address published in a public list | yes | yes | **never**: reachable only as an onion service |
| Strangers' traffic leaves the internet from your connection | no | yes | **never** |
| Can read the messages and private posts it carries | no | sometimes | **never**: they arrive sealed |
| Abuse complaints or legal letters sent to your provider | rare | common | **no**: nobody sees your address |
| Earns you something | no | no | **credits**, paid privately to your Pillar |

Turn it on in the app (Settings → Help run Sentinel), or run the one-file Pillar program on any computer that stays on. A Raspberry Pi is perfect. Add disk space and it becomes an **Archive**, storing encrypted pieces of photos and videos and earning credits every day.

## What makes it private

- **Split knowledge.** No computer in the network ever knows both *where* you are and *who* you are.
- **Sealed everything.** Posts, profiles and messages are encrypted and padded before they leave your device. Pillars store data they can't read.
- **Reading without revealing.** Timelines, Discover and mailboxes are fetched in shared buckets over separate Tor circuits, so nobody learns who you follow, what you read, or how many messages you get.
- **Deniable messages.** The person you talk to knows it's you, but can't prove it to anyone else.
- **Post-quantum.** Messages and room keys use a hybrid of X25519 and ML-KEM-768. Signatures, credits and updates are quantum-safe too.
- **Anonymous credits.** Pay for paid rooms or for keeping files longer with zero-knowledge proofs: nobody can trace who paid whom.
- **Safety built in.** Emergency passphrase (silently erases the real account), disguise mode (the app becomes a working calculator), key files, auto-lock, panic wipe, screen protection, High-risk mode, and recovery words to take your account to a new device.
- **Reliable delivery.** If someone's Pillar is down, your message is handed to another Pillar that keeps trying for a week, so it arrives even after you've gone offline.
- **Kept clean, without spying.** Public posts can be reported to the Pillars that hold them, and room messages to the room's moderators; illegal content is removed by the people who can see it. Private conversations stay private.
- **Updates nobody can hijack.** Releases are signed with post-quantum release keys (a majority must agree once there are several) and must be carried identically by at least two Pillars, so no one can slip a special version to one person.

The details are in [How Sentinel works](DESIGN.md).

## Get it

Download from the **Releases** section of this page. Everything is inside: Tor, the video tools, the browser engine.

| On | Download |
|---|---|
| **Windows 10 or 11** | `sentinel-windows-setup.exe`: installs for your user only, no admin rights needed |
| **Android 7 or newer** | `sentinel-android.apk` |
| **A computer that stays on** | `sentinel-pillar-windows.exe`, `sentinel-pillar-linux-x86_64`, or `sentinel-pillar-linux-arm64` (Raspberry Pi) |

Check your download against `SHA256SUMS.txt` in the same release. The [tester guide](TESTER_GUIDE.md) walks you through the first ten minutes.

## Where it's going

Sentinel works today, end to end, over the real Tor network: accounts, posts, messages, rooms, media, credits, several devices per account and signed updates, on Windows and Android, with Pillars on Windows and Linux.

Next up:

- **More Pillars run by more people.** Every new Pillar makes the network faster and harder to block.
- **An independent security audit**, and builds anyone can reproduce byte for byte.
- **Private fetching (PIR)**, larger encrypted groups, and more Sentinel Apps for rooms.
- **Working through internet shutdowns** over local Wi-Fi, Bluetooth and USB.

## Get involved

- **Run a Pillar.** It's the single biggest help.
- **Try it with friends** and report what breaks, with the connection log from Settings → Connection.
- **Review the code and the design.** Security researchers and cryptographers are especially welcome: [How Sentinel works](DESIGN.md) and the code in [`sentinel-proto/`](sentinel-proto/).

<details>
<summary><b>Building it yourself</b></summary>

<br>

The code lives in [`sentinel-proto/`](sentinel-proto/), and [its README](sentinel-proto/README.md) explains how to build each part. Releases are built with `sentinel-proto/scripts/build-release.ps1`, which strips every local path out of the programs and checks the result.

The app uses FFmpeg to rebuild videos and audio, so a recording can't be traced to the phone or app that made it. FFmpeg is too big for GitHub, so only its fingerprints are kept here. To fetch it, run this from the `sentinel-proto` folder (the release and Linux build scripts do it for you):

```
powershell -ExecutionPolicy Bypass -File scripts\get-ffmpeg.ps1
```

It downloads FFmpeg 8.1 from [BtbN/FFmpeg-Builds](https://github.com/BtbN/FFmpeg-Builds) over HTTPS, checks the published fingerprint, and unpacks it into `vendor/ffmpeg/win64/`. The app only ever runs FFmpeg files matching the fingerprints it was built with. Phones don't need it: they rebuild videos with their own encoders.

</details>

<div align="center">

<br>

*Built for people who need privacy most, so it's private enough for everyone.*

</div>
