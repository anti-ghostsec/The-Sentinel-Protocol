# The Sentinel Protocol, the short version

*A social network and messenger for when being doxxed means a shallow grave.*

Version 0.16. The long, careful version: [How Sentinel works](DESIGN.md).

---

### 0. Elevator Pitch for Cynics

Most decentralized networks are academic exercises, exit scams, or metadata leaks dressed up as freedom. Sentinel is an attempt to build something people can actually use under real pressure:

1. A public timeline (Twitter/X style)  
2. End-to-end encrypted DMs (Signal style)  
3. Encrypted group rooms (without the usual forensic footprint)

There are no corporate masters, no domain names, no registries, no phone numbers, and no exit nodes. Everything moves through onion routing.

Sentinel does **not** claim to defeat a global passive adversary that controls most of the network *and* your device. It raises the cost of linking your identity to your location from protocol traffic alone. One unmasked IP is treated as permanent and catastrophic.

---

### 1. Threat Model

We design for **Adversary A11: the lethal state actor** — unlimited resources, subpoena power, deep packet inspection, and physical coercion.

```
[ A11: Lethal Adversary ]
   ├── Detains contacts and seizes unlocked phones
   ├── Correlates cell-tower data with posting times
   └── Compels ISPs, hosts, and app stores

[ A5: Global Passive Observer ]
   └── End-to-end timing and size correlation

[ A1: Malicious Node Operators ]
   └── Logging, withholding, Sybil attacks
```

**Inviolable rules**
- Every node that is not physically yours is assumed hostile and logging everything. Operator promises mean nothing.
- A single leaked IP linked to an identity is game over. Identities cannot be un-linked once linked.
- The device is the weakest link. Most people are caught by unlocked phones, cloud backups, or their own writing style — not by breaking Tor.

---

### 2. Architecture: Split Knowledge

**No single machine in the network ever learns both who you are and where you are.**

```
[ Client ] ──(Tor / arti onion)──► [ Pillar ] ◄──► [ Archive ]
 (Tor-locked,                  (ciphertext only,     (encrypted
  never falls back)             small cache)          chunks only)
```

- **Client**: Makes zero network calls until you choose a transport mode. Tor-locked by default. If Tor fails, traffic stops.
- **Pillars**: Onion-service relays and small caches. They store only ciphertext and reject plaintext. The long-standing seed Pillars also issue credits; there is no separate "mint" to run.
- **Archives**: Storage nodes that hold encrypted, erasure-coded media chunks. They never receive decryption keys.
- **Bridges**: Pluggable transports (Snowflake, WebTunnel, obfs4) compiled into the binary and checksum-verified before use. Dead public bridges and stale Tor bridge memory are cleaned up by Sentinel itself; nothing waits on upstream Tor fixes.
- **Your account's Tor** runs as its own process behind a password-locked local door; lock or wipe kills it and every file goes at once.
- **Your own Pillar** (optional) runs as a separate process with its own Tor identity. It never touches your account keys, and Archive and Compute are separate opt-ins with their risks spelled out.

---

### 3. How the Features Work

**Identities**
- Created entirely on your device. Keys are locked with Argon2id (256 MiB), and contacts are verified with 60-digit safety numbers.
- An **emergency passphrase** silently nukes the real account and opens an empty decoy. The key file looks identical whether one exists or not, and every unlock takes the same time.
- An optional **key file** (VeraCrypt-style: any file, mixed into the key) makes offline guessing hopeless without it, and nothing shows one is in use. The emergency passphrase works without it.
- **Disguise mode** turns the locked app into a working calculator (window, icon and shortcuts included) until you type your code and press =. It survives wipes, so a wipe doesn't give itself away.
- **Recovery words** (21, on paper) bring the account back on a new device with the same identity, or sign a move to a new key that followers check against a pinned, quantum-safe recovery key.
- **Several devices** share one account: a link code plus a matching check code on both screens. Each device keeps its own passphrase and message keys, and activity syncs between them.
- Auto-lock after 15 minutes (5 in High-risk mode).

**Post-quantum**
Private messages and new room keys are sealed with a hybrid of X25519 and ML-KEM-768, so traffic recorded today stays unreadable to future quantum computers. Every post, profile and card carries an **ML-DSA-65** signature that followers check against a pinned key. Posts, files and backups already use 256-bit symmetric keys.

**Updates**
Signed by a majority of pinned release keys (hybrid Ed25519 + ML-DSA-65). Only newer versions install. They spread from Pillar to Pillar or get handed over as a file. Apps take a release only when two Pillars carry the identical one (no targeted updates), wait three days, and drop any release a majority of keys revokes. On Android, the system installer asks you and only accepts an APK signed like the one you have.

**Mixed sending** (always on in High-risk mode) routes messages through two Pillars with random delays.

**Public feed & follows**  
Following someone gives you a link that contains their feed key. The UI honestly labels this “People with your link” — because anyone who obtains the link can read the content. For a real private audience there are **approved followers**: approved one by one, removable, with a fresh key handed to everyone left after each removal.
Timelines are pulled as whole **author buckets** shared by many accounts, so a Pillar never learns who you follow. Public topics are hashed into broad discovery buckets; clients fetch entire buckets plus random cover buckets over isolated circuits so nodes cannot tell which exact topic you care about. Mute and block live only on your device and tell nobody.

**Direct messages**  
End-to-end encrypted with a Double Ratchet (vodozemac Olm). Sealed sender. Rotating blind mailboxes, filed in shared buckets, so hosts cannot count your messages or tell which ones are yours. Cryptographic deniability: the recipient knows it came from you, but cannot prove it to a third party. Disappearing after 7 days by default, and you can delete selected messages, whole conversations or everything, and ask the other person's app to delete its copy too.

**Rooms**  
Small rooms use sender-key ratchets (Megolm) with deniable membership. Removing someone re-keys the room so they cannot read anything new; new keys go only to members who proved who they are. Paid rooms (one-time Pass or monthly Membership) take anonymous credits. Public rooms list themselves in Discover, signed by the room's own key rather than yours. The creator can name moderators (by a room-only key, never an account) who hide messages, remove people and answer requests. Rooms can be set to ask-to-join: requests are sealed so only the creator and moderators see who asked, and approval sends the room key sealed to the newcomer. Every admin action lives in a signed, chained **authority log**: bans everyone enforces, messages hidden for everyone, re-keys that carry a cut so removed members can't back-date anything, one agreed message order, and a loud warning if the admin key ever signs two histories.

**Sentinel Apps**  
Small programs that add features to a room, like Polls: contracts without a blockchain. Every member's device runs the same code on the same commands in the room's agreed order, inside a sandbox with no network, files or keys, so everyone gets the same result and nobody can fake one. The room's admin adds them and signs daily snapshots so late joiners agree. Apps see members only as a room-only nickname.

**Media**  
Every image is redrawn and every video rebuilt by a bundled, checksum-verified FFmpeg before it leaves the device; EXIF/GPS/device tags die there. (Phones rebuild videos with their own encoders instead. On computers without the FFmpeg files, videos lose their tags but keep their original layout, and the app says so.) Dangerous formats (PDFs, archives) are never auto-opened and carry explicit warnings. Files are encrypted per-file, split into identical pieces, size-padded, erasure-coded across at least three Archives and spot-checked with storage proofs.
On Windows the app blocks screenshots, screen capture, Recall, clipboard history, file-dialog traces, crash dumps and browser autofill, and refuses to start if a Windows policy tries to tamper with its browser engine. Android blocks screenshots and backups. A panic wipe clears keys and local state, including your Pillar's.

---

### 4. Credits (Optional)

The network works completely without credits. There are no free credits: they're earned by running Archives and Pillars (rewards build over months of passing random checks, so fake Pillars earn nothing) or sent by other people.  
Credits are anonymous notes for keeping files longer and joining paid rooms. Each is a secret whose fingerprint sits in an issuer's public list; spending reveals a separate "spent" tag plus a zero-knowledge proof (hash-based, so quantum computers can't forge or trace it) that the note is somewhere in the list, without saying where. Issuers sign checkpoints of their lists every 10 minutes, so one that shows different people different lists gets caught. A credit is made of parts from a majority of the seed Pillars, so no single operator can fake or double-spend one, and tracing one fails even if all of them collude. Keys rotate every 180 days from one pinned key, supply is publicly countable, and the format is ready to become a withdrawable private currency later. Credits sent in a message nobody collects come back to the sender. Pillar rewards were tuned against a year-long simulation of cheaters: keeping only recent data, going offline half the time or dodging checks earns next to nothing. The network works fully without them.

---

### 5. Performance (Realistic)

Tor is not magic. Expect:

| Action              | Typical latency          | Mitigation                          |
|---------------------|--------------------------|-------------------------------------|
| Feed refresh        | a few seconds per Pillar | Whole author buckets per circuit    |
| New circuit         | 0.7 s (pooled) / up to 60 s cold | Pre-warmed pools + hedged connects |
| Large video         | ~0.5–1 MB/s per circuit  | Parallel swarm + progressive play   |

---

### 6. What Sentinel Cannot Protect You From

- A global passive adversary watching most of the internet can still attempt timing correlation.
- Your mobile carrier always knows your approximate physical location.
- A compromised device (malware, seized unlocked phone, cloud sync) defeats everything.
- Your own writing style, photos of places you frequent, and careless contacts.

No software can make you perfectly safe. Sentinel only removes the easy, protocol-level ways of finding you.

---

### Status (October 2026)

**Working in the current prototype (live over Tor: Windows app, Android app, Linux Pillar)**
Tor-locked transport (in its own process, on phones too) with self-healing bridges, blind sharded mailboxes, author buckets, approved followers, Olm/Megolm sessions with deniability, mixed sending, several devices per account, paid rooms, room moderators, ask-to-join rooms, the room authority log, Sentinel Apps (Polls), media sanitisation (phones rebuild video with their own encoders), message deletion, erasure-coded Archives with storage proofs, majority-of-Pillars quantum-safe credits, post-quantum messages and signatures, signed updates spread by Pillars, recovery words, High-risk mode, emergency passphrase, key file, disguise mode, auto-lock, Windows forensic mitigations, path-stripped release builds, an in-memory connection log for testers.

**Still under construction**
Independent seed operators (today: one seed, on one home computer), security audits, formal analysis, reproducible builds, private fetching, large-group tree ratchets, the Linux desktop client, bridges on phones, more Sentinel Apps and payments inside them, faster credit proofs. (No iPhone or Mac app, by decision.)

---

*The protocol is designed so that network traffic alone cannot put you in front of a firing squad. Everything else is still on you.*