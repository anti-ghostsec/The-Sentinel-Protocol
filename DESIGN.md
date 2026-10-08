# How Sentinel works

The complete design of The Sentinel Protocol. The short introduction is in the [README](README.md).

Version 0.16, in plain language: every part says what it does, why, and what it can't protect you from. A short technical reference for people building or auditing it is at the end.

> [!NOTE]
> **Built** means it's in the prototype and has been tested over the real Tor network. **Partly built** means some of it works today. **Planned** means it's designed but not written yet.

### Contents

1. [What Sentinel is](#1-what-sentinel-is)
2. [Who it's for, and who we're protecting them from](#2-who-its-for-and-who-were-protecting-them-from)
3. [The ground rules](#3-the-ground-rules)
4. [How it fits together](#4-how-it-fits-together)
5. [Helping run Sentinel: Pillars, Archives and Compute](#5-helping-run-sentinel-pillars-archives-and-compute)
6. [Your account](#6-your-account)
7. [Connecting through Tor](#7-connecting-through-tor)
8. [High-risk mode](#8-high-risk-mode)
9. [Posting, following and discovering](#9-posting-following-and-discovering)
10. [Private messages](#10-private-messages)
11. [Rooms](#11-rooms)
12. [Photos, videos and files](#12-photos-videos-and-files)
13. [Credits](#13-credits)
14. [Protecting your computer](#14-protecting-your-computer)
15. [Protecting the people who run the network](#15-protecting-the-people-who-run-the-network)
16. [Speed](#16-speed)
17. [What it can't protect you from](#17-what-it-cant-protect-you-from)
18. [Known attacks and what we do about them](#18-known-attacks-and-what-we-do-about-them)
19. [Sentinel Apps (partly built)](#19-sentinel-apps-partly-built)
20. [What's built and what's left](#20-whats-built-and-whats-left)
21. [Technical reference](#21-technical-reference)
22. [Version history](#22-version-history)

---

## 1. What Sentinel is

Sentinel is three things in one app:

- **A public square** like Twitter: profiles, posts, photos and videos, following, and a Discover page for finding new people and topics.
- **A private messenger** like Signal: one-to-one messages that only you and the other person can read.
- **Rooms**: group chats that can be free or paid, private or (later) public.

What makes it different is **how** it works:

- **Nobody owns it.** There is no company server, no domain name and no central database. The network runs on computers lent by volunteers (Pillars and Archives, see section 5). If any of them disappear, are seized or are shut down, the rest keep going.
- **Tor is built in.** Every connection goes through Tor, the same network journalists and activists use to hide where they are. You don't install anything else. The app simply can't connect without Tor.
- **The computers that carry your posts and messages can't read them.** Everything they store is encrypted, and they're designed to learn as little as possible about who talks to whom.
- **No phone number, no email.** You make an account on your own device in seconds.

### What success looks like

1. A Twitter-style network and private chat in one place.
2. Nothing that can be taken down to kill the network or an account.
3. Nobody learns your internet address together with who you are, what you say or who you talk to.
4. A determined attacker can't locate a specific person from how they use the app.
5. It survives hostile governments: blocking, seizures, pressure on volunteers, and internet shutdowns.
6. Install and go: no setup, no servers, no accounts elsewhere.
7. Fast and stable enough to feel normal.

### What Sentinel doesn't try to do

- **Beat an adversary who watches the entire internet and controls most of Tor.** We make that very expensive; we don't claim it's impossible.
- **Hide your phone from your mobile carrier.** Phone companies always know roughly where a phone is. What we can do is make sure they can't connect that location to your Sentinel activity.
- **Stop people from copying what they're allowed to read.** If someone can read your message, they can screenshot it.
- **Guarantee that public posts are deleted everywhere.** Deleting is a request, not a guarantee, once others have copies.
- **Protect a device that's already hacked.** If someone controls your phone or computer, they see what you see.
- **Hide your writing style.** People can sometimes be recognised by how they write.

---

## 2. Who it's for, and who we're protecting them from

Sentinel is built for the hardest case: **someone for whom being identified could mean prison or death.** Journalists, activists, whistleblowers, people in abusive situations, and anyone living under a government that hunts its critics. If it's safe enough for them, it's safe for everyone else.

### Who might be trying to find you

| Who | What they can do |
|-----|------------------|
| **People who run parts of the network** | Run Pillars or Archives themselves, record everything, lie, refuse to pass things along |
| **Your internet provider or Wi-Fi owner** | See that you're online, block or slow connections, inspect traffic |
| **A censoring government** | All of the above, for a whole country: block apps and websites, probe suspicious servers, pressure operators, make the app illegal |
| **Someone hunting one specific person** | Message you, follow you, run many fake nodes, try anything to get your location |
| **Someone who watches huge parts of the internet** | Compare the timing of traffic in different places |
| **Spammers and flooders** | Create fake nodes, fake accounts, spam, and overload |
| **Someone with your device in their hands** | Take your phone or computer, or force you to unlock it |
| **Someone tampering with the app itself** | Swap in a modified app, a bad update or a poisoned library |
| **Courts and police pressure on volunteers** | Subpoenas, raids, blaming hosts for content |
| **Internet shutdowns** | Cut a region off, or split a country from the world |
| **A deadly, patient state** | All of the above combined, plus arresting your contacts and searching their phones, and comparing real-world events with when you post. **Linking an account to a real person may cost that person their life.** |

### Three assumptions we never relax

1. **Every computer except your own is assumed to be hostile and recording everything.** Sentinel must stay private even then. A volunteer promising "I keep no logs" is nice, but we never rely on it.
2. **One slip is forever.** One leaked address, one photo with GPS in it, one seized contact's phone can link you permanently. Once linked, you can't be un-linked. So we design against single mistakes, not averages.
3. **Just using the app can be dangerous.** In some places, being seen using Tor or Sentinel is itself a risk. Hiding *that* you use Sentinel is a goal too (that's what bridges are for, section 7).

### What we protect

Your internet address and physical location · who you know · what you say · when you're online · your account itself · the network staying up.

---

## 3. The ground rules

Every design choice is checked against these:

1. **Split knowledge.** No single computer ever knows both *where you are* (your internet address) and *who you are or what you're doing*.
2. **Data proves itself.** Posts are signed and addressed by their own fingerprint, so a volunteer computer can refuse to pass something along, but can't fake it or change it.
3. **No addresses in data.** Internet addresses never appear in anything that's signed, stored or shown.
4. **Separate everything.** Accounts, contacts, requests and roles are kept apart, so one leak doesn't lead to the next.
5. **Everyone looks the same.** Fixed sizes, padding and normal behaviour, so nobody stands out by their traffic.
6. **Never quietly get less private.** If the private way doesn't work, the app waits and tells you. It never falls back to a less private way on its own.
7. **Cover traffic does real work.** Background "noise" traffic fetches useful things, so privacy costs less.
8. **No off switch.** No key, server or organisation can shut the network down or ban people from it globally.
9. **Don't invent cryptography.** Use well-tested, audited building blocks; check new protocols formally before relying on them.
10. **Strongest privacy wins.** When privacy and convenience conflict, privacy wins, and the app explains the trade-off in plain words.

---

## 4. How it fits together

### The pieces

| Piece | What it is | What it never does |
|-------|-----------|--------------------|
| **The app** | Holds your keys and your data on your own device. Everything is encrypted before it leaves. | Accepts connections from anyone, or stores things for others (unless you choose to, below) |
| **Pillar** | A volunteer computer that carries the network: keeps posts and sealed messages for a while, passes them along, keeps the directory of other Pillars, and (for established Pillars) issues credits. Reachable only as a Tor onion service. | Holds big files; sees what's inside messages; knows anyone's internet address |
| **Archive** | A Pillar that also lends disk space for photos, videos and files, all encrypted. | Reads what it stores (it never gets the keys) |
| **Compute** *(Planned)* | A volunteer computer that lends processing power, for example to convert videos. | |
| **Bridge** | A secret entrance to Tor for people in countries that block it. Run by Tor volunteers. | Appears in any public list |

### The layers, from the bottom up

| Layer | What it handles |
|-------|-----------------|
| Network | Tor, bridges, onion services, finding Pillars |
| Identity | Your keys and account |
| Objects | Everything stored is a sealed, signed, fingerprinted object |
| Structures | Your feed, rooms, mailboxes, the Discover index |
| Encryption | Who can read what: anyone with your link, a room, one person |
| Social | Following, Discover, rooms, profiles |
| Apps *(Planned, section 19)* | Programs people write and share (forums, polls, games, communities), running in a locked-down sandbox on top of everything above |

### Keeping volunteer computers apart from people

- A Pillar's keys are made separately from any account and are never signed by or linked to one.
- **Your account's own Tor connection also runs in a separate process.** The app talks to it through a private door (a local SOCKS port on this computer only, locked with a secret only the app knows, that connects only to Sentinel onion services). The program holding your keys never handles raw network traffic, and locking or wiping the app ends that process, so all its files can be deleted at once.
- When you run a Pillar from the app, it runs as **a separate program in its own process**, with its own Tor identity and connections. It never holds your account's keys, and turning it off ends that process completely. The app never uses your own Pillar as your home Pillar (that would let someone match its online hours to yours).

---

## 5. Helping run Sentinel: Pillars, Archives and Compute

Sentinel has no company servers. It runs on computers lent by people. In **Privacy → Help run Sentinel**, each way to help has its own switch, a plain description, and a list of its risks shown **before** you turn it on. All of them are **off unless you turn them on**, and **all are off in High-risk mode**.

The app never asks or detects what country you're in (that would itself be a leak). It tells you the risks and leaves the decision to you.

### Pillar *(Built)*

**What it does:** while the app is open, your computer keeps other people's public posts and sealed messages for up to 60 days (at most 2 GB) and passes them along over Tor.

**The risks, as the app states them:**
- It stores other people's public posts and sealed messages. Sealed messages can't be read, not even by you.
- It's reachable only through Tor, so your internet address and location stay hidden.
- Someone watching very closely could notice that your Pillar goes offline when you do, and use that to guess it's yours.
- If your computer is taken, it will show that you ran a Pillar.
- **Only do this where it's legal and safe** to use Tor and to keep other people's content.

**Computers only, not phones.** A Pillar is only useful if it's reachable most of the time, and phones aren't: Android pauses apps in the background, phones switch between Wi-Fi and mobile data (which breaks Tor's connections and takes the Pillar offline for minutes), and serving other people's data costs battery and mobile data. It's also riskier for the owner: a phone's Pillar would vanish whenever they go underground or lose signal, so its uptime would trace their daily life, and phones are the first thing taken at a checkpoint or arrest. Phones never offer it, and the app refuses to start one there. (A later "only while charging on Wi-Fi" mode is possible, off by default and never in High-risk mode.) A Raspberry Pi or an old laptop that stays home and stays on is a far better Pillar.

### Credits are issued by Pillars, not by a separate "mint" *(Built)*

There is no separate role to run for credits. The network's **established Pillars** (the seed Pillars that ship with the app, run by its long-standing operators) automatically act as the credit "mints" (section 13). A Pillar you run from the app does not issue credits unless it becomes one of those established Pillars. You never have to set this up.

### Archive *(Built)*

**What it does:** lends disk space (5 GB to 2 TB, your choice) for other people's photos, videos and files. Everything it keeps is encrypted, split into pieces, and spread over several Archives. It earns credits every day (section 13). It runs inside your Pillar, so turning on an Archive turns on your Pillar too. Changes apply at once, without restarting.

**The risks, as the app states them:**
- It keeps encrypted pieces of other people's files. Nobody can read them, including you and anyone who takes your computer, but that also means **you can't check what they are.**
- In some places, keeping data you can't inspect is itself risky. **Only do this where it's legal and safe.**
- Archives are contacted more often than plain Pillars and checked at random times, so their online hours are easier to watch. Your internet address still stays hidden behind Tor.
- It uses the disk space you choose and some bandwidth. Files are spread over several Archives, so nobody loses anything if yours goes away.
- If your computer is taken, it will show that you ran an Archive.

**Also keep my own uploads** (optional, inside the Archive card): your Archive also serves your own files, which makes them faster and longer-lasting. The cost: **anyone who sees your posts learns your Archive's address and can watch when it's online.** Off in High-risk mode.

### Compute *(Planned)*

Lending spare processing power, for example to convert videos for people on slow devices. It's shown in the app as "coming later" and does nothing yet. Before it's built, it will get the same treatment: a plain description, its risks (above all, that the work you run for others must never reveal what it is or who asked for it), and an off-by-default switch.

---

## 6. Your account

### Making an account *(Built)*

- Your account is a cryptographic key made **on your device**. No phone number, no email, no server signs you up.
- The key is locked with your passphrase using a deliberately slow lock (Argon2id with 256 MB of memory), so guessing passphrases is very expensive even with powerful hardware.
- The app can make a strong **7-word passphrase** for you (from a standard 7,776-word list, about 90 bits of strength) and shows how strong yours is. Generated words are shown as a numbered list, and the account isn't created until you tick that you've written them down.
- The locked key file doesn't even say it belongs to Sentinel.

### Profile *(Built)*

A name, a bio (up to 300 characters), a profile picture and a header image. Pictures are **cropped and completely re-drawn on your device** before upload, which removes hidden data like GPS location and camera model. Your profile is encrypted like everything else: only people with your link can read it.

### Checking you're talking to the right person *(Built)*

Every contact has a **safety number** (60 digits). Compare it in person or over another channel; if it matches, nobody is impersonating them.

### Backups, passphrase changes and panic wipe *(Built)*

- **Change passphrase** at any time.
- **Encrypted backup** to a file of your choice. A backup holds your identity, who you follow, your rooms and your credits, but **no message history and no session keys**, so a seized backup doesn't reveal conversations.
- **Panic wipe** deletes the account, its data, the app's browser storage and any extracted helper files from the device.

### Emergency passphrase *(Built)*

For when someone forces you to unlock the app. You set a second, **emergency passphrase** and a name for an empty account. If you type the emergency passphrase at the unlock screen, the app **silently erases your real account** from the device and opens an empty account with that name, so it looks like an ordinary unlock.

- **Nobody can tell whether you've set one.** The key file always has the same size and shape; without an emergency passphrase, that part of the file is random.
- **Timing gives nothing away.** Every unlock checks both passphrases side by side, and a normal unlock also does the same slow work the emergency path spends creating the empty account, so a real unlock and an emergency one take the same time.
- **Nothing is left behind.** Your account's Tor process and your Pillar (if you run one) are stopped first, so every file can be deleted on the spot. Tested: after an emergency unlock, the account folder held only the new empty account's two files.
- The empty account connects the same way your real one did (through bridges if you used them), so it never connects less carefully.
- Honest limits: if someone copied the device's files *before* you used it, they still have the encrypted real account (protected by your real passphrase). Keep an encrypted backup somewhere safe if you want to recover your account afterwards.

### Key file *(Built)*

Like VeraCrypt's keyfiles. You can make unlocking need your passphrase **and** a file: any file you pick (a photo, a document) or a new random one the app makes. Set it when creating the account, or later in Settings → Safety.

- **Brute-force resistant.** The file's contents are mixed into the key that protects your account. Someone who copies the device can't even start guessing passphrases unless they also have the exact file.
- **Invisible.** The account's key file on the device looks exactly the same with or without one. A failed unlock always says "Wrong passphrase or key file", whether or not a key file is used.
- **Only a fingerprint, only in memory.** The app reads the file (the first 1 MiB, like VeraCrypt), keeps a fingerprint of it in memory while unlocked, and never saves anything about it. The file is chosen in a dialog that leaves no "recent files" trace.
- **Your emergency passphrase still works without it.** If someone forces you to unlock, it has to work with whatever they hand you.
- **Rules to keep:** keep the file away from the device (a USB stick, or one photo among many), never edit it (changing a single byte makes it a different key), and keep a copy. Losing it locks you out, and your backups need it too.

*Tested:* with a key file set, the passphrase alone and the passphrase with a different file both failed with the same message; the right pair unlocked. Changing the passphrase kept the key file, removing and re-adding it worked, and the emergency passphrase opened the empty account with no key file.

### Disguise mode *(Built)*

For places where just having the app is dangerous. Turned on in Settings → Safety with a code of 4–12 digits.

- **While locked, Sentinel is a calculator.** It looks and works like one (sums, percentages, the lot). Typing your code and pressing = opens the real unlock screen; any other number just gets calculated.
- The window is called **"Calculator"** with a calculator icon, and the Start menu and desktop shortcuts are renamed to match (using Windows' own calculator icon). An update or reinstall that puts the old shortcut back is disguised again at the next start.
- **It survives wipes.** After a panic wipe or an emergency unlock, the app still opens as a calculator; a disguise that suddenly vanished would give the wipe away.
- The code is kept beside the account as a salted hash (it has to be checked before unlock). It's a door, not a lock: your passphrase is still what protects the account.
- **Honest limits:** Task Manager and Windows' list of installed apps still say The Sentinel Protocol, a taskbar pin keeps its old look (unpin it), and anyone who knows about this disguise knows to try it. It hides Sentinel from a glance, not from a search of the device.

*Tested:* the calculator showed at start and after locking, did sums correctly, a wrong code just calculated, the right code opened the unlock screen, and after a panic wipe the calculator was still there and led to the welcome screen.

### Recovery words and moving to a new key *(Built)*

Every new account comes with **21 recovery words** (Settings → Safety). They're the account's master copy: write them on paper, and the app removes them from the device once you say you have.

- **Lost device:** on a new device, choose "Recover my account with recovery words". The account comes back with the same identity, so everyone who follows you keeps following you. (Posts and messages from the lost device don't come back; a backup does that.)
- **Device taken, or your key may be known:** "Move my account to a new key". Your recovery words sign a notice: "this account now uses key N". Everyone who follows you checks it and switches over by themselves. A thief holding the old key can't stop or fake it, because only the recovery words can sign one, and followers keep the recovery key they first saw (a thief can't swap it).
- **Taken vs lost:** if the device was taken, the move doesn't pass your feed key on (whoever has the device could read it), so private posts need your new follow link. If it was only lost, followers keep reading without doing anything.
- **Private:** the move notice is sealed so only your followers (and you, from your words) can read it. A Pillar can't link your old and new keys.
- **Catching up:** recovering on a new device after a move finds the latest move and picks up the newest key automatically.
- **Quantum-safe:** the recovery key is a hybrid of Ed25519 and ML-DSA-65, so a future quantum computer can't forge a move.
- Nothing on the device has to be re-encrypted when the account moves: the device's own storage key stays the same, only the identity changes.
*Tested over Tor:* an account moved to a new key; its follower switched over by itself and read the next post under the same name; wrong words were refused; recovering from the words on another device caught up with the move automatically.

- **Honest limits:** anyone with your words can take over your account, so keep them hidden. Someone who starts following you *after* a thief changed things trusts what they see first. People you only messaged (but who don't follow you) see the moved account as a new conversation. Older accounts can create recovery words in Settings; their first move switches to a key made from the words.

### Several devices *(Built)*

Use one account on your phone and your computer at the same time (Settings → Safety → Your devices).

- **Linking:** your existing device shows a link code; on the new one, choose "Use my account from another device" and enter it. **Both show the same check code**, and you allow it on the existing device. Someone who glimpsed the code and raced to use it would get a different check code. The account then travels to the new device sealed post-quantum: your identity, follows, rooms, approved followers, hidden people, topics and settings.
- **Never copied:** credits (they could be spent twice) and old message history.
- **Each device has its own passphrase and its own message keys.** People who message you send to every one of your devices; if they don't know a new one yet, your other device passes the message on privately. What you send from one device shows up on the others, and so do your posts, follows, rooms you join and people you hide.
- **Room admin rights stay on the device that made the room** (two devices writing one room's rulebook would split it).
- **Removing a device** stops sending to it. It still holds your account key, so to cut a lost or taken device off completely, also move your account to a new key with your recovery words.

*Tested over Tor:* a second device was linked (both showed the same check code) and became the account; a message to the account reached both devices; a reply from the new device reached the sender and showed as sent on the first device; a post from the first device appeared on the second as its own.

### Planned

- Optional recovery through trusted friends (never in High-risk mode: friends can be arrested).

---

## 7. Connecting through Tor

### Tor is built in, and it's the only way *(Built)*

- The app contains its own Tor (arti, the Rust version of Tor). Nothing else to install.
- **Every** connection goes to a Tor onion service. There are no "exit" connections to the normal internet, so nobody at the edge of Tor sees what you do.
- **Tor-lock:** an account can never connect without Tor, even if Tor fails. If Tor isn't working, the app waits and tells you. There is no "direct" mode at all.
- **First launch is silent:** the app makes no network connections until you've made your account and chosen how to connect.
- Full **vanguards** are always on. They protect against a known class of attacks that try to find the real location of onion services and their users.
- Every unrelated request gets **its own Tor circuit**, so the computers you talk to can't link your requests together.

### When Tor is blocked or dangerous: bridges *(Built)*

- **Bridges** disguise the fact that you're using Tor. Built in: **Snowflake** (the default, looks like a video call), **obfs4** and **WebTunnel** (looks like an ordinary website). You can also paste private bridge addresses given to you by someone you trust.
- The helper program for bridges is stored under a neutral name, checked against a known fingerprint before every use, and **deleted when you're not in bridge mode.**
- **Fails closed:** if your bridges don't work, the app does not fall back to normal Tor (which would show your provider that you use Tor). It waits and tells you.
- **Dead bridges are skipped.** Tor only ever tries two bridges at a time and remembers them, so one dead public bridge could stall bridge mode for good. When bridge mode hasn't worked in the last day, the app checks which of the **built-in, public** bridges accept a connection and gives Tor only those. (It doesn't check at every start: probing every public bridge each time is a pattern a censor could notice.) Private bridges you added yourself are never checked this way (an extra connection to a private bridge is a needless signal).
- **Stale bridge memory is cleaned up.** Tor's saved list can keep bridges that are no longer configured, and marks bridges "unlisted" when it once failed to reach them; both made bridge mode fail within seconds in testing. Before each start, the app keeps only the bridges configured now and clears that stale mark. When bridges change, the learned circuit timeout is reset too (a timeout learned over obfs4 kills every circuit over the slower Snowflake). And if bridge mode hasn't connected successfully within a day, the cached directory is discarded: otherwise Tor starts from an expired directory, says it is ready before the bridges are usable, and every connection fails at once.
- **meek isn't offered:** Tor's built-in meek bridge has no identity fingerprint, which the Rust version of Tor rightly requires, and it didn't respond in testing. Snowflake (default), obfs4 and WebTunnel cover the same need.
- Bridge mode keeps completely separate Tor state from normal mode.

### Finding Pillars *(Built)*

The app ships with a few **seed Pillars** and learns about the rest from them. New Pillars announce themselves with a small proof of work, and are only listed after they're checked to actually answer. Live Pillars announce themselves again every 6 hours, and **any Pillar or Archive not seen for 3 days drops off the lists** (each entry keeps only the day it was last seen), so gone Pillars aren't handed to new apps.

Your app picks its Pillars automatically; you never type addresses. It starts as soon as **one** Pillar answers, looks for a backup for one more short round, and finds one later while in use if needed. (Before this, an app waiting for a second Pillar could sit at "Finding Pillars" for a very long time when the list held gone Pillars; it happened in testing.) If the starting Pillars don't answer, the connecting screen says so and lets you paste the address of a Pillar someone you trust runs; there's also a manual setting under Advanced.

**Connection log (Built).** Settings → Connection, and the connecting screen, show what Tor and Sentinel did lately (finding Pillars, sending, receiving), with a button to copy it for whoever is helping you. It's kept in memory only, never written to disk, with addresses blanked out by Tor's own safe logging, and holds no account, messages or IP address.

### Planned

- **Private fetching** (PIR) for mailboxes and author buckets. (Mixed sending is built: section 10.)
- More ways to disguise traffic, and ways to hand out bridges person to person.
- Running over local Wi-Fi or Bluetooth when the internet is shut down, and passing signed bundles by USB stick.
- Using an existing Tor app (like Orbot or Tails) instead of the built-in one.

---

## 8. High-risk mode

Most real-world unmaskings don't come from breaking Tor. They come from **devices, contacts, content and timing.** High-risk mode is one switch that hardens all of those.

### What it does today *(Built)*

- **Keeps your posts out of Discover.**
- **Stops follow notices** (the anonymous signal that adds to someone's follower count).
- **Delays your posts by a random 2 to 20 minutes**, so "posted right after something happened" is harder to match to you.
- **Adds background cover traffic**, so bursts of activity don't show when you read or post.
- **Never keeps viewed photos and videos on disk.**
- **Loads large media only when you press play.**
- **Turns off running a Pillar or an Archive** (their online hours could be matched to yours).
- **Locks after 5 minutes** without use instead of 15.

### Planned for High-risk mode

Forcing bridges by default, the mix network for all messages, coarser timestamps, shorter disappearing-message timers, blurring faces and text in photos, a "one identity per purpose" rule, and safe-download guidance (getting the app from somewhere not tied to your real name).

### Advice the app gives (plain words)

- Never use the same account anywhere you're known by your real name.
- Don't post things only you could know, or photos of places you go.
- A contact's seized phone can reveal you and your messages. Disappearing messages limit that.
- No software can make you perfectly safe. This mode reduces the ways you can be found.

---

## 9. Posting, following and discovering

### Posts are sealed *(Built)*

Every post, profile and contact card is a **sealed object**: encrypted, padded to a standard size, and signed by its author so Pillars can reject forgeries and spam. **Pillars refuse anything that isn't sealed.** A Pillar sees only which account posted, which Discover buckets the post belongs to, and scrambled data.

Times on posts are rounded to the minute, and post IDs are random, so they don't leak exact timing.

### Reading your timeline without revealing who you follow *(Built)*

Every Pillar also files each post under one of 256 **author buckets**, based on who wrote it. To refresh your timeline, your app downloads **whole buckets** (posts included), never one account's list, and keeps only what it can verify and decrypt. Each bucket comes over its own circuit, in random order, with an extra random "cover" bucket when buckets are split. The Pillar learns "someone downloaded bucket 7", which holds many authors, never which accounts you follow.

Your app picks how finely to split buckets from its own download sizes, never from anything a Pillar claims. Its reading position is rounded so a returning reader doesn't stand out. A new follow reads that bucket from the start once, to catch up, and the cover bucket is read from the start at the same time, so a full read doesn't point to a new follow.

### Following: "people with your link" *(Built)*

You share a **follow link**. It carries the key that unlocks your posts. Anyone who has your link can read your posts; nobody else can, including the Pillars storing them. The app calls this **"People with your link"** and never calls it private, because a link can be passed on. To lock out everyone, you change your key and share a new link.

### Approved followers *(Built)*

For things you only want certain people to see. Someone who follows you can **ask to be approved** (from your profile); the request arrives as an encrypted message. If you approve, your app sends them the key for your "Approved followers" posts, in the same encrypted chat.

- In the composer, the audience button cycles: **People with your link → Discoverable → Approved followers.**
- An approved-followers post is sealed only for that key: people who merely have your link can't read it, and neither can Pillars. All sealed posts look alike, so nobody can tell which audience a post had.
- **Removing** someone gives everyone else a new key; the removed person can't read anything new (they keep what they already saw).
- Your app accepts such a key only from someone you follow and asked, so nobody can push keys at you to mark what you read.

### Discover *(Built)*

- When you post, you can choose to make a post **discoverable** and give it up to 3 topics (like `technology/robotics`). Strangers can then find it.
- To protect readers, topics are grouped into **64 buckets**. When you browse a topic, your app downloads its whole bucket plus extra random buckets as cover, each over its own circuit. A Pillar learns "someone fetched buckets 7, 19 and 40", never which topic you care about. Ranking happens on your device.
- Discoverable posts are encrypted under keys any Sentinel app can work out. That protects hosts from casual scanning, but **a public post can't be secret from the public**, and the app is honest about that.
- Discover is off for your posts in High-risk mode: a niche topic plus a posting time can point to a person.

### Follower counts without revealing followers *(Built)*

Following someone sends their Pillar an **anonymous follow notice**: a token that's the same each time for that one pair (so it can be counted once and withdrawn on unfollow) but can't be linked to the follower or across accounts. Each notice costs a little computing work, so faking thousands is expensive. Pillars publish only the count. You can hide your own count. High-risk mode sends no notices.

### Muting and blocking *(Built)*

**Mute** hides someone's posts. **Block** hides them everywhere and drops their messages unread. Both lists stay on your device, and nobody is ever told, so blocking someone can't reveal anything to them.

### Planned

Custom feeds anyone can publish, anonymous "boosts" into Discover, competing trend lists, people suggestions computed on your device, search, labels for spam and abuse, and private fetching (PIR) so even buckets reveal nothing.

---

## 10. Private messages

### How they work *(Built)*

- **End-to-end encrypted** with Olm (the Double Ratchet design used by Signal and Matrix): only you and the other person can read them, and old messages stay safe even if a key is stolen later.
- **Sealed sender:** the Pillar holding a message can't see who sent it.
- **Rotating mailboxes:** your mailbox address changes every day, and only you hold the key that lets you list it, so someone with your link can't count how many messages you get.
- **Shared mailbox buckets:** messages are filed under a short prefix shared by many people. When you check your mail, you download the whole bucket and your app quietly picks out what's yours. Your app decides how big the bucket is from what it observes, never trusting the Pillar's word for it. Each bucket is fetched over its own circuit.
- **Deniable:** messages are authenticated in a way that convinces the person you're talking to, but **proves nothing to anyone else.** Even your first message, which introduces you, uses a code only the recipient could also have made.
- **Disappearing messages** are on by default: messages are deleted from both sides after 7 days. (Honest limit: a modified app could ignore that.)
- **Deleting messages yourself** *(Built)*: in a conversation, *Select* lets you pick messages (or *Delete all*), and "Also ask their app to delete them" sends a request that the other person's app carries out. In a room, *Select* deletes messages on your devices (only the room's admin and moderators can hide them for everyone). Settings → Privacy → *Delete all messages* clears every conversation and room at once. Your other devices delete the same messages. Deleting asks twice. (Honest limit: asking the other app is a request; a modified app or a screenshot can't be undone.) *Tested over Tor:* deleting one message only on one side, one on both sides (gone from the other person's app within a minute), one room message, and everything; nothing came back after a refresh.
- Replays and duplicates are recognised and dropped.

### Protection against future quantum computers *(Built)*

Someone could record encrypted traffic today and keep it until a quantum computer can break it ("harvest now, decrypt later"). The first such machines will likely belong to the agencies most of our users fear, so Sentinel doesn't wait.

- **Every private message** is sealed for the recipient's mailbox with a **hybrid** of X25519 and **ML-KEM-768** (the NIST post-quantum standard). To read a recording, an attacker must break both. Contact cards carry the mailbox's ML-KEM key, which changes every 30 days.
- **New room keys** (when someone is removed, a membership renews, or someone is let in) are sealed the same way to each member's room-only ML-KEM key, which every member announces when they join.
- Older apps without these keys still work; they just get the classical protection until they update.
- The rest was already quantum-safe: posts, room messages, files and backups use 256-bit symmetric keys (XChaCha20-Poly1305, BLAKE3, Argon2id), which quantum computers don't meaningfully weaken.

*Tested over Tor with three people:* join answers, moderator keys and a removal's new room key were all sealed post-quantum and opened by the right people only (the removed person couldn't read on); private messages went both ways through the hybrid sealing.

What isn't post-quantum yet is listed in section 17.

### Mixed sending *(Built)*

Tor hides who you are, but someone able to watch a large part of the internet could match the moment you send something with the moment it lands in a mailbox. With **Mix my messages** (Settings → Privacy; always on in High-risk mode):

- Each message and room post travels through **two other Pillars**, chosen at random, and **each holds it for a random time** (usually a minute or two, at most ten) before passing it on. It's deposited minutes later, by a Pillar that isn't you, among everyone else's mixed messages.
- Every hop is sealed to that Pillar's own key (X25519 + ML-KEM-768): the first Pillar doesn't see where it's going, the second doesn't see where it came from, and packets are padded to the same size.
- Pillars drop replayed packets and keep only a bounded number waiting.
- Honest limits: messages arrive later; if a mixing Pillar goes offline while holding a message, it retries for about an hour and then the message is lost (your app shows it as sent once the first Pillar took it).

*Tested over Tor with three Pillars:* a message sent with mixing on was taken by the first mixing Pillar, passed through a second, and reached the recipient minutes later.

**Fixed-size mailbox checks:** whenever your app checks its mailboxes, it asks for a padded, fixed number of buckets, so a Pillar can't count how many inboxes and rooms you have.

### Planned

Per-contact mailboxes on separate Pillars for High-risk users; private information retrieval (PIR) once Pillars hold copies of the same data.

---

## 11. Rooms

### Rooms today *(Built)*

- **Private rooms** joined by invite link. Messages are encrypted with Megolm (group encryption from Matrix) and stored as sealed blobs in daily-changing mailboxes, so Pillars can't tell which room a message belongs to, who sent it, or who's in it.
- **Deniable membership:** members introduce themselves to each other with codes that convince other members but prove nothing to outsiders. New members are marked "unverified" until they've proven who they are.
- The sender's identity travels **inside** the encrypted, signed message, so nobody can make someone else's messages look like theirs.
- Room name and settings are signed by a **room-only admin key** (not anyone's account), so only the admin can change them.
- **Paid rooms:** a **Pass** (one-time price) or a **Membership** (monthly), paid with anonymous credits (section 13). The creator's app checks the payment and sends the invite automatically. It only accepts an invite from the creator you actually paid, so nobody can pull you into a room they control.
- **Removing someone** (or a lapsed membership): the room gets new keys, sent only to remaining members who have **proven** their identity. Removed people can't read anything new. (Honest limit: they keep what they already read.)

### The room's rulebook: the authority log *(Built)*

Every admin action in a room is an entry in one chain: numbered, pointing at the entry before it, and signed with the room's admin key. Every member applies the entries in the same order, so everyone ends up with the same room.

- **Daily checkpoints** carry the room's full state (name, settings, bans, hidden messages), so late joiners and people back from a long absence catch up without the whole history.
- **Bans** are visible to every member: a banned person's introductions and messages are refused by everyone, not just the admin.
- **Hide a message:** the room's creator can hide any message for everyone.
- **No back-dated messages:** when someone is removed, the new room key comes with a "cut", the last message the admin had seen from each person. Anything later "from before" the removal is dropped by everyone.
- **One agreed order:** messages carry a counter, and every member sorts them the same way. Sentinel Apps (section 19) build on this.
- **Stolen admin key warning:** if the admin key ever signs two different versions of the same entry, every member sees a warning.

*Tested over Tor with three people:* all three saw the same order; a hidden message disappeared for everyone; after a removal, the removed person's new messages reached nobody and they couldn't read new ones, while the remaining member moved to the new key. Two delivery bugs this test found are fixed (a re-key could be held back a whole day, and a member could skip the messages sent just before a re-key arrived).

Still needed: **formal analysis** of these rules (the same requirement as for the rest of the room protocol).

### Moderators *(Built)*

The room's creator can make any member a **moderator**. Moderators can hide messages, remove people and answer requests to join.

- **Named by a room-only key, never an account.** The rulebook lists each moderator by the key they use in this room only, and gives them a separate moderator key (sealed so only they can open it). A copy of the rulebook doesn't prove which account was a moderator.
- **Everyone applies their actions at once.** A moderator's hide or removal is signed with their moderator key; members check it against the current list in the rulebook. When the creator's app sees a removal, it finishes it with a new room key, so the removed person can't read anything new.
- **Limits:** only the creator chooses moderators and changes keys. Moderators can't remove each other or the creator (if one tries, the creator's app undoes it for everyone). Up to 20 per room.
- **Losing the role:** when the creator takes it away (or removes them), their moderator key stops being accepted by everyone.

### Rooms that need approval to join *(Built)*

A free room can be set to **ask to join**. Instead of an invite link holding the room key, the creator and moderators share an **ask link** that never holds it.

- Someone with the ask link sends a request: their name, handle and an optional note. It's sealed so **only the creator and moderators** can read it; other members never see who asked.
- Names in requests aren't proven (a signature would be lasting proof that someone asked). Once let in, the person's introduction to the room proves who they are, and unproven members are marked as such.
- **Letting someone in** sends the room key sealed to a key the requester made just for this room, into a mailbox only they read. **Turning someone down** tells them so. Other moderators see that the request was answered.
- When a moderator loses the role, the room gets a new ask link (they knew the old one).
- **Honest limit:** members already hold the room key, so a member could still pass it on. Approval keeps strangers out; it can't stop members who choose to leak.
- Public rooms can need approval too: their Discover listing then carries the ask link.

*Tested over Tor with three people:* the creator let one person in and made them a moderator; the moderator let a second person in (the creator's list cleared on its own), hid their message and removed them; the creator's app finished the removal with a new key, and only the remaining member read the next message. Members couldn't get a link to share, and a paid room couldn't be set to ask-to-join.

### Leaving a room *(Built)*

Leaving deletes the room, its keys and its messages from your device. Other members aren't told and keep what you posted. If the creator leaves, nobody can remove people, choose moderators or change the key again; the app warns first.

### Public rooms in Discover *(Built)*

A room created as **Public** gets a short description and 1–3 topics, and its listing appears in Discover for people who follow those topics (and in the "recent" mix).

- **The listing is signed with the room's own key, not your account**, so listing a room doesn't publicly tie it to you. Exception, stated in the app: a *paid* room's listing has to include your follow link so people can pay you, which ties that room to your account.
- Listings travel exactly like discoverable posts: filed in topic buckets, fetched in whole buckets with cover buckets, so nobody learns which topics you browse.
- Every listing is checked: its join link must be for the very room whose key signed it, so nobody can list someone else's room under a fake name.
- **Honest label:** a free public room can be read by anyone who finds it, including who's in it. The app says so before you join.

### Planned

Group encryption built for very large rooms (MLS-style), once it's been formally analysed.

---

## 12. Photos, videos and files

### Cleaning before anything leaves your device *(Built)*

- **Images** are re-drawn from scratch, which removes GPS, camera model, times and hidden data.
- **Videos and audio** are rebuilt by a built-in, fingerprint-checked copy of FFmpeg: re-encoded up to 1 GB (larger files are re-packaged), with metadata, chapters and hidden encoder notes removed, and output byte-for-byte reproducible. FFmpeg is locked down so a booby-trapped file can't make it reach the internet or read other files.
- **On phones,** videos and audio are rebuilt by the phone's own encoders (Android's Media3) into a fresh MP4, then cleaned of any metadata left, like any MP4.
- Other formats are cleaned in place where possible (MP4, MOV, M4A, WebM, MKV, MP3, FLAC, WAV).
- Files that can't be cleaned safely (zip archives, documents, some formats) show a clear warning to both sender and reader that they may contain names, file paths, dates or even malware. They're never opened automatically.
- File names shown to readers are neutral ("video.mp4") unless the sender edits them.

### Sending and storing *(Built)*

- Small images, GIFs and short videos (up to 25 MB) appear right in the timeline.
- Every file is encrypted with **its own random key** (never one derived from the content, which would let a censor recognise a known leaked file), split into **identical 1 MB pieces**, and the number of pieces is **padded** so the exact size doesn't give the file away.
- Large files are **spread over at least three Archives with spare recovery pieces** (Reed-Solomon erasure coding), so any one Archive can vanish without losing anything. Readers rebuild missing pieces and re-upload them.
- **Storage checks:** your app keeps single-use challenges for every file and, at random times over separate circuits, asks Archives to prove they still hold the pieces. Archives that fail stop getting new files.
- Video plays while it downloads. Saving goes to your Downloads folder by default, with a warning if the folder syncs to a cloud service.
- Free storage lasts **90 days without anyone fetching it**; popular files stay alive on their own. To keep a file longer, anyone who can see it can **pin** it with credits (section 13).

### Honest expectations

Tor is slower than the normal internet: a few hundred KB to a few MB per second. Big videos are a background experience. The app will **never** speed things up by leaving Tor, sharing circuits or weakening isolation.

---

## 13. Credits

Credits are Sentinel's anonymous tokens. You use them to keep files longer and to join paid rooms. **Everything important in Sentinel works without them**: posting, following, messaging, free rooms, Discover and hosting never cost credits.

### Getting credits *(Built)*

- **No free credits.** Credits come only from **work** (running an Archive or a Pillar) or from **other people** (someone paying or sending you credits). Earlier versions gave out free credits for a little computer work; that was removed, because anyone with enough computers could have printed as many as they liked.
- **Sent to you:** anyone can send you credits in a private message (*Send credits* in the conversation). They travel inside the end-to-end encrypted message, and your app swaps them for your own at once, so the sender can't spend them again. **Credits never get lost in the post:** if a message carrying credits still hasn't been delivered after a day, the sender's app cancels it and takes the credits back; if it was delivered but never collected (the other person never opened the app), the sender's app takes them back after 8 days. If the other person did collect them, the issuer refuses, which confirms they arrived. *Tested over Tor* (with the waiting time shortened in a test build): a credit sent to someone whose app stayed closed came back to the sender by itself.
- **Earned:** Archives earn credits every day for proving they really store data. The network's established Pillars place regenerable test data on each Archive, check it at random times over separate circuits, and pay Archives that keep passing. Payment goes to the Archive's own onion address, so only the person running it receives it, and the payer never learns who that is.
- **From others:** when someone pays you (for a room, say), your app immediately swaps their credits for fresh ones of your own, so they can't spend them again.
- **A short wait for new credits:** a credit can be spent once its issuer has signed a checkpoint that includes it (every 10 minutes, see below), so a payment made with brand-new credits can take up to 10 minutes to go through.

### Why nobody can trace them, even with a quantum computer *(Built)*

Think of each credit as a **sealed envelope in a public pile**:

1. Your app makes a random secret, and gives the issuing Pillar only a **fingerprint** of it (a hash). The issuer adds the fingerprint to its **public list** of credits. The fingerprint looks like random noise and says nothing about you.
2. To spend the credit, your app reveals a **different** fingerprint of the same secret (its "spent tag") and a **zero-knowledge proof** that says: *"this spent tag belongs to one of the credits in your list, and I know its secret"*, without saying **which** one.
3. The issuer checks the proof and records the spent tag, so the credit can't be spent twice. It **can't tell which credit in its list was spent**, so it can't connect the spending to when, or to whom, the credit was issued.

There are no accounts, no balances on any server, and no record of who paid whom.

**Why this is safe against quantum computers:** the proof (a zero-knowledge proof built with Plonky2, using only the Poseidon hash function) and the fingerprints rest on **hash functions alone**. Quantum computers break the maths behind most of today's signatures (elliptic curves, factoring), but against hash functions they only gain a limited speed-up. Earlier versions of Sentinel used blind signatures on an elliptic curve: their privacy was already safe, but a quantum computer could have worked out an issuer's secret key and printed credits. Old credits are traded in for the new kind automatically, and the old kind is no longer issued.

**Signed checkpoints stop issuers from tagging people.** A dishonest issuer might try to show you a list of your own, so that a proof against that list gives you away. So every 10 minutes the issuer signs a **checkpoint** of its list (its size and a fingerprint of the whole list) with its own quantum-safe key (Ed25519 + ML-DSA-65), and only accepts proofs against checkpoints. Your app checks that the list it downloaded matches the checkpoint, and remembers checkpoints it has seen: two signed checkpoints that disagree are **proof the issuer cheated**, and the app stops using that issuer. Lists are downloaded in fixed pages (the same requests from everyone), on a different connection from the spend.

### No single issuer can cheat *(Built)*

A credit is made of **parts from a majority of the network's established Pillars** (for example 2 of 3, or 3 of 5). Each part is signed separately, and each issuer only ever sees its own part. So:

- **Faking or double-spending a credit** needs a majority of issuers to cheat together.
- **Tracing a credit** is impossible even if *all* of them work together, because every part is spent with its own zero-knowledge proof.

Your wallet holds parts and assembles whole credits when you spend.

### Built so it can become a real currency later *(Built)*

The token format is already what a withdrawable private currency needs, so a future move wouldn't change what's in people's wallets:

- **Bearer tokens, one unit each.** Every token is worth exactly one, so amounts never mark a token.
- **Versioned format** with a field for future changes.
- **Key periods (epochs) of 180 days.** Each issuer's key changes every period, but every period's key is **mathematically derived from the one published key** that ships with the app. So rotating keys never gives an issuer a chance to hand you a special key. Tokens can be spent in their own period and the next; your app refreshes older ones automatically.
- **Bounded spent lists.** Issuers only keep spent serials for periods that can still be spent, so the lists don't grow forever.
- **Public supply counts.** Each issuer publishes, per period, how many tokens it issued and how many were spent, so anyone can check the total supply without seeing a single token.
- **Pinned keys.** Issuer keys (and the fingerprints of their checkpoint keys) are listed in the app's seed list, or failing that, kept from the first time they're seen.
- **Anyone can check a spend.** A spend proof is checked against the issuer's *public* list, with no secret key, so a future ledger could verify credits without asking the issuers.
- **Amounts don't stand out.** When credits are redeemed, it's done in small batches of random size, each over its own circuit, so an issuer sees lots of small swaps, not "a payment of 37".

**What a withdrawal would add (Planned, research):** a ledger, and a bridge where a majority of issuers jointly retire credits and release the same value on that ledger (and the reverse for deposits). Because spend proofs are checked against public lists, such a ledger could verify credits itself. Before any of this: formal analysis, independent audits, and legal review, because money brings regulation and new kinds of tracking.

### Spending *(Built)*

- **Pinning:** 1 credit per gigabyte per month, per Archive, to keep a file past the free 90 days.
- **Paid rooms:** a Pass or a monthly Membership (section 11).

*Planned:* capped, clearly labelled boosts in Discover (nobody can buy their way to the top), and earning for running Pillars and other useful work (below).

### Earning for running Pillars *(Built)*

Paying for plain uptime is easy to cheat: anyone can start a thousand Pillars. Rewards for Pillars are designed so that honest, long-term, small-scale operators win, and fake or rented-for-a-week Pillars lose:

- **Trust that takes months to build and weeks to lose.** A Pillar's reward weight grows slowly the longer it keeps passing checks (most of it after about four months) and falls much faster when it stops. Spinning up many new Pillars earns little for months.
- **Random checks, not self-reporting.** Issuers test each Pillar about 36 times a day at random moments over separate circuits: does it answer, and does it still hold and serve sealed test items the issuer stored there earlier? Each test item is asked for again at a **random age of 1 to 30 days**, so keeping only recent data fails. Test items come from throwaway keys and look like anyone's post, so a Pillar can't keep only them. A test item it won't answer for (dropping the connection instead) stays due, and counts as missing at the end of a day the Pillar was otherwise answering.
- **Judged by the day, not the single check.** Tor drops some connections, so a day counts as good when at least 70% of its checks pass. Pay follows weight **times availability** (the share of checks passed over about two weeks), so being online 85% of the time earns at most 85%, never more.
- **Fair to people with bad luck, hard on patterns.** A single bad day costs about two days of building; three in a week cost more; five in two weeks cost a lot. A missing test item isn't bad luck (the Pillar answered but had thrown it away) and costs a lot at once. So an attacker can't get an honest Pillar punished much by disrupting it now and then.
- **Shared rewards, smoothly shrinking.** Each issuer shares 24 credit parts a day among all Pillars in proportion to weight (at most 3 per Pillar a day), and that amount shrinks slowly over the years (about half after two years and nine months), with no sudden halvings. Fractions carry over, so with hundreds of Pillars each still earns its share. **Pillars younger than 90 days share at most a quarter of the pool between them**, so a wave of new Pillars can't take it over quickly. A whole credit needs parts from a majority of issuers, so a Pillar only earns whole credits if most issuers agree it's doing its job.
- **Paid to the Pillar's own onion address,** as notes only its operator holds, the same way Archives are paid, so the issuer learns which Pillar earned, never who runs it. A Pillar run from the app pays into the app's wallet by itself; a Pillar on a server keeps its earnings until its operator runs `pillar --take-credits <file>` and imports the file in the app (Settings → Credits), which swaps them at once.
- **Compute volunteers** will be paid the same way once Compute exists (section 5). The payment side is ready; what's missing is Compute itself, and a way to check its work.
- **Simulated against cheaters** (a year, 36 checks a day, a test that runs with every build). Compared with an honest Pillar (100%):

  | Strategy | Earns |
  |---|---|
  | Honest, but on bad Tor (15% of checks fail) | 86% |
  | Honest, down 3 days a month | 61% |
  | Honest, but attacked 1 day a week / 2 days a week | 76% / 58% |
  | Online only 85% of each day | 70% |
  | Runs 10 days, off 10 days | 7% |
  | Keeps only 25 / 14 / 3 days of data | 34% / 10% / 3% |
  | Keeps 3 days and dodges the checks | 3% |
  | Keeps 3 days and starts over under a new address monthly | 10% |

  Sixty Pillars started together took 19% of the pool in their first month (capped at a quarter), and never more than the pool is paid out.
- **Tested live over Tor** with a sped-up clock (a "day" of 90 seconds, test builds only): an issuer checked a new Pillar, its weight built day by day, and once it crossed the threshold the issuer paid it 6 quantum-safe credit parts over two days, all found in the issuer's signed list. A real Pillar on the network refused the test issuer's payment, as it should (only listed issuers can pay).
- **What it can't tell apart:** many Pillars run by one person on one computer each earn like separate people once they've run for months. It can't inflate the money supply (the pool is fixed), only take a bigger share of it, and only by keeping every one of them online and storing for months.

### Limits, honestly

- Today the network has **one** seed Pillar, so it has one issuer. The design needs **at least three independent operators** before credits are trustworthy.
- Issuers learn that *someone* swapped credits at a given time, and which Archive or Pillar earned rewards. They never learn who.
- On a phone (which can't run an Archive or a Pillar), credits come only from other people.
- If you restore an old backup, credits you've spent since then won't work again.
- Spending takes a moment: each proof (up to 4 credit parts) is about 170 KB (compressed) and takes a second or two to make on a computer, longer on a phone. The proof machinery is prepared in the background when the app starts, so the first payment doesn't wait for it. (A newer, about 30 times faster proof mode was measured and rejected: its hiding can't be made strong enough yet, and could reveal which credit was spent.)
- The proof system's security is *conjectured* at about 128 bits (the usual assumptions behind this kind of proof); against a quantum computer, the hash-based parts keep roughly two thirds of that. The proof library is a maintained fork of Plonky2; neither it nor Sentinel's use of it has been independently audited.

---

## 14. Protecting your computer

Most people are caught through their devices, so Sentinel works hard on the computer itself. *(All Built on Windows.)*

- **Everything on disk is encrypted** with a key from your passphrase.
- **Locks when you step away:** after 15 minutes without use (5 in High-risk mode), the app locks itself and forgets its keys. Can be turned off in Settings → Privacy.
- **Screen security:** on by default, the app's window is hidden from screenshots, screen recording, screen sharing and Windows Recall. You can turn it off in Settings → Privacy.
- **Secret clipboard:** follow links and invites (which contain keys) are copied in a way that keeps them out of Windows clipboard history and cloud clipboard sync, and the clipboard is cleared after 60 seconds.
- **No traces in Windows:** file dialogs don't add to recent files, jump lists or dialog history (tested).
- **Cloud folders:** saving defaults to Downloads; folders synced by OneDrive, Dropbox, Google Drive, iCloud and others need an explicit confirmation naming the service.
- **Nothing typed is remembered by the browser engine:** form autofill and password saving are switched off, so names, bios or searches typed into the app aren't kept in its profile on disk.
- **No crash reports:** the app and its browser engine don't send crash dumps to Microsoft (including the last browser-engine setting, now switched off through Sentinel's own copy of the window library), and leftover dump folders are deleted at startup.
- **Hijacking the browser engine through Windows settings:** Windows lets a user-level policy give the browser engine extra start-up options (such as a remote-control port) or swap in another engine. Sentinel checks for such policies aimed at it (or at every program) before it opens, and refuses to start, saying where the setting is.
- **Viewed media:** cached pieces are re-encrypted with a device key and named so that a seized computer can't be matched against a known post. Nothing is cached in High-risk mode.
- **Bundled helper programs** (FFmpeg, bridge transports) are fingerprint-checked before every run.
- **Stable under bugs:** an unexpected error in one part doesn't crash the app or a Pillar, and secrets are still wiped from memory.
- **Builds carry no personal paths:** release builds strip the builder's file paths (which include their user name) out of the programs, and the build refuses to finish if any are left.

---

### Updates *(Built)*

Sentinel will never be in an app store. It's handed from person to person and run from many places, so updates have to be safe to get from anywhere:

- **One update file, checked from end to end.** An update lists every file it changes with its size and hash, and that list is signed. Change one byte anywhere and the app refuses it.
- **Signed by a majority of the release keys.** The app has Sentinel's release keys built in, and an update needs signatures from more than half of them. No single person, and no single stolen key, can push an update. Each signature is a hybrid of Ed25519 and **ML-DSA-65**, so a quantum computer can't forge one either.
- **Never backwards.** Only a newer version is accepted, so nobody can push you back to an older, weaker release.
- **The same update for everyone.** Every Pillar fetches new signed releases from other Pillars and passes them on, and the app takes a release only when **at least two different Pillars** carry the very same one. The most dangerous attack on any update system is a special version made for one targeted person; here it would have to be planted across the network, where everyone (and every key holder) can see it.
- **Three days' wait.** The app offers a release only three days after it first saw it. If a bad release ever slips through, there's time to notice it.
- **Revocation.** A majority of the release keys can sign a revocation (`release-revoke`). It spreads from Pillar to Pillar like a release; apps then delete that release and never install it, and Pillars stop passing it on.
- **No secret control software.** The release tools are part of the open-source code. Anyone can build them, but only the release keys can make an update that apps accept, so the code being public costs nothing. Security comes from the keys and from how they're split between people.
- **Carried by Pillars.** The app asks its Pillar and the seed Pillars over Tor at random times (every 6–12 hours), downloads over several circuits at once, and resumes where it left off. If you run a Pillar, it passes the update on: updates spread from Pillar to Pillar, so there's no single server to block or seize.
- **Or handed over.** "Install from a file…" (Settings → Connection) takes an update someone gives you on a USB stick or in a message (for example during an internet shutdown). It's checked the same way and can be installed right away, but it hasn't been compared with what others got, so the app says to install it only if you trust who gave it to you.
- **Installing** swaps the changed files in place (usually just the app itself, not the bundled video tools), puts everything back if anything fails, and restarts.
- **For key holders, inside the app:** Settings → Help run Sentinel → Release keys. "Make my release key" saves it straight to a USB stick and shows a public line to send to whoever builds releases; "Sign an update" shows exactly what's inside (versions, file fingerprints) before signing, and can revoke instead. With two key holders both must sign; with three, any two.
- **For the people releasing it:** `sentinel-cli release-keygen`, `release-pack`, `release-cosign` and `release-revoke` do the same from a terminal.

*Tested over Tor:* a signed update (60 MB) was carried by a Pillar, downloaded by the app over four circuits and checked; a forged one (signed by a key that isn't a release key) was refused; installing swapped the files in place and the app restarted by itself.

*Tested over Tor:* a release put on one Pillar was picked up by a second Pillar on its own, byte for byte; the app took it only once both carried it, refused to install it during the waiting period, and dropped it when a signed revocation appeared.

Still to do: **more release keys held by independent people** (today there's one: a single stolen key could sign a release, though the two-Pillar check, the wait and revocation still apply), and **reproducible builds**, so each key holder builds the app from the published code and signs only if their build is identical.

### Phones (Android) and Linux *(Built: Android app and Linux Pillar; Linux app ready to build)*

- **Android:** the same app, same account and same protections, with a layout made for phones (tabs at the bottom that step aside while you type, section tabs that fit the screen, nothing drawn under the status bar, the gesture bar or the keyboard). *Tested:* on an Android 17 emulator running the release build as an ARM phone would: it made an account, connected through Tor in about 30 seconds, joined a room made on a computer, posted, and exchanged messages with the computer. (Polls was tested on computers.) A tester's real phone connected and joined a room.
  - **Always on:** Android's screen protection (no screenshots, no screen recording or casting, a blank preview in the recent-apps list).
  - **Tor in its own process** (as on computers): the app ships a small separate Tor program that Android unpacks next to the app, so locking or wiping ends it and all its files can be deleted at once. *Tested on the emulator:* it ran as its own process and connected privately in about a minute and a half.
  - **Files:** picking files (attachments, key files, backups, credits files, updates) and saving them work through Android's own file screens; picked files are copied into the app's private storage, which is emptied every time the app starts. (Before 0.16, picking a file on a phone silently did nothing.)
  - **Videos rebuilt** with the phone's own encoders (section 12). *Not yet confirmed on a phone:* the emulator used for testing became unstable before the test finished.
  - **In-app updates:** a signed update for phones (the `app-android` bundle) travels from Pillar to Pillar like the Windows one, is checked the same way (majority of release keys, two Pillars, three days), and is handed to Android's installer, which asks you and only accepts an APK signed with the same key as the app you have. *Not yet tested end to end* (it needs a second, newer signed release).
  - **Memory:** the credit proof machinery (a few hundred MB) is built only while paying and freed afterwards, so Sentinel isn't the first app Android closes in the background. Measured: about 80 MB instead of about 670 MB.
  - **Honest differences:** Phones don't run Pillars or Archives (section 5 says why). If a phone runs very low on memory while you're in a file screen, Android may close Sentinel; it opens again locked, and the file has to be picked again.
- **Linux:** the Pillar is one static file for x86-64 and ARM (Raspberry Pi), built with `scripts/build-linux-pillar.ps1`. The Linux app (a .deb and an AppImage) is built on any Linux machine with `scripts/build-linux.sh`, which fetches a pinned, checksum-verified FFmpeg the same way as on Windows.

## 15. Protecting the people who run the network

Volunteers are a target too: raided, sued or pressured over what passes through their computers.

- **Everything a Pillar stores is encrypted (Built).** Private messages and rooms are end-to-end encrypted and sealed-sender. Posts for "people with your link" can only be read with the author's key.
- **Archives store encrypted pieces with keys they never receive (Built).** Honest limit: someone running an Archive could still read a *public* post as an ordinary reader and work out which pieces belong to it. This isn't strong deniability.
- **Rounded file times (Built):** Pillars and Archives round the dates on stored files and folders down to the day, so a seized disk doesn't show exactly when each item arrived. Volunteers should still use full-disk encryption.
- **No addresses kept:** Pillars don't record the addresses of whoever connects (Tor hides them anyway).
- *Planned:* volunteers choosing content policies (subscribing to abuse labels and refusing matching pieces; the network routes around refusals), and hidden Pillars and Archives that keep things running if every public one in a country is seized.

---

## 16. Speed

- **Ready-made circuits (Built):** the app builds Tor circuits in the background and hands each one out **once**, then throws it away. Actions don't wait for circuits, and network activity no longer lines up with the moment you act. Pooled circuits retire after a random 5 to 8 minutes.
- **Hedged connections (Built):** if a new connection isn't ready after 8 seconds, a second independent attempt starts, and the first to succeed wins. This removed rare one-minute stalls.
- **Measured over real Tor:** a request on a warm connection takes about 0.6 to 0.7 seconds; a fresh private request group through the pool, about 0.7 seconds.
- **Parallel downloads (Built):** files come from several Archives at once over separate circuits.
- **One connection per room delivery (Built):** without mixing, the items a room has waiting (introductions, room details, messages) go to the room's Pillar over one connection instead of one each. A new onion connection takes 5 to 20 seconds, so a new room's first message went from over a minute to about 16 seconds. The trade-off: the Pillar can tell those sealed items came from one device (as their timing mostly shows anyway), never what they say, who sent them or which room they're for. With mixing on, each still travels through the mix on its own.
- *Planned:* downloading whole "what's new" buckets instead of asking per account, and cover traffic that pre-fetches popular content.

---

## 17. What it can't protect you from

Plainly:

- **Someone who can watch huge parts of the internet** can sometimes match traffic going into and out of Tor by timing. Delayed posting, cover traffic and (planned) the mix network make this much harder, not impossible.
- **Tor isn't invulnerable.** Long, expensive attacks with many malicious Tor relays have unmasked onion-service users before. Vanguards, stable entry relays and delayed posting reduce this.
- **Your mobile carrier always knows roughly where your phone is.** With bridges, it can't see that you're using Sentinel. The danger is correlation: if someone already suspects you, they can compare your movements with when an account acts.
- **A hacked device** shows everything to whoever hacked it.
- **What you post can identify you**: what you know, how you write, what's in your photos.
- **People you talk to** can copy what you send them, and their seized phones can reveal you.
- **Fake Pillars flooding the directory** is still an open problem.
- **Small networks** give smaller crowds to hide in: mailbox buckets and credits are most private when many people use them.

---

### Quantum computers: what's protected and what isn't yet

| Part | Today | Against a future quantum computer |
|------|-------|-----------------------------------|
| Private messages, new room keys | Hybrid X25519 + ML-KEM-768 | Protected, including recordings made today |
| Posts, room messages, files, backups, the key file on your device | 256-bit symmetric encryption | Protected |
| Updates | Signed with Ed25519 + ML-DSA-65 | Can't be forged |
| Tor itself | Classical | A recording of the Tor layer could later be opened, but what's inside is Sentinel's own encryption above. Tor is adding post-quantum handshakes; Sentinel picks them up as arti gains them. |
| Posts, profiles, contact cards (who wrote them) | Ed25519 outside, plus an ML-DSA-65 signature inside every object, from a key derived from the account | Can't be forged: followers pin your ML-DSA key from your profile and refuse anything without a valid one. (Room introductions are still classical, by design: they're deniable MACs.) |
| Credits | Notes in public lists, spent with zero-knowledge proofs built only from hash functions (Plonky2, Poseidon); checkpoints signed with Ed25519 + ML-DSA-65 | Can't be forged or traced: hash-based throughout. (Old blind tokens are traded in automatically and no longer issued.) |

## 18. Known attacks and what we do about them

Each line: the attack, then what stops it. "Fixed" means a real weakness was found in the prototype and repaired.

<details>
<summary><b>All 133 attacks, one line each</b> (click to open)</summary>

| # | Attack | What stops it |
|---|--------|---------------|
| 1 | A link or file makes your app contact an attacker's server | The app never fetches anything automatically; files come only from Archives, by fingerprint, over Tor |
| 2 | Calling you to capture your internet address | No calls yet; when built, calls are relayed through Tor only |
| 3 | Learning your online hours from "online" or "read" indicators | None exist |
| 4 | Watching mailboxes and matching deliveries to pickups | Rotating mailboxes, sealed sender, shared buckets, separate circuits |
| 5 | Running Tor relays to see both ends of a connection | Tor's entry guards and vanguards; residual risk |
| 6 | Looking up where someone's home computer is | No addresses anywhere; everything is an onion service |
| 7 | Getting an address from an invite link | Links contain keys and onion addresses only |
| 8 | Fingerprinting by device, language, time zone or media | None of it is sent; media cleaned; times rounded; random IDs |
| 9 | A malicious Tor entry relay builds a history of your locations | Tor guard design; no stable identifier toward relays |
| 10 | Matching timing at both ends | Delayed posting and cover traffic (High-risk); mix network planned |
| 11 | Finding you nearby by Bluetooth or local network | Not used |
| 12 | Push-notification tokens linking a phone to an account | No push services used |
| 13 | Linking two of your accounts | Nothing in the protocol connects accounts; separate circuits |
| 14 | A Pillar learns who reads whom, or which accounts are being read | Timelines come from whole author buckets shared by many accounts, each over its own circuit (Fixed) |
| 15 | Forged or altered posts | Signatures and fingerprints; Pillars can only refuse, not fake |
| 16 | GPS or camera details in photos | Images re-drawn, video rebuilt |
| 17 | A phone seen connecting to a home address | The app never connects to anything but onion services |
| 18 | A home computer listed as a public relay | Pillars are onion-only |
| 19 | Finding the real location of an onion service | Full vanguards on both sides |
| 20 | DNS lookups revealing app use | The app makes none |
| 21 | A leaked chat used as proof of what someone said | Deniable messages and rooms |
| 22 | Seeing who's in a room | Room mailboxes hide room, sender and members |
| 23 | Counting someone's likes or follows | Follows are private; counts are anonymous |
| 24 | Exact posting time from post IDs | Random IDs; times rounded to the minute |
| 25 | Tricking someone into revealing their location | Outside what software can stop; warnings in the app |
| 26 | A Discover server profiling your interests | Topic buckets, random cover buckets, separate circuits, ranking on your device |
| 27 | A niche topic plus posting time identifying an author | Discover is a per-post choice and off in High-risk mode |
| 28 | Boosts or follow notices revealing who supports whom | Anonymous, unlinkable tokens; only counts are published |
| 29 | Fake followers inflating counts | Each notice costs computing work; counts shown as approximate |
| 30 | Someone with your link counting how many messages you get | Only you hold the key to list your mailbox (Fixed) |
| 31 | "Followers-only" posts leaking when a link is shared | The app honestly calls it "People with your link"; for a real private audience, approved followers with removal (Fixed) |
| 32 | Draining someone's one-time message keys | A fallback key keeps messaging working; limits on fetching |
| 33 | File metadata identifying the author | Cleaning, plus clear warnings where cleaning isn't possible |
| 34 | A booby-trapped media file attacking the app | Decoded only in the sandboxed view; allowed formats only; files never auto-opened |
| 35 | A censor recognising a known leaked file by its fingerprint | Random key per file and padded sizes |
| 36 | Archives pretending to store data | Random storage checks; failing Archives get no new files |
| 37 | Paying for a room links you to your spending | Anonymous credits from several independent issuers |
| 38 | A seized computer proves its owner viewed a known post | Cached pieces renamed and re-encrypted with a device key; no cache in High-risk mode (Fixed) |
| 39 | A fake media reference claiming millions of pieces, to exhaust memory | Every reference is checked before use (Fixed) |
| 40 | Windows remembering the names of files you shared or saved | Hardened file dialogs leave no recent-files traces (Fixed) |
| 41 | A saved file silently uploaded to a cloud service | Downloads by default; cloud folders need confirmation (Fixed) |
| 42 | Links containing keys landing in clipboard history or cloud sync | Secret clipboard, cleared after 60 seconds (Fixed) |
| 43 | Windows Recall or screen recording capturing messages | Screen security on by default (Fixed) |
| 44 | Crash dumps holding keys sent to Microsoft | Crash reporting off, including the last browser-engine setting (through Sentinel's own copy of the window library); dump folders deleted (Fixed) |
| 45 | A seized Pillar disk showing when each item arrived | File and folder dates rounded to the day (Fixed) |
| 46 | A room member making someone else's messages look like theirs | The sender travels inside the signed message (Fixed) |
| 47 | Any member renaming a room | Only the room's admin key can (Fixed) |
| 48 | A Pillar operator with your link watching when you check messages | Shared mailbox buckets (Fixed). On a small network, timing still narrows it down; PIR or a mix network is the full fix |
| 49 | A room member proving to outsiders who said what | Deniable introductions; identity inside the encrypted message (Fixed) |
| 50 | Privacy switches that don't actually do anything | Every switch now does exactly what it says (Fixed) |
| 51 | A file changing during upload, producing a broken post | Every piece is re-checked; any change stops the upload (Fixed) |
| 52 | Upload or playback timing revealing when you act | High-risk delays posts and their uploads; big media loads only on play (Fixed) |
| 53 | Your first message to someone being lasting proof you contacted them | Deniable introduction (Fixed) |
| 54 | Video structure identifying the recording device or app | FFmpeg rebuild with hidden notes removed. Limit: files over 1 GB are re-packaged, not re-encoded (Fixed) |
| 55 | A contact pulling you into a room they control | Invites honoured only from the creator you paid (Fixed) |
| 56 | Joining a room and silently missing its history | Re-scan on join; duplicates dropped (Fixed) |
| 57 | A removed profile picture still being uploaded later | Pending pieces dropped (Fixed) |
| 58 | An issuer marking users with a special key | Every issuance proves it used the published key (Fixed) |
| 59 | Losing credits when the payee can't reach the issuer | Payments are queued and retried (Fixed) |
| 60 | A booby-trapped media file making FFmpeg contact the internet or read your files | FFmpeg locked to local input and allowed formats only (Fixed) |
| 61 | Bundled programs swapped on disk | Fingerprint-checked before every run |
| 62 | One unexpected error crashing the app, or remotely crashing a Pillar | Errors are contained; secrets still wiped (Fixed) |
| 63 | One issuer faking or double-spending credits | Credits need parts from a majority of issuers (Fixed) |
| 64 | An issuer giving different users different keys to sort them into groups | Keys pinned in the app; period keys derived from the pinned key (Fixed) |
| 65 | A Pillar lying about mailbox bucket size to shrink your crowd | Your app picks the size itself (Fixed) |
| 66 | Someone with a room's secret claiming to be a paid member to get new room keys | New keys only go to members who proved who they are (Fixed) |
| 67 | A seized backup revealing conversations | Backups hold no messages or session keys (Fixed) |
| 68 | Room payments over 64 credits being rejected and lost | Payments redeemed in batches (Fixed) |
| 69 | A fake reward offer spoiling an Archive's daily reward | Each reward exchange is tied to its own connection (Fixed) |
| 70 | An issuer recognising a payment by its exact size | Redeemed in small random batches, each on its own circuit (Fixed) |
| 71 | Spent-serial lists growing forever (and becoming a long-term record) | Key periods; old lists deleted (Fixed) |
| 72 | Release programs containing the builder's user name in file paths | Paths stripped at build time; build refuses to finish if any remain (Fixed) |
| 73 | A fault in the hosted Pillar reaching the account's keys | The Pillar runs in its own process and never holds them (Fixed) |
| 74 | A computer left unlocked being read by whoever finds it | Auto-lock after 15 minutes (5 in High-risk mode) (Fixed) |
| 75 | A dead public bridge stalling bridge mode for good | Built-in bridges are checked before starting; dead ones are left out (Fixed) |
| 76 | Someone you don't want to hear from keeps messaging you | Block: their messages are dropped unread, and they're never told (Fixed) |
| 77 | Being forced to unlock the app | Emergency passphrase: silently erases the real account and opens an empty one; its existence can't be detected from the files or the unlock time (Fixed) |
| 78 | The time an unlock takes revealing that the emergency passphrase was used | Normal unlocks do the same slow work as the emergency path (Fixed) |
| 79 | A wipe leaving files behind (such as your Pillar's keys or data) because a program still had them open | Tor and your Pillar run in their own processes and are stopped first; everything is deleted at once (Fixed) |
| 80 | Probing every public bridge at each start, a pattern a censor could spot | Probes happen only when bridge mode hasn't worked in the last day (Fixed) |
| 81 | A Pillar noticing a new follow because one bucket is read from the start | The cover bucket is read from the start too (Fixed) |
| 82 | Public documents naming where the test seed runs | Removed; real seeds must run on servers unconnected to their operators (Fixed) |
| 83 | A removed member back-dating messages "from before" their removal | Re-keys carry a cut; later old-epoch messages are dropped by everyone (Fixed) |
| 84 | A stolen room admin key quietly rewriting a room's history | Authority entries are chained; conflicting entries raise a warning for every member (Fixed) |
| 85 | Members seeing different message orders (and apps disagreeing) | Lamport counters give one agreed order (Fixed) |
| 86 | The account's Tor files staying locked (and on disk) after a wipe; network data handled in the process that holds the keys | The account's Tor runs in its own process behind a private, password-locked local door (Fixed) |
| 87 | A room member sending a huge order counter to break the room's message order for everyone | Counters may jump only a bounded amount and never overflow (Fixed) |
| 88 | Someone listing another person's room in Discover under a fake name (to lure people) | A listing's join link must match the room key that signed it (Fixed) |
| 89 | A room's rulebook proving which account was a moderator | Moderators are named by room-only keys and act with a room-only moderator key (Fixed) |
| 90 | A removed or demoted moderator still acting, or replaying old actions | Actions are checked against the current moderator list, and each applies only once (Fixed) |
| 91 | Requests to join revealing to every member who asked | Requests are sealed with an ask key only the creator and moderators hold; it changes when a moderator leaves (Fixed) |
| 92 | Someone else answering a request in your name, or pulling a requester into another room | Answers go to a one-time mailbox only the approvers know, sealed to the requester's own room key and tied to the room (Fixed) |
| 93 | Someone glancing at (or briefly handed) a device and seeing a secure messenger | Disguise mode: a working calculator, named and iconed as one, until the code is typed; kept through wipes (Fixed, with the limits in section 6) |
| 94 | Someone with a copy of the device guessing the passphrase offline | Argon2id (256 MiB) plus an optional key file mixed into the key; without the file, guessing gets nowhere, and nothing shows that one is used (Fixed) |
| 95 | Recording traffic now to decrypt later with a quantum computer | Messages and room keys use hybrid X25519 + ML-KEM-768 (Fixed); Tor's own layer is classical, but only Sentinel ciphertext is inside it |
| 96 | A malicious or tampered update, or a downgrade to an old version | Updates need a majority of the pinned release keys (hybrid Ed25519 + ML-DSA-65), every file is hashed, and only newer versions install (Fixed) |
| 97 | A Pillar or a friend changing an update while passing it on | The signed manifest covers every byte; a Pillar won't even pass on a bundle it can't verify (Fixed) |
| 98 | A stolen or seized account key used to impersonate someone for good | Recovery words sign a move to a new key that followers check against the recovery key they pinned first (Fixed) |
| 99 | A thief swapping in their own recovery key | Followers keep the first recovery pin they saw; later ones are ignored (Fixed) |
| 100 | A special, signed update made for one targeted person | Apps take a release only when two different Pillars carry it identically, and wait three days (Fixed) |
| 101 | A bad release discovered after it went out | A majority of the release keys revoke it; the revocation spreads Pillar to Pillar and apps delete it (Fixed) |
| 102 | A quantum computer forging posts in someone's name | Every object carries an ML-DSA-65 signature too, checked against the key followers pinned (Fixed) |
| 103 | Matching when someone sends with when a message arrives, by watching much of the network | Mixed sending: two Pillars, random delays, sealed layers, padded packets (Fixed, opt-in; on in High-risk mode) |
| 104 | Counting someone's inboxes and rooms from what they fetch | Mailbox checks are padded to a fixed number of buckets (Fixed) |
| 105 | Someone who saw a device-link code linking their own device | Both devices show a check code computed from the request; the person must allow it on their device (Fixed) |
| 106 | A hostile app reaching the network, files or keys | Apps run in a sandbox with no outside functions at all; code that asks for any is refused (Fixed) |
| 107 | An app freezing phones with endless work or huge state | A computing and memory limit per call, a size limit on state, screens and commands (Fixed) |
| 108 | Members ending up with different app results (a fork) | Deterministic interpreter; commands in the room's agreed order; signed snapshots that name exactly which messages they hold (Fixed) |
| 109 | An app identifying members across rooms | Apps see only a nickname made for that room and app (Fixed) |
| 110 | An app imitating Sentinel (fake passphrase prompts) | App screens are drawn by Sentinel from fixed parts, as plain text, inside a frame naming the app (Fixed) |
| 111 | A member disrupting delivery of an app's code | Code pieces must be signed by the room's admin key and match the app's identity (Fixed) |
| 112 | Gone or fake Pillars in the directory making new apps wait forever | Apps start with the first Pillar that answers and look for a backup only briefly; entries not seen for 3 days drop off; new entries must answer before they're listed (Fixed) |
| 113 | A Pillar linking one device's queued room items together | Only without mixing, and only items for the same room box; they stay sealed and anonymous; mixing sends each separately (Accepted trade-off, section 16) |
| 114 | A phone Pillar's uptime revealing its owner's movements | Phones can't run Pillars (Fixed) |
| 115 | A quantum computer forging credits | Credits are notes spent with hash-based zero-knowledge proofs; the old elliptic-curve tokens are no longer issued (Fixed) |
| 116 | An issuer showing someone a list of their own to recognise their spends | Proofs only count against signed checkpoints; apps check the list against them and keep them, and two that disagree prove cheating and the app drops that issuer (Fixed) |
| 117 | Someone reusing a spend proof (to redirect a payment) | Every proof is bound to the fresh credits it pays into; spent tags can't be used twice (Fixed) |
| 118 | Recognising someone by how much of an issuer's list they download | Lists are fetched in fixed pages, the same requests for everyone, on a different connection from the spend (Fixed) |
| 119 | Android backing up Sentinel's data to Google Drive or to a new phone | Backups and device-to-device transfer are switched off for everything Sentinel stores (Fixed in the security audit of 0.15) |
| 120 | Someone with a moment at an unlocked computer setting the browser engine's environment variables (a remote-control port, or a tampered engine) | Release builds clear those variables at startup; only test builds keep them (Fixed in the audit) |
| 121 | A setting left on the computer pointing Sentinel at a different (decoy) account folder | The test-profile switch only works in test builds (Fixed in the audit) |
| 122 | Flooding an issuer with replayed or misdirected spend proofs | Cheap checks (spent tags, checkpoint, payee) before the expensive one; at most two proofs checked at a time, off the network threads; hostile bytes can't crash it (Fixed in the audit) |
| 123 | An issuer claiming an impossibly large list so wallets download forever | Checkpoints larger than the list can hold are refused (Fixed in the audit) |
| 124 | Free credits printed by anyone with many computers | There are no free credits: only work or other people (Fixed) |
| 125 | Fake Pillars farming rewards | Weight builds over months of passed checks; pay follows availability; checks use items indistinguishable from real posts; a whole credit needs a majority of issuers. A year-long simulation of eleven cheating strategies is part of the tests (section 13) (Mitigated: one person running many real Pillars still earns like many people) |
| 126 | Flooding an issuer's lists with gone or fake nodes so its checks (and everyone's rewards) crawl | Checks run 8 at a time, each with a 4-minute limit; a check that times out counts as failed; entries not seen for 3 days drop off (Fixed) |
| 127 | A Pillar keeping only recent data (or only the test items) and still being paid | Test items asked for at a random age of 1–30 days; one it won't answer for stays due; a missing one costs a lot at once (Fixed) |
| 128 | Getting an honest Pillar punished by disrupting it, or by Tor's ordinary dropped connections | Judged by the day (70% of checks), not by single checks; one bad day costs about two days of building (Fixed) |
| 129 | Many Pillars being paid nothing at all (rounding) once there are more than 24 | Fractions carry over to the next day (Fixed) |
| 130 | A wave of new Pillars from one person taking over the rewards | Pillars under 90 days old share at most a quarter of the pool (Mitigated) |
| 131 | Credits lost in a message that never arrives, or is never opened | The sender's app takes them back (a day if undelivered, 8 days if never collected) (Fixed) |
| 132 | A Windows policy setting giving Sentinel's browser engine a remote-control port or another engine | Checked before the window opens; Sentinel refuses to start and says where the setting is (Fixed) |
| 133 | A phone closing Sentinel in the background because it holds a lot of memory | The credit proof machinery is freed after each payment on phones (Fixed) |

</details>

### What each party can see

| Who | Your internet address | Who you are | What you say | Who you talk to |
|-----|----------------------|-------------|--------------|-----------------|
| Your Tor entry relay | yes | no | no | no |
| Other Tor relays | no | no | no | no |
| A Pillar holding your messages | no | no (rotating, shared mailboxes) | no | no |
| A Pillar holding your posts | no | your account (posts are signed) | only with your link | no |
| An Archive | no | no | no | no |
| A room member | no | yes | yes, in that room | that room's members |
| Your internet provider or carrier | yes (it's your line) | no | no | no; sees Tor, or with bridges, disguised traffic |

---

## 19. Sentinel Apps (partly built)

*Built: the sandbox, signed app packages, the permission screen, the screen parts, and a first app (Polls) that comes with Sentinel. Tested over the real Tor network with three accounts: one asked, the others voted, a member who joined later saw exactly the same result, and nobody could close someone else's poll. Still to come: credit payments inside apps, more apps, and templates for people who don't program.*

**The idea:** instead of Sentinel adding every new feature itself (forums one release, polls the next), anyone can write a **Sentinel App**: a small program that defines how a space works, its rules, who may do what, and what its screens look like. People add an app to a room, and everyone in it runs the same rules. The built-in timeline, messages and rooms stay as they are; they're simply the apps that ship with Sentinel. Different versions of an app can live side by side (Forum v1 and Forum v2), the way Matrix has room versions.

What changes is the answer to "what is Sentinel?": not only a private Twitter-and-Signal, but **a private, decentralized platform people can build on**, where every app gets Tor, sealed storage, deniable messaging and anonymous credits for free and can't weaken any of them.

**Definition:** a Sentinel App is a signed, versioned, sandboxed program that works only on the Sentinel objects and state it's been allowed to use, through a small set of permissions.

**Contracts without a blockchain.** Sentinel Apps do what smart contracts do, without a blockchain: an app is deterministic code, every member runs it on the same inputs in the same agreed order (the room authority log, section 11), so everyone reaches the same state, and anyone can check it. Payments inside an app use credits (section 13), so an app can sell, escrow or reward without anyone learning who paid whom. No mining, no public ledger of everyone's actions, and nothing that has to be online all the time. If credits one day become a withdrawable currency, apps already speak it.

### The line apps can never cross

Sentinel's core keeps everything that keeps people alive. An app **never** touches: Tor or any network connection; identities, keys or encryption; files on the device; account recovery or device security; anything outside its own room or space. It runs in a sandbox (WebAssembly, with no system access and a strict limit on how much it can compute), and it can only ask for things like:

| Permission | Meaning |
|------------|---------|
| Read and update its room's state | Only the space it was added to |
| Post a message or create a post | Through the normal sealed, deniable paths |
| Read objects it was given | Never searching or fetching on its own |
| Show a notification | Shown by Sentinel, worded neutrally |
| Ask for a credit payment | Sentinel shows its own confirmation; the app never sees a wallet |
| Request a picture or file | Fetched by Sentinel on its usual schedule and circuits |

A hostile app can't ask for keys, can't connect to an address, and can't make a phone do anything Sentinel wouldn't do anyway.

### How everyone agrees on what happened

Many people run the same app in a room, so they must get the same result. An app is a pure function: **state + command → new state + events**. No clock, no randomness and no internet from the computer it runs on; when an app needs time or chance, it gets them as agreed inputs from the room. Commands are the room's own (deniably authenticated) messages, applied in a fixed order with fixed tie-break rules, so every member reaches the same state without any blockchain. Nothing runs on Pillars: **members' devices run the rules, and Pillars only carry sealed messages**, as now. This deliberately avoids the Ethereum model where every node runs everything, which would bring back the cost and privacy problems Sentinel was built to avoid.

How it works today:

- **The sandbox** is a WebAssembly interpreter (wasmi) in its deterministic mode, so the same code gives the same answer on every phone and computer, maths included. An app has **no outside functions at all**: code that asks for any is refused before it runs. Each call gets a fresh copy of the app, a computing limit and a memory limit, so an endless loop just stops.
- **Commands** are ordinary room messages, sealed and deniable like any other, and hidden from the conversation. Every member applies them in the room's agreed order (section 11). A command the app refuses changes nothing for anyone. Your own device checks a command first, so one that would be refused is never sent.
- **People who join later** can't read messages from before they arrived. So the room's admin device posts a **signed snapshot** of each app's state every day and whenever someone new arrives. A snapshot lists exactly which messages it holds (per sender, an unbroken run of message numbers), so a command that arrives late is applied on top of it, never lost, and every member treats it the same way.
- **Members appear to an app only as a nickname made for that room and that app**, never as their account. Sentinel shows their name; the app never learns it.
- **Adding an app** is an entry in the room's authority log, so only the admin can add or remove apps, and everyone agrees which apps the room has. Apps that don't come with Sentinel are signed by their author (the admin sees a short fingerprint of the author's key to check with them), and their code is carried to members in pieces signed by the admin. An app's identity is the hash of its whole package, so everyone runs exactly the same code.
- **Before adding an app**, the admin sees in plain words what it can do (keep its own information in the room, show screens in its frame) and what it can't (connect to anything, see accounts, keys, files or other rooms, spend credits, send messages).

### Screens without code

An app doesn't ship its own web page or scripts. It describes its screens with a small fixed set of parts (title, text, a member's name, text box, button, result bar, row, card, divider; pictures come later), and Sentinel's own client draws them, always as plain text. One app can look like a forum, another like Discord or a poll, all on the same identity, encryption and network. Rules for this:

- Apps can't load anything from the internet, embed web content or run scripts in the window.
- App screens are always drawn inside a frame that clearly shows which app is speaking, and **can never imitate Sentinel itself**: no passphrase prompts, no security badges, no "Sentinel says" dialogs.
- Text is shown as plain text; sizes and counts are capped.

### Privacy rules specific to apps

Apps add a new risk: a hostile app trying to **identify people through how they use it**, not through what it can read. So:

- **No network behaviour of its own.** All fetching is done by Sentinel on its normal schedules, buckets and circuits. An app can't make one person fetch something unique, or make anything happen at a time it chooses.
- **No hidden channels.** An app sees only the room state everyone in the room sees. It can't learn which device, which language or which time zone it runs on.
- **Same identity, or a separate one.** Using your account in an app links your activity there to your account, as it would in any room. Apps that don't need to know who you are can be joined with a separate, per-app identity.
- **Installed on purpose, never updated silently.** Apps are fingerprinted, signed by their authors and pinned to an exact version. An update is a new version you choose to switch to, never a quiet change underneath you.
- **High-risk mode** allows only apps that ship with Sentinel or have passed an independent review.
- Each app's state has a size limit, and its computing is metered, so a broken or hostile app can't freeze devices or fill Pillars.

### Credits and Compute

Apps can charge for things (joining, pinning, a premium feature) through the existing anonymous credits. Sentinel asks you to confirm every payment in its own screen, with a per-app limit you set. Heavy work an app needs (say, converting video) could later go to Compute volunteers (section 5) under the same rules: they'd get only sealed inputs, and nothing that says who asked.

### Order of work

1. The room authority log with an agreed order of messages (built), then formally analysed.
2. The sandbox and the permission list, then the screen description format (built).
3. A first, small built-in app (Polls), to prove the design (built).
4. Opening it to outside authors: signing and exact versions (built: `sentinel-cli app-pack` signs an app; the admin adds it from a file). Still to come: reviews, and High-risk mode allowing only reviewed apps.
5. Credit payments inside apps, pictures in app screens, more apps, and templates so people can make simple apps without programming.

It comes after the security work in section 20 (audits, independent seeds, reproducible builds): a platform for other people's code is only as safe as the base it runs on.

## 20. What's built and what's left

### Built and tested over real Tor

Accounts, profiles, safety numbers, backups, panic wipe, an emergency passphrase, an optional key file, recovery words and moving to a new key · several devices per account · disguise mode · auto-lock · the account's Tor in its own process · built-in Tor with bridges and Tor-lock · finding Pillars (start with one, gone Pillars age out, paste a trusted address) and the connection log · sealed posts, follow links, approved followers, timelines from author buckets, Discover with topic buckets, anonymous follower counts, mute and block · deniable, sealed-sender private messages with shared mailboxes and disappearing messages · mixed sending through two Pillars, fixed-size mailbox checks · private and public rooms (listed in Discover), paid rooms, moderators, ask-to-join rooms, the room authority log (bans, hidden messages, no back-dating, one agreed order) · Sentinel Apps: the sandbox and Polls · cleaned and encrypted photos, video and files, spread over Archives with recovery pieces and storage checks · quantum-safe credits (notes, zero-knowledge spend proofs, signed checkpoints) with majority-of-issuers parts, key periods and public supply counts · post-quantum (hybrid ML-KEM) messages and room keys, ML-DSA signatures inside every post, profile and card, a quantum-safe recovery key · signed updates carried by Pillars or handed over as a file, release keys managed in the app · High-risk mode (as listed in section 8) · Windows device protections · a per-user Windows installer with everything bundled · the Android app (signed APK; Tor in its own process) · deleting messages (selected, whole conversations, rooms, everything; optionally on the other person's side) · credits taken back when a message is never collected · Pillars earning credits (tested live with a sped-up clock) · the Linux Pillar (one static file, x86-64 and ARM).

### Still to build

**Before anyone at risk relies on it:**
1. **Independent issuers and seeds.** Today there's one seed Pillar, and it runs on one home computer: when that computer sleeps or the Pillar's window closes, new accounts can't find the network and messages wait. (This happened during testing.) The network needs at least three independent, always-on operators in different places, with their addresses and keys built into the app. Cheapest start: two or three friends each running the Linux Pillar on a Raspberry Pi.
2. **Independent security audits** of the cryptography, the network code and the app.
3. **Formal analysis** of the room (including the new authority log), mailbox and credit protocols.
4. **Reproducible builds**, so anyone can check a release was built from the published code. (Signed, majority-approved updates are built: section 14.) More release keys, held by independent people.
5. **Private fetching** (PIR) for mailboxes and author buckets, so even shared buckets reveal nothing on small networks. (Mixed sending and fixed-size mailbox checks are built: section 10.)

**Features:**
6. On phones: confirm video rebuilding and in-app updates on a real phone (both are built, section 14), and ship the bridge helper for phones so "Restricted network" works there. (There will be no iPhone or Mac app: Sentinel runs on Windows, Linux and Android only.)
7. More disguises (and on phones, a changed app name and icon).
8. The rest of High-risk mode (section 8).
9. Custom feeds; search; boosts; abuse labels.
10. Large-room encryption (MLS-style) after analysis.
11. Compute volunteering.
12. Faster spend proofs. Proofs are now compressed (about 170 KB) and prepared in the background; a newer proof mode about 30 times faster was measured and rejected because it could reveal which credit was spent. Next: one proof for a whole payment, and an independent review of the credit proofs.
13. Internet-shutdown features: local Wi-Fi/Bluetooth relay and USB bundles.
14. Earning credits for running Pillars is built, simulated against cheaters and tested live (section 13). Next: real months of earning on the live network, and paying Compute volunteers the same way once Compute exists (the payment side is ready; Compute itself and a way to check its work aren't).
15. The research path to a withdrawable currency (section 13).
16. **Sentinel Apps** (section 19): the sandbox and Polls are built. Next: credit payments inside apps, pictures, more apps, templates, and independent review of outside apps.

**Known gaps in what exists:**
17. Bridges: the public obfs4 bridges are crowded; the app now measures them and keeps only the four quickest, quickest first, which shortens the start. Snowflake is still the default.
18. The Windows policy check (#132) is built but was not tested by planting a real policy (that would change this computer's settings).
19. We carry our own fix for a Tor library bug that hangs startup on Windows, permanently, inside the project. Nothing depends on the Tor project fixing it.
20. Phones: the first connection takes from 30 seconds to a few minutes. Video rebuilding and in-app updates still need a test on a real phone.
21. The Linux desktop app has a build script but hasn't been built or tested yet (it needs a Linux machine).
22. The Pillar keeps its list of other Pillars by announcement only; it doesn't yet test listed Pillars itself between announcements.

---

## 21. Technical reference

For people building or auditing Sentinel.

<details>
<summary><b>Cryptography, credits, storage, network and release details</b> (click to open)</summary>

### Cryptography

| Use | Choice |
|-----|--------|
| Signatures | Ed25519 |
| Key agreement | X25519 (hybrid with ML-KEM-768 planned) |
| Encryption | XChaCha20-Poly1305 |
| Hashing and key derivation | BLAKE3 (keyed, derive-key and XOF modes) |
| Passphrase lock | Argon2id, 256 MiB, optionally mixed with a key-file fingerprint (BLAKE3 of the first 1 MiB) for the real slot only; key file `magic | salt | nonce | sealed key | emergency slot (248 bytes, random when unused)`; both slots derived in parallel on every unlock |
| Private messages | vodozemac Olm (Double Ratchet), sealed sender |
| Rooms | vodozemac Megolm, deniable hellos with pairwise X25519 MACs |
| Credits | Notes in per-issuer Merkle trees (Poseidon over Goldilocks, depth 20); spends proven with Plonky2 (PLONK + FRI, zero-knowledge on, ~128-bit conjectured); checkpoints signed Ed25519 + ML-DSA-65. Old: VOPRF (RFC 9497) over Ristretto255, now only traded in |
| Erasure coding | Reed-Solomon, 10 data pieces per stripe, parity sized so any one Archive may be lost |

### Credits in detail

- Note (token version 2): `{ v: 2, epoch, input = secret (4 Goldilocks elements), output = position (u64) }`. Commitment `Poseidon(secret ‖ "note")`, spent tag (nullifier) `Poseidon(secret ‖ "spen")`.
- Each issuer keeps one append-only tree per key period (depth 20, empty leaves zero). A spend proof covers up to 4 notes (unused slots switched off); public inputs: root, binding value, and per slot (on/off, nullifier). The binding value is `BLAKE3-derive("sentinel/v1/pq-spend-bind", epoch ‖ fresh commitments)`, reduced to four 62-bit field elements.
- Checkpoints every 600 seconds when the tree grew: `{ mint, epoch, seq, size, root }`, signed with a hybrid key derived from the issuer's seed. Proofs are accepted only against checkpoint roots of a spendable period; a swap carries at most 8 proofs.
- Requests: `PqSwap`, `PqUpgrade` (old tokens in, notes out), `PqLeaves` (pages of 8192), `PqCheckpoint`, `PqMintKey`; Archive rewards via `RewardOfferPq` / `RewardAppended`.
- Old blind tokens (version 1): `output = F(k_e, input)`, nullifier `BLAKE3-derive("sentinel/v1/credit-nullifier", epoch ‖ input)`; accepted only by `PqUpgrade`.
- Issuer master secret `k` is derived from a 32-byte seed. Period key `k_e = k + H(e)` with `H` = BLAKE3-XOF reduced mod ℓ; the public period key is `K + H(e)·G`, so it is computable from the pinned long-term key `K` alone.
- Period length 180 days. Spendable in its own period and the next. Issuance accepted under the current period, or the neighbour within one day of a boundary.
- Credit = bundle of parts from `t = ⌊n/2⌋ + 1` distinct listed issuers (the seed Pillars). Wallets assemble bundles greedily from the issuers with the most parts.
- Redeem batches: 1 to 8 tokens, random, each on its own isolated circuit; at most 64 per request.
- No free issuance. Archives: up to 3 parts a day per issuer for passing storage checks. Pillars: per issuer, 24 parts a day shared by weight × availability (at most 3 each, fractions carried over; weight builds with a 40-day time constant on days with at least 70% of checks passed; bad days keep 95% of it, 80% after three in a week, 60% after five in two weeks or a missing test item; test items asked for at a random age of 1–30 days; Pillars under 90 days old share at most 25%; the pool shrinks with a 1460-day time constant). Pinning: 1 credit per started GB-month per Archive.
- Supply: each issuer answers `MintStats` with `(period, issued, spent)`.

### Storage

- Sealed objects padded to power-of-two buckets; 8 key slots per object.
- Media pieces: 1 MiB plaintext, identical ciphertext size (synthetic-IV encryption), piece count padded to buckets (about 12.5% steps above 8).
- Pillar limits: 2 GB, 60-day retention (hosted from the app). Archive pieces expire after 90 days without a fetch unless pinned.
- Mailboxes: deposits filed under a 16-bit prefix of the rotating mailbox ID; readers choose fetch depth (up to 8 bits), separate circuit per prefix.
- Author buckets: `bucket = BLAKE3-derive("sentinel/v1/author-bucket", author)[0]`; `AuthorBucket { bits ≤ 8, prefix, after }` returns sealed objects inline with a per-Pillar sequence; readers round `after` down to multiples of 32 and split depth only when a round exceeds 8 MB.

### Network

- arti (Rust Tor), onion services only, full vanguards, isolated circuits per request group, pre-built single-use stream pool, hedged connects at 8 seconds.
- Bridges via the Tor Project's lyrebird (Snowflake, obfs4, WebTunnel), fingerprint-checked, extracted only in bridge mode.
- Seed list format: `<onion> [credit key hex] [pq=<checkpoint key fingerprint hex>]` (both printed by `pillar --print-keys`).

### Building releases

Release builds must use `scripts/build-release.ps1`. It strips local file paths from the programs and fails if any remain.

</details>

---

## 22. Version history

<details>
<summary><b>What changed in each version</b> (click to open)</summary>

- **0.16**: Deleting messages (selected or all, in conversations and rooms, optionally on the other side; everything from Settings). Credits in a message that's never delivered or collected come back to the sender. Pillar earning rebuilt from a year-long simulation of cheaters: judged by the day, pay follows availability, test items at random ages, fractions carried over, a cap for new Pillars; tested live with a sped-up clock. Smaller (compressed) credit proofs, prepared in the background. Phones: Tor in its own process, picking and saving files through Android's file screens (it silently didn't work before), videos rebuilt with the phone's encoders, in-app updates through Android's installer, far less memory. Windows: the last crash-report setting off, and a check for policies that hijack the browser engine. Quicker obfs4 starts.
- **0.15**: No free credits (only work or other people); sending credits in a private message; Pillars earn credits (weight over months, random checks, shared shrinking pool), server Pillars hand earnings over with `pillar --take-credits`. A security audit (Android backups off, browser-engine variables ignored, test profiles only in test builds, issuer flood and oversized-list protection, dependency scan). Quantum-safe credits: notes in public per-issuer lists, spent with hash-based zero-knowledge proofs (Plonky2), signed checkpoints that catch an issuer showing different lists; old blind tokens traded in automatically. A design for earning by running Pillars. No iPhone or Mac app, by decision. Finding Pillars starts with the first one that answers; Pillars drop entries not seen for 3 days; phones can't run Pillars (and why); a connection log; one connection per room delivery; phone layout clear of system bars and the keyboard. Sentinel Apps: a deterministic WebAssembly sandbox with no outside functions, signed app packages, a plain-language permission screen, screens drawn by Sentinel from fixed parts, admin-signed snapshots so late joiners agree, per-room nicknames, and a first app (Polls). The connecting screen says when Pillars aren't answering and lets you paste a trusted Pillar's address. FFmpeg is fetched and checked by a script (too big for GitHub); without it videos are cleaned in place and the app says so.
- **0.14**: Several devices per account (link code with check code; every device gets messages; activity syncs). Post-quantum signatures (ML-DSA-65) inside every post, profile and card, pinned by followers. Mixed sending through two Pillars with random delays; fixed-size mailbox checks. Release key holders can make keys and sign or revoke updates inside the app. Linux Pillar. Unfollow. A "Getting started" checklist.
- **0.13**: Updates spread Pillar to Pillar; apps need two Pillars to carry the same release, wait three days, and honour signed revocations. Recovery words (lost device: same identity on a new one; taken: move to a new key that followers check against a pinned, quantum-safe recovery key). Signed updates (hybrid post-quantum release signatures, majority of release keys, carried Pillar to Pillar or handed over as a file). Post-quantum hybrid (ML-KEM-768) sealing for private messages and room keys. Sentinel Apps described as contracts without a blockchain.
- **0.12**: Optional key file for unlocking (VeraCrypt-style). Disguise mode (a working calculator in front of the unlock screen). Room moderators (room-only keys) and ask-to-join rooms; leaving rooms. Public rooms listed in Discover (signed by the room's own key). Bounded message-order counters. The account's Tor connection runs in its own process (wipes delete everything at once; keys never share a process with network parsing); the room authority log (checkpoints, bans, hidden messages, epoch cuts, agreed order, fork warning); first connection keeps searching for Pillars instead of giving up; re-keys delivered immediately. Friendlier screens: Settings split into Privacy, Safety, Connection, Help run Sentinel and Credits; status in plain words; starter topics in Discover; generated passphrases must be confirmed as written down.
- **0.11**: Privacy pass: equal unlock timing, wipe retries, bridge probing only for recovery, cover bucket read in full alongside a new follow. Approved followers (a private audience approved one by one, removable, with fresh keys after each removal). Sentinel Apps added as a planned layer: sandboxed, deterministic, capability-limited programs with described screens, run by members' devices, never by Pillars.
- **0.10**: The hosted Pillar runs in its own process (switch off and on freely); built-in bridges health-checked and stale bridge memory cleaned up; timelines from author buckets (Pillars no longer see which accounts are read); free credits use all cores; auto-lock; mute and block; emergency passphrase.
- **0.9**: Credits issued by the established Pillars (no separate mint role); token format ready for a future currency (versions, 180-day key periods derived from one pinned key, bounded spent lists, public supply counts, hidden payment sizes); a clear "Help run Sentinel" section with separate Pillar, Archive and Compute switches and their risks; build paths stripped from release programs; this plain-language rewrite.
- **0.8**: Credits from a majority of issuers; pinned issuer keys; review fixes (mailbox depth, room re-key verification, full safety numbers, backups without history, crash resistance).
- **0.7**: Profiles; deniable messages and rooms; shared mailbox buckets; erasure coding; storage checks; credits; paid rooms; FFmpeg rebuild; cover traffic.
- **0.6**: Large files and Archives; streaming; device protections (dialogs, cloud folders, clipboard, screen security, crash dumps).
- **0.5**: Everything Pillars store is encrypted; end-to-end encrypted messages; Pillar and Archive roles; media design; credits design.
- **0.4**: Discover as a core feature: topics, buckets, anonymous follower counts.
- **0.3**: Tor built in; the deadly-adversary threat model; High-risk mode.
- **0.2**: First adversarial review.

</details>
