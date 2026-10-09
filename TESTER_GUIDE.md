# Trying Sentinel: a guide for testers

Thanks for trying Sentinel! This is one of its first releases, and your feedback shapes what comes next. Please read the first section before you start. (What Sentinel is: the [README](README.md). How it works: [DESIGN.md](DESIGN.md).)

## Before you start

- **It's an early release.** Everything works end to end over Tor, and an independent security audit is next. The network is still small, so every tester who runs a Pillar makes it faster and stronger.
- **Write down your recovery words** (Settings → Safety). They're the only way back into your account if your computer is lost. Anyone who has them can take over your account, so keep them on paper, hidden.
- **Your passphrase can't be reset.** If you forget it and don't have your recovery words, the account is gone.

## Installing

1. Get `sentinel-windows-setup.exe` from the person who invited you, or from the **Releases** section of the project page, and run it. It installs for your user only (no admin rights needed) and includes everything: Tor, the video tools, the browser engine. Nothing else to download.
2. Pick **Standard** (or **Restricted network** if Tor is blocked where you are).
3. Choose a name (any name), press **Generate** for a strong passphrase, write the words down, and tick the box.
4. The first connection takes about a minute. After that, a few seconds.

## On an Android phone

1. Get `sentinel-android.apk` (from the person who invited you, or the **Releases** section), copy it to the phone and open it. Android asks to allow installing apps from that source (Files or your browser): allow it for this one install.
2. Open Sentinel and set it up the same way. To use the account you already have on your computer, choose **Use my account from another device** (see below).
3. Sentinel blocks screenshots on phones, always.
4. The first connection can take a few minutes on a phone. Keep the app open and the screen on until it says *Connected privately*.
5. Attaching or saving a file opens Android's own file screen. If your phone is very low on memory, Android may close Sentinel while that screen is open; just unlock it and pick the file again.
6. Later versions can install themselves (Settings → Connection → Updates): Android asks you first, the first time to allow Sentinel to install updates.

## Things to try

- **Follow each other:** Profile → *Copy follow link*, send it to a friend privately, and paste theirs into *Follow someone*.
- **Post** to your followers, or mark a post *Discoverable* with a topic so others can find it in Discover.
- **Message** someone you follow (Messages).
- **Rooms:** make one, share the invite or ask-to-join link, try moderators and paid rooms. There are no free credits: someone can send you some in a private message (*Send credits*), or run an Archive or a Pillar (Settings → Help run Sentinel) to earn them.
- **Polls:** in a room you made, press **Apps** → *Add Polls to this room*. Ask a question; everyone in the room can vote and change their vote until you close it.
- **Safety features** (Settings → Safety): emergency passphrase, key file, disguise mode (the app turns into a calculator when locked).
- **Deleting messages:** in a conversation or room, *Select* lets you delete some messages or all of them (in a conversation you can also ask the other person's app to delete them). Settings → Privacy → *Delete all messages* clears everything.
- **Report anything harmful:** public posts and Discover rooms have a *Report* button, and so do messages in rooms. It goes to whoever can see the content (the Pillars holding a public post, or a room's moderators), never to anyone who can't. Media from people you don't follow is blurred in Discover until you tap it.
- **Forgot your passphrase?** The unlock screen has a link that lets you start over and get your account back with your recovery words, a backup or another device.
- **Credits that don't arrive come back:** if credits you sent are never collected, your app takes them back by itself (after a day if the message never got through, after 8 days if it did but wasn't opened).

## Your phone and computer together

Settings → Safety → Your devices → **Link a new device** shows a code. On the other device choose **Use my account from another device**, type the code, and check that both screens show the same 8-digit check code before you press Allow.

## Helping run the network

Settings → **Help run Sentinel** lets your computer carry part of the network (a Pillar) or store encrypted files for others (an Archive). Read the risks shown there first. You can turn them off at any time. A handful of friends running Pillars makes the whole network faster and harder to block.

If you want to run a Pillar on a server that's always on, ask for the Pillar program: `sentinel-pillar-windows.exe` for Windows, or `sentinel-pillar-linux-x86_64` / `sentinel-pillar-linux-arm64` for Linux (a Raspberry Pi works). It's one file, no app or installs needed: just run it.

## Updates

Updates arrive by themselves through the network (Settings → Connection → Updates), or someone can hand you an update file (*Install from a file…*). Either way the app checks that it's genuinely signed and newer before installing anything.

## If it gets stuck

- **Stuck at "Finding Pillars" or messages stay "sending privately…":** the network's starting Pillar may be offline. Keep the app open; it keeps trying. If someone you trust runs a Pillar, paste its address in the box that appears.
- **Get the connection log:** Settings → Connection → *Connection log* → *Copy the log* (also on the connecting screen). It shows what the app tried and what failed. It has no account details, messages or IP address. Send it to the person helping you.

## Reporting problems

Tell the person who gave you the app what happened and roughly when, and include the connection log if it was about connecting or sending. Please don't send screenshots of your follow link, recovery words or messages.
