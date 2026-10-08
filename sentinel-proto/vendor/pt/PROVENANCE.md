# Vendored pluggable transports

These files are embedded into the `sentinel` client so users never install anything extra. They are unmodified copies from the Tor Project's official, signed release.

| Field | Value |
|-------|-------|
| Source | `https://dist.torproject.org/torbrowser/15.0.24/tor-expert-bundle-windows-x86_64-15.0.24.tar.gz` |
| Archive SHA-256 | `e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65` |
| Signature | `….tar.gz.asc`, **Good signature** (verified 2026-10-04) |
| Signing key | Tor Browser Developers (signing key) `<torbrowser@torproject.org>` — primary `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`, subkey `022D A248 432D 2A0E 0F54 E65E 316C 1FAC D62D 07D9` |

| File | SHA-256 | From archive path |
|------|---------|-------------------|
| `windows-x86_64/lyrebird.exe` | `6e218e85f9a7ae2481f5402ded822471a9a9d0c7e66b05db3842b93fa5c1f02e` | `tor/pluggable_transports/lyrebird.exe` |
| `windows-x86_64/pt_config.json` | `3f11d303c30191b3b1d382b9badd882d87fd87550d061f7d25a1b31226fc9b75` | `tor/pluggable_transports/pt_config.json` |
| `windows-x86_64/LICENSE-lyrebird.txt` | — | `docs/lyrebird.txt` |

`lyrebird` provides obfs4, WebTunnel, meek and Snowflake. `pt_config.json` contains Tor's built-in Snowflake, obfs4 and meek bridges.

## Re-verifying or updating

1. Download the archive and its `.asc` from `dist.torproject.org/torbrowser/<version>/`.
2. Fetch the key by fingerprint (`keys.openpgp.org/vks/v1/by-fingerprint/EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`) into a throwaway `GNUPGHOME`, and check the fingerprint matches the one above.
3. `gpg --verify <archive>.asc <archive>` must report a good signature from that key.
4. Extract, copy the files listed above, and update every hash in this file.

Releases must use reproducible builds and threshold signing (spec §19); updating these binaries is a release-gated change.
