# Changelog

## 0.1.1 — 2026-11-27

- Security: `ctutils` 0.4.3 → 0.4.8, fixing [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385)
  (non-constant-time mask generation; pulled in by `aes-gcm` and `hmac`). The 0.1.0 helper is
  affected; rebuild it with `./install.sh`.
- Works with Omarchy 4.5 on Qt 6.12: the palette is read as `Commons.Color`.
- Dependencies: sha2 0.11.2, zeroize 1.9.2, rusqlite 0.43.0 (tests only), refreshed lockfile.
- CI: Rust 1.100.0, cargo-deny-action 2.1.4, actions/checkout 7.0.1, actions/setup-node 7.1.0.

## 0.1.0 — 2026-10-20

First release.

- Keyboard-driven bar panel for Proton Authenticator TOTP codes: fuzzy search, pinned and recent
  ordering, privacy mode, issuer glyphs, theme-aware styling.
- Hardened Rust helper `pa-helper` that reads the official app's local vault read-only, with no
  SQLite or network at runtime, and copies codes through a detached, self-clearing clipboard holder.
- `install.sh` builds the helper from source with locked dependencies.
