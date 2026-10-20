# Changelog

## 0.1.0 — 2026-10-20

First release.

- Keyboard-driven bar panel for Proton Authenticator TOTP codes: fuzzy search, pinned and recent
  ordering, privacy mode, issuer glyphs, theme-aware styling.
- Hardened Rust helper `pa-helper` that reads the official app's local vault read-only, with no
  SQLite or network at runtime, and copies codes through a detached, self-clearing clipboard holder.
- `install.sh` builds the helper from source with locked dependencies.
