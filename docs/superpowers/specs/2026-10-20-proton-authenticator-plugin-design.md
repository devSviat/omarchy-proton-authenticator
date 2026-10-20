# Proton Authenticator for Omarchy — Design

Date: 2026-10-20 · Author: devSviat · Status: approved 2026-10-20, updated with decisions taken during implementation

## Why

The official Proton Authenticator desktop app (Tauri/WebKitGTK, 1.1.6 at the time of writing) can feel slow on Linux, and fetching a 2FA code means opening a full window. This plugin gives fast access to the codes from the Omarchy bar: hotkey → type a few letters → Enter → the code is on the clipboard.

Priorities, in order: **security → reliability → UX → UI**.

The plugin will be published in the plugins.omarchy.org catalog.

### Relation to other plugins

The Omarchy plugin catalog already lists several community plugins for Proton Authenticator. This project is an independent implementation, not a fork or a reaction to them. The author has not audited those projects and makes no claims about their quality or security. A separate implementation simply lets every line that touches 2FA secrets be designed, tested and reviewed against a single, explicit threat model, which is the main point of this plugin.

## Goals

- A bar panel that lists accounts with their current TOTP codes and opens instantly.
- Fully keyboard-driven: type-to-search, Enter copies the code.
- The data source is the official Proton Authenticator local vault, **read-only**. Syncing with other devices remains the job of the official app.
- New accounts appear in the plugin automatically once the official app has updated the vault.
- Secrets never reach QML, disk, argv/env, logs, notifications or clipboard history.

## Non-goals

- Adding, editing or deleting accounts. Accounts are added on the phone (it has the camera); everything else happens in the official app.
- Network sync with Proton. The plugin never touches the network.
- Protection against malware running as the same user. Such a process can already read the vault and its key from the Secret Service, which has no per-application access control. The goal is to **add no new leak channels**, not to defend beyond that boundary.
- Other code sources (Proton Pass, Aegis, file imports). The official `pass-cli` only works with Proton Pass and cannot see the Authenticator vault.

## Anti-goals (failure even if it "works")

- Any TOTP seed or vault key on disk, in swap, in a core dump, in process arguments, in environment variables, in logs, in notifications or in clipboard history.
- Any network access from the plugin or its helper.
- Downloading prebuilt binaries, `curl | bash`, `sudo`, or replacing/patching the official app.
- Any write to the Proton vault or its directory.
- Silent failure or garbage output when the vault format changes.
- A slow panel. If it does not open instantly the plugin has no reason to exist.

## Context and facts

- **Omarchy** 4.0.6, Quickshell-based `omarchy-shell`. Plugin docs: `/usr/share/omarchy/shell/README.md`, `/usr/share/omarchy/shell/plugins/README.md`, `/usr/share/omarchy/shell/plugins/bar/README.md`. Manifest schema: `/usr/share/omarchy/shell/services/PluginRegistry.qml`. Validator: `omarchy-plugin-validate`. UI kit: `/usr/share/omarchy/shell/Ui/`.
- **Omarchy constraints:**
  - plugins run unsandboxed inside the shell;
  - visual widgets share one QML scene graph, so sensitive state must stay outside the reachable graph;
  - symlinks inside a plugin directory are rejected;
  - the manifest cannot register hotkeys.
- **Code-structure reference:** the author's `sviat.nightlight` plugin (github.com/devSviat/omarchy-nightlight):
  - `Service.qml` is a singleton that owns state and processes;
  - `Panel.qml` gets it via `bar?.shell?.serviceFor("<id>")` and uses `manageIpc: false`.
  - Nightlight also ships `indicators/*.qml`; this plugin has none, because its bar icon is the panel's own button.
- **Proton Authenticator vault:** `~/.local/share/me.proton.authenticator/databases/indexeddb/v1/tauri_localhost_0/<hash>/IndexedDB.sqlite3`. It is a WebKit IndexedDB stored in SQLite (WAL mode) with the object stores `items` and `storageKey`.
  - The 32-byte root key lives in the Secret Service: service `com.proton.authenticator`, username = the record's `adapterKeyId` (or `id` for pre-1.1.4 layouts).
  - Storage key = HKDF-SHA256(root key, salt from `storageKey`, info `authenticator;storage-key`).
  - Each item is AES-256-GCM encrypted (12-byte IV prefix, AAD `authenticator;item`). The plaintext is JSON with `entryType` (`Totp`/`Steam`), `secret`, `uri`, `period`, etc.
  - Key sources: 0 = OS keyring (supported), 1 = app password (reported as `APP_LOCKED`), 2 = fallback key stored in the database (refused as `UNSAFE_KEY_STORAGE`).
  - Source of truth for this format: Proton's open-source WebClients code (`applications/authenticator/src/lib/storage-key`, `db/entities`, `crypto.ts`, `src-tauri/src/storage_key.rs`) and `protonpass/proton-pass-common` (GPL-3.0). These are used as a **specification only**; no code is copied.
  - The app has no official CLI or API.
- **Clipboard:** `wl-clipboard` ≥ 2.3 supports `--sensitive`, and Omarchy's clipboard history (`plugins/clipboard/capture.sh`) skips such content.
- **Recommended hotkey:** `Super+Alt+A`. It was free on the author's system; the README tells users to check their own bindings.

## Architecture

The plugin has two parts:

1. **QML plugin (`sviat.proton-authenticator`)**, kinds `service` + `bar-widget`:
   - `Service.qml` owns state, runs the helper and polls vault status;
   - `Panel.qml` is both the bar icon (its own `BarIconButton`) and the panel that drops from it.
2. **Helper (`pa-helper`, Rust)**, a short-lived process. It reads and decrypts the vault, computes codes and puts a code on the clipboard. It is built from source into the plugin directory, and QML calls it **by absolute path inside the plugin directory**, never through `PATH`.

Trust boundary: **TOTP seeds, the derived storage key and decrypted items exist only inside the helper**, and only for one invocation. The vault's root key also passes through the Secret Service, the D-Bus session bus and `/usr/bin/secret-tool` (and its output pipe) on its way in; that is the keyring's own path, not one this plugin adds. QML only ever receives ids, labels (issuer/account) and current codes.

### Helper protocol

Each command prints exactly one JSON line, bounded in size, in an envelope `{"ok":…,"protocol":1,…}`. Errors carry only a machine-readable code, never data.

- `version` → helper version and protocol number. The service compares the version with `manifest.version` and treats any difference as `HELPER_OUTDATED`.
- `check [--demo]` → `status` (`READY` or an error code) and `vaultMtime`, without decrypting anything and without ever opening a keyring prompt. It also verifies that `wl-copy` and `secret-tool` are available.
- `codes [--only <id>] [--allow-prompt] [--demo]` → `now` and `entries` (`id`, `issuer`, `account`, `kind`, `code`, `nextCode`, `period`, `digits`, `remaining`). The output type has no field that could hold a secret.
- `codes --private [--reveal <id>] [--allow-prompt] [--demo]` → the same reply shape, but every entry has only `id`, `issuer` and `account` set; the other fields are present and `null`. The `--reveal` entry, if given, is computed in full. Without `--reveal` nothing is decrypted (labels are cleartext in the vault), and the keyring is touched only with `--allow-prompt`: the root key is then read and dropped, which shows the unlock prompt, so privacy mode can unlock without revealing a code. With `--reveal` only that item is decrypted, under the same lock rules as `codes`. `--reveal` requires `--private`, `--private` excludes `--only`, and an unknown reveal id is `ITEM_NOT_FOUND`.
- `copy <id> [--clear-after <5..120>] [--demo]` → the helper computes the code itself (the next one if 5 s or fewer remain, the same window the panel marks as urgent) and passes it via stdin to a detached holder: a fresh exec of its own binary (`/proc/self/exe`) that leads a new session and process group, with the scrubbed environment. The holder hands the code to `wl-copy --foreground --sensitive --type text/plain` via stdin and confirms with one status byte once `wl-copy` has read the code and is still running after a 250 ms grace period (an exit within it means the code never reached the clipboard and is an `INTERNAL` error; a missing `wl-copy` is `DEPENDENCY_MISSING`). Only then does `copy` reply and exit, so killing the caller (shell restart, plugin reload) cannot strand the code. The holder keeps `wl-copy` alive until the deadline. If `wl-copy` is still the clipboard owner at the deadline, the holder kills it and runs `wl-copy --clear`. If the user copied something else in the meantime, `wl-copy` has already exited and nothing is cleared. `wl-copy` gets SIGTERM if its holder dies, and a non-zero `wl-copy` exit makes the holder exit with a failure. Descriptors inherited without `FD_CLOEXEC` (Quickshell leaks some) are marked close-on-exec before the holder and `wl-copy` are exec'd. No copy or hash of the code is kept.
- `hold --clear-after <5..120>` → internal, started only by `copy`: reads one validated code (5–10 digits or a Steam code) from stdin, never the vault or keyring, and answers with a status byte instead of JSON (`MEMLOCK_FAILED` included when its own hardening fails).
- `prefs get` / `prefs set` → pinned and recent ids plus the privacy flag (see "Stored state").
- Error codes include `VAULT_NOT_FOUND`, `VAULT_BUSY`, `VAULT_FORMAT_CHANGED`, `KEYRING_LOCKED`, `KEYRING_UNAVAILABLE`, `KEY_NOT_FOUND`, `DECRYPT_FAILED`, `APP_LOCKED`, `UNSAFE_KEY_STORAGE`, `DEPENDENCY_MISSING`, `ITEM_NOT_FOUND`, `INVALID_ARGUMENT`, `MEMLOCK_FAILED`, `TIMEOUT`, `OUTPUT_TOO_LARGE`, `INTERNAL`.

### Helper security requirements

- **Process hardening, first thing in `main`:**
  - `prctl(PR_SET_DUMPABLE, 0)`, so there are no core dumps and no ptrace from peers;
  - `RLIMIT_CORE = 0`;
  - `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)`. If it fails, the helper exits with `MEMLOCK_FAILED` (fail closed).
  - The whole helper must fit a typical 8 MiB `RLIMIT_MEMLOCK`. This is verified by a test with a maximum-size vault.
- **Memory hygiene:** keys, seeds and decrypted plaintext live in `Zeroizing` types, and the crypto crates are built with their `zeroize` features. Residual stack copies inside crypto libraries are documented. The real protection is the process hardening above.
- **Panics:** `panic = "abort"` in release builds. Error output never contains vault data.
- **No SQLite in the shipped helper.** Even read-only opens of a WAL database can create or modify `-wal`/`-shm` files next to the vault, so the helper reads the files itself:
  - the main file and `-wal` are opened with `O_NOFOLLOW`, size-capped and checked for stability before and after reading; `-shm` is ignored;
  - committed WAL frames are applied per the documented WAL format (salts and checksums, last valid commit), streamed in two passes;
  - the resulting in-memory image is parsed by a strict, read-only, safe-Rust B-tree reader limited to what the vault needs;
  - any unexpected structure gives `VAULT_FORMAT_CHANGED`.
  - SQLite is used only in tests, as a reference oracle.
- **WebKit value decoding:** a strict decoder for the subset of WebKit's SerializedScriptValue format the vault uses, with bounded allocation, failing closed.
- **No network:** no network code and no network crates.
- **Keyring access:**
  - the lock state is read via `/usr/bin/gdbus` (Secret Service `SearchItems`), which never prompts;
  - the root key is read via `/usr/bin/secret-tool lookup` into a zeroizing buffer;
  - the unlock prompt appears only when the user explicitly presses "Unlock" (`codes --allow-prompt`, with or without `--private`), and that call gets a longer time budget (120 s) so the password can be typed;
  - known race: without `--allow-prompt` the lock state is checked first and the key read right after; a keyring that locks in that window of a few milliseconds makes `secret-tool` show the prompt anyway. The 10 s budget ends the call, and cancelling the prompt is safe.
- **Child processes:** absolute paths, a scrubbed environment (`HOME`, `XDG_RUNTIME_DIR`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS` only), their own process group, bounded output, hard timeouts and whole-group kill. Secrets never go through argv or env.
- **Inputs:** ids validated against `^[A-Za-z0-9._:-]{1,128}$`, flag-like values rejected, all sizes bounded, a global watchdog (10 s; 120 s for the explicit unlock).
- **Dependencies:** minimal (RustCrypto `aes-gcm`, `hkdf`, `hmac`, `sha1`, `sha2`, plus `zeroize`, `serde`/`serde_json` and `libc`). `Cargo.lock` is committed, builds use `--locked`, and `cargo deny` runs in CI. TOTP/HOTP/Steam are implemented in-house per RFC 6238/4226.
- **Algorithms:** SHA1/SHA256/SHA512, 6–8 digits, any period from 1 to 86400 s, and Steam codes. Unsupported entries (e.g. HOTP) are shown as unsupported instead of breaking the list.

### QML security requirements

- QML never receives or stores secrets.
- Codes stay in the model only while the panel is open. Closing the panel clears the model and stops helper calls.
- No `console.log` of data and no notifications with account names.
- Copying is done by the helper (`copy <id>`). QML never runs `wl-copy` with a code.
- Privacy mode (Ctrl+H): only a row the user chose shows its code, and hidden codes are never loaded into QML. Nothing is revealed on open or while typing: a row is chosen by a keyboard move, Enter or a click, never by the default first-row selection or a resting pointer; Enter or a click on a hidden row reveals it instead of copying. The panel lists and searches rows from `codes --private` and fetches the chosen row's code with `codes --private --reveal <id>`.

## Project architecture

### Repository layout

```
manifest.json            # Omarchy manifest
Service.qml              # state and processes (singleton)
Panel.qml                # rendering only
components/              # panel components (row, search field, footer, empty states)
helper/                  # Rust crate pa-helper
install.sh
README.md, LICENSE, preview.png
docs/                    # specs, plan
.github/workflows/ci.yml # fmt, clippy, test, memlock budget test, MSRV build, cargo deny allow-list, node tests, version equality
```

### Helper layers and patterns

**Functional core / imperative shell** with **ports & adapters**: pure logic without I/O in the middle, all I/O behind traits at the edges.

- `main.rs`: a thin entry point. Hardening, then argument parsing, then one use-case, then one JSON line and an exit code.
- `sys`: the **only module allowed to contain `unsafe`** (prctl, rlimits, mlockall, setsid, dup2, kill). Every block carries a SAFETY comment; the rest of the crate denies `unsafe_code`.
- `cli`: hand-written strict argument parsing, no `clap`.
- `app`: the use-cases (`check`, `codes`, `copy`) and the `KeyProvider` port.
- `domain`:
  - `Secret` (no `Serialize`/`Clone`/`Display`; `Debug` prints `[REDACTED]`);
  - `Entry`;
  - `EntryView`, which has no secret field by construction.
- `otp`, `base32`, `uri`: pure functions, fully tested against RFC vectors.
- `vault`, `wal`, `sqlite_file`, `ssv`: vault file access, WAL application, the B-tree reader and the WebKit value decoder.
- `crypto`: HKDF and AES-GCM.
- `keyring`, `proc`: Secret Service access through bounded child processes.
- `clipboard`: the `Clipboard` port and the `WlCopy` holder.
- `prefs`: the small state file.
- `error`: `ErrorCode` without payloads.

### QML layers

- **`Service.qml`**: the single source of truth and an explicit state machine (`Loading → Ready | Error(code)`). It is the only place that runs the helper, through one `HelperClient` wrapper that owns the absolute path, timeouts, size limits, JSON parsing and error mapping.
- **`Panel.qml` and `components/`**: rendering and keyboard navigation only. `Panel.qml`'s own bar button shows the `check` status.

## Development and review process

- Every implementation task gets a code review and a security review before the next task starts.
- Before the `dev → main` PR and before publishing, a full repository security audit plus the manual checks under "Testing" are performed.
- New dependencies need a justification and a `cargo deny` pass.

## Sync and data refresh

- While the panel is open the service polls `check` every 5 s (every 60 s while closed). A changed `vaultMtime` triggers a reload, so new accounts appear automatically whenever the official app has synced.
- While the panel is open `codes` is requested **once per period boundary**, not every second. Countdown rings tick locally.
- The panel header shows "Updated N ago" (the vault's last local change, worded honestly).
- The footer always has a Sync button. If the vault has not changed for longer than a threshold (setting, default 24 h), a subtle "Not synced for …" hint appears next to it.
- **Sync** starts `/usr/bin/proton-authenticator`. The plugin picks up the change once the app has written the vault. The app (1.1.6) has no tray, background or start-hidden mode, so Sync opens its normal window (see `docs/notes/proton-tray.md`).
- The official app is **not** started automatically when the panel opens: it is slow and takes focus.
- On `VAULT_FORMAT_CHANGED` the panel shows a clear message and an "Open Proton" button, never partial data.

## UX and UI

Layout **A, a list under the bar**, was chosen.

- **Opening:** a click on the bar icon or `Super+Alt+A` (`omarchy-shell shell toggle sviat.proton-authenticator`). Focus goes straight to the search field.
- **Row:** issuer icon, issuer, account (elided), the code in a large monospace font (grouped, e.g. `482 913`) and a countdown ring. The code and ring turn red in the last 5 s.
- **Issuer icons:** monochrome brand glyphs from the Nerd Font the bar already uses, looked up by a normalized issuer name; the issuer's initial when no glyph matches. No icon files and no network.
- **Next code:** shown only on the selected row, only in the last 5 s.
- **Search:** fuzzy over issuer and account (`gh` → GitHub). Order: pinned, then recently used, then alphabetical.
- **Keys** (every action on Ctrl, so typing never triggers one):
  - `Enter` copies;
  - `↑↓` or `Ctrl+J/K` move the selection, and `PgUp/PgDn` move faster;
  - `Esc` clears the search first, then closes the panel;
  - `Ctrl+P` pins or unpins;
  - `Ctrl+H` toggles privacy mode (remembered).
- **After copying:** a brief "Copied ✓" in the row, then the panel closes (configurable). The clipboard is cleared after 20 s (configurable).
- **Bar icon:** the panel's own button, showing status only (ready, keyring locked, vault missing, format changed, dependencies missing, helper missing or outdated), from `check` and `version`, with no decryption.
- **Style:** colors and fonts from the current Omarchy theme via the standard UI kit, with no hard-coded colors.
- **Empty and error states:** no accounts; keyring locked (with Unlock); Proton Authenticator not found; format changed; app lock on; unsafe key storage; helper missing or outdated (with the exact install command).
- **Demo mode** with fake accounts (public RFC test seeds), for screenshots and UI work. It never touches the vault or the keyring.
- **UI copy:** English.

### Settings (`barWidget.schema`)

| Key | Type | Default |
|---|---|---|
| `clearClipboardSeconds` | integer 5–120 | 20 |
| `closeOnCopy` | boolean | true |
| `staleHours` | integer 1–168 | 24 |

### Stored state

Pinned and recently used accounts are stored as **ids only** (no labels) in `$XDG_STATE_HOME/sviat.proton-authenticator/prefs.json`, together with the privacy flag:
- the directory is 0700 and the file 0600;
- writes are atomic (exclusive temp file, fsync, rename);
- reads use `O_NOFOLLOW`.

## Installation and publishing

- **Repository:** `github.com/devSviat/omarchy-proton-authenticator`, public, MIT license. No code is copied from GPL projects. Development happens on `dev`; `main` only changes through pull requests.
- **App lock (Proton Authenticator PIN/password):** when it is enabled, the vault key is derived from the app password and the helper reports `APP_LOCKED`. The README explains this. PIN support in the plugin may be added later if requested.
- **Manifest:** `id` `sviat.proton-authenticator`, `name` "Proton Authenticator", `author` "devSviat", `kinds` `["service","bar-widget"]`.
- **`install.sh`:**
  - checks dependencies (`cargo`, `libsecret`/`secret-tool`, `glib2`/`gdbus`, `wl-clipboard` ≥ 2.3, `proton-authenticator`);
  - builds the helper (`cargo build --release --locked`) outside the plugin directory and installs only the binary;
  - refuses to run when piped (`curl | bash`);
  - never uses `sudo`;
  - names the package to install when something is missing.
- **Updates:** `omarchy plugin add`/`update` only clone or pull. The service runs `pa-helper version` at load, after a manifest rescan and after a missing or outdated helper, and compares it with `manifest.version` (CI keeps `helper/Cargo.toml` and `manifest.json` equal); every reply's protocol is checked too. When the helper is missing or outdated it shows "Run install.sh" with the exact command and runs neither `codes` nor `copy`. Building fetches crates from crates.io, pinned by `Cargo.lock`; this is the only network step and it happens only at install time.
- **Catalog:** listed as "Manual setup". `omarchy-plugin-validate` must pass.
- **README:**
  - an honest threat model (see "Non-goals");
  - dependencies;
  - the recommended hotkey;
  - how sync works;
  - what to do when the vault format changes after a Proton update.

## Testing

- **Rust:**
  - RFC 4226/6238 vectors (SHA1/256/512) and Steam codes;
  - decryption tests on **synthetic** vaults built by the tests themselves (known key, fake entries). No real secrets or real vaults live in the repository;
  - differential tests of the WAL applier and B-tree reader against real SQLite;
  - truncation and mutation fuzzing of every parser;
  - a test for every error code;
  - the memlock budget test with a maximum-size vault.
- **Manual security checks:**
  - `VmLck` > 0 for a running helper;
  - core dumps disabled;
  - `strace -f`: no writes outside the prefs file, no sockets except D-Bus from the child tools;
  - no secret in `ps`, `/proc/*/cmdline` or `environ`;
  - no code in Omarchy's clipboard history.
- **Live:** the author's real vault, comparing codes with the official app; a new account added on the phone must appear after the official app syncs, without restarting the shell.

## Left to the implementation

- How to watch for vault changes beyond `check` polling, if polling proves insufficient.
