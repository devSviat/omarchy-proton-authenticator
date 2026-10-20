# Proton Authenticator for Omarchy

![The panel in demo mode on the default Tokyo Night theme](preview.png)

The panel follows the active Omarchy theme; here it is on a dark custom theme:

![The panel in demo mode on a dark custom theme](docs/screenshots/abstract-black.png)

Your [Proton Authenticator](https://proton.me/authenticator) 2FA codes in a keyboard-driven
panel on the Omarchy bar: press a hotkey, type a few letters, press Enter, and the code is
on the clipboard.

The official desktop app is a full window, and opening it just to read one code is slow.
This plugin reads the app's **local vault, read-only**, and shows the codes from the bar
instead. Adding accounts and syncing with Proton stay with the official app; the plugin
never touches the network and never writes to the vault.

This is an independent implementation. Other Proton Authenticator plugins in the catalog
were not audited, and nothing here is a claim about them.

## Requirements

- Omarchy 4 (developed and tested on 4.0.6).
- The official app, `proton-authenticator` 1.1.x (AUR: `proton-authenticator-bin`), set
  up and synced at least once, with its key stored in the system keyring (the default).
- A Secret Service keyring. Omarchy ships `gnome-keyring`.
- Packages `install.sh` checks for, by Arch package name:

  | Package | Used for |
  | --- | --- |
  | `rustup` (then `rustup default stable`) or `rust` | building the helper (Rust 1.89 or newer) |
  | `libsecret` | `/usr/bin/secret-tool`, which reads the vault key from the keyring |
  | `glib2` | `/usr/bin/gdbus`, which asks the keyring whether it is locked |
  | `wl-clipboard` 2.3 or newer | `/usr/bin/wl-copy --sensitive` |

- A locked-memory limit (`ulimit -l`) of at least 8192 KiB. That is systemd's default, so
  most systems already have it. See [MEMLOCK_FAILED](#troubleshooting).

## Install

The catalog lists this plugin as **Manual setup**: adding it only clones the repository,
and the helper has to be built once.

```bash
omarchy plugin add https://github.com/devSviat/omarchy-proton-authenticator
cd ~/.config/omarchy/plugins/sviat.proton-authenticator
./install.sh
omarchy plugin enable sviat.proton-authenticator
```

`install.sh`:

- checks the dependencies above and names the package for anything missing; it installs
  nothing itself;
- builds `pa-helper` with `cargo build --release --locked` into
  `~/.cache/sviat.proton-authenticator/target` and copies only the binary to `bin/pa-helper`
  in the plugin directory;
- runs `bin/pa-helper version` to confirm the build works and speaks the expected protocol.

It never uses `sudo`, refuses to run as root, and refuses to run when piped
(`curl … | bash`) or sourced: it has to be run from a clone. Its only network access is
cargo downloading the crates pinned by `Cargo.lock` from crates.io.

### Updating

```bash
omarchy plugin update sviat.proton-authenticator
cd ~/.config/omarchy/plugins/sviat.proton-authenticator && ./install.sh
```

`omarchy plugin update` only pulls the repository, so re-run `install.sh` after every
update. The panel compares the helper's version with the plugin's: if the helper is
missing or was built from another version, the panel says so, loads no codes, and offers
to copy the exact command.

### Removing

```bash
omarchy plugin remove sviat.proton-authenticator
rm -rf ~/.cache/sviat.proton-authenticator ~/.local/state/sviat.proton-authenticator
```

The second line removes the build cache and the stored pins and settings.

## Usage

Click the plugin's bar icon, or bind a key. `Super + Alt + A` is a good fit; add this to
`~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + ALT + A", "Proton Authenticator", "omarchy-shell shell toggle sviat.proton-authenticator")
```

Check that the combination is free on your system first:
`omarchy menu keybindings --print`.

The panel opens with the search field focused. Search is fuzzy over issuer and account, so
`gh` finds GitHub.

| Key | Action |
| --- | --- |
| `Enter` | Copy the selected code (in privacy mode, a hidden row is revealed first) |
| `↑` `↓`, `Ctrl+J` `Ctrl+K` | Move the selection |
| `PgUp` `PgDn` | Move five rows |
| `Esc` | Clear the search; close the panel when it is already empty |
| `Ctrl+P` | Pin or unpin the selected account |
| `Ctrl+H` | Toggle privacy mode |
| `Tab`, `Shift+Tab` | Switch to the neighbouring bar panel |

Every action is on a non-letter key or a `Ctrl` chord, so typing never triggers one.
Clicking a row selects it and copies its code; in privacy mode a hidden row is revealed
first, and a second click or Enter copies it.

After copying, the row shows "Copied ✓" and the panel closes (`closeOnCopy`). If 5 seconds
or less of the current code remain, the next code is copied instead; the selected row also
shows the next code during those last seconds. The clipboard is cleared after 20 seconds
(`clearClipboardSeconds`), unless you have copied something else in the meantime.

**Order.** Pinned accounts come first, then the five most recently copied, then the rest
alphabetically. Copying changes the recent order on the next open, so rows never move
while you are looking at them; pins apply at once.

**Privacy mode** (`Ctrl+H`, remembered) hides every code except the row you choose. Nothing
is revealed when the panel opens or while you type: a code appears only once you choose its
row with `↑` `↓`, `Enter` or a click. Hovering with the mouse highlights a row without
revealing it. Hidden codes are not computed at all, not merely masked on screen. The header
shows `PRIVATE` while it is on.

**Unsupported entries** such as HOTP counters are listed as "unsupported" rather than
breaking the list. TOTP (SHA-1, SHA-256, SHA-512) and Steam codes are supported.

**Limits.** The plugin reads a vault of at most 1000 items; with more, it lists nothing and
says "More than 1000 accounts". It also fails closed, showing nothing rather than partial
data, when the vault database is larger than 2 MiB, when a stored field exceeds 64 KiB, or
when any single item cannot be read or decrypted.

### Sync

The plugin reads what the official app has stored locally; it does not sync. The panel
header shows when the vault last changed ("updated 2 h ago"), and the footer has a
**Sync** link that opens the official app so it can sync with Proton. The app has no tray
or background mode (checked for 1.1.6, see [docs/notes/proton-tray.md](docs/notes/proton-tray.md)),
so it opens its normal window; close it once it has synced.

The plugin checks the vault every 5 seconds while the panel is open and every 60 seconds
otherwise. New accounts appear on their own once the app has written them. If the vault
has not changed for longer than `staleHours`, the footer shows "Not synced for …".

The app is never started automatically: it is slow and takes focus.

### Settings

Set them in the bar widget's settings, or with `omarchy bar set`.

| Key | Default | Meaning |
| --- | --- | --- |
| `clearClipboardSeconds` | `20` | Clear the copied code after this many seconds (5–120) |
| `closeOnCopy` | `true` | Close the panel after copying |
| `staleHours` | `24` | Show the "Not synced" hint after this many hours without a vault change (1–168) |

### Demo mode

For screenshots and UI work, the panel can show fake accounts built from the public
RFC 4226/6238 test seeds. Demo mode never reads the vault or the keyring, and pins made in
it are not saved.

```bash
omarchy bar set sviat.proton-authenticator demo true --json
omarchy bar set sviat.proton-authenticator demo false --json
```

The setting is deliberately absent from the settings UI.

## Troubleshooting

The bar icon reflects the status without decrypting anything; its tooltip and the panel
say what is wrong.

| Panel says | Meaning and fix |
| --- | --- |
| Keyring is locked | Press **Unlock** (or Enter). Your keyring's password prompt appears; the plugin never opens it on its own. |
| Proton Authenticator not found | No vault under `~/.local/share/me.proton.authenticator`. Install the official app, sign in and let it sync once. |
| Vault format not recognised | The vault did not match the expected format, usually after a Proton Authenticator update, or after a system WebKitGTK update (the app stores its vault through WebKit's IndexedDB). It is also shown when the vault exceeds the limits above or one item cannot be read. The plugin shows nothing rather than partial data. Codes are still in the official app (**Open Proton**). Update the plugin; if the problem remains, open an issue with the app and WebKitGTK versions. Never attach your vault. |
| More than 1000 accounts | The vault holds more items than the plugin reads (`OUTPUT_TOO_LARGE`). Use the official app (**Open Proton**). |
| App lock is on | The official app's PIN/password lock is enabled. The vault key is then derived from that password and is not in the keyring, so the plugin cannot read it (`APP_LOCKED`). Turn the app lock off in the official app to use the plugin. |
| Proton is storing its key outside the keyring | The app keeps its key in its own database instead of the keyring. The plugin refuses that layout (`UNSAFE_KEY_STORAGE`). Make sure a keyring is running and open the official app; the plugin works once the app stores its key in the keyring. |
| No Secret Service keyring is running / The vault key is not in the keyring | Start the keyring (`gnome-keyring` on Omarchy) and open the official app once. |
| Run install.sh | The helper is missing, outdated, or a required tool is missing. Run the shown command (**Copy command** puts it on the clipboard). |
| The helper could not lock its memory | `MEMLOCK_FAILED`: the helper refuses to run without locked memory. Check `ulimit -l` in a new terminal; it needs at least `8192`. Raising it takes root, e.g. `DefaultLimitMEMLOCK=` in systemd's `system.conf`/`user.conf` or `/etc/security/limits.conf`. |
| The vault is being written | The app was writing while the plugin read; it retries on the next check. |

## Security

Priorities, in order: security, reliability, UX, UI. The design and threat model are in
[the spec](docs/superpowers/specs/2026-10-20-proton-authenticator-plugin-design.md).

### What it protects

- **Secrets stay out of the shell.** TOTP seeds and decrypted items exist only inside
  `pa-helper`, one short-lived process per request. The vault's root key is read from the
  keyring by `/usr/bin/secret-tool`, so it also passes through the Secret Service, the
  D-Bus session bus and `secret-tool`'s output pipe on its way into the helper. The panel
  (QML) only ever receives ids, issuer and account labels, and current codes. Codes are
  dropped when the panel closes.
- **The helper is hardened** before it reads anything: it is non-dumpable
  (`PR_SET_DUMPABLE 0`, so no core dumps and no ptrace by other processes of the same
  user), sets `RLIMIT_CORE` to 0, and locks all its memory with `mlockall` so nothing is
  swapped out. If locking fails it exits (`MEMLOCK_FAILED`). Keys, seeds and decrypted
  data are held in zeroizing buffers; this is best effort, since crypto libraries may
  leave copies on the stack. Release builds abort on panic, and errors carry only a code,
  never vault data.
- **No network.** The helper has no network code and no network crates.
- **Read-only vault access.** The vault is a SQLite database in WAL mode, and even a
  read-only SQLite open can create or modify files next to it. So the helper does not use
  SQLite at all: it reads the database and WAL files itself (`O_NOFOLLOW`, size-capped,
  checked for stability) with its own strict B-tree and WAL reader, and never writes to the
  vault directory. Anything unexpected is reported as a format change.
- **No secrets in argv, environment or logs.** The vault key is read from `secret-tool`'s
  output, and codes are passed to child processes over stdin. Child processes run by
  absolute path with a scrubbed environment and hard timeouts.
- **Clipboard.** The code is handed to `wl-copy --sensitive`, which Omarchy's clipboard
  history skips. A detached holder process keeps it on the clipboard, survives shell
  restarts, and after the timeout clears the clipboard only if it still holds the code.
- **Privacy mode** decrypts at most one entry per request; labels are stored unencrypted in
  the vault, so listing them needs no decryption.
- **Issuer icons** are brand glyphs from the Nerd Font the bar already uses, monochrome,
  with the issuer's initial as a fallback. Nothing is downloaded. (For comparison, the
  official app's issuer list points almost all logos at Google's favicon service:
  1187 of 1227 entries in
  [`issuerInfos.txt`](https://github.com/protonpass/proton-pass-common/blob/0ed0a269be460bada538a5b5d58a1ddae79a238b/proton-authenticator/resources/issuerInfos.txt)
  use `t0.gstatic.com`.)
- **Stored state** is ids only: pinned and recent account ids and the privacy flag, in
  `~/.local/state/sviat.proton-authenticator/prefs.json` (directory 0700, file 0600,
  atomic writes).

### What it does not protect against

- **Malware running as your user.** Such a process can read the vault and fetch its key
  from the Secret Service itself, which has no per-application access control. The plugin
  aims to add no new leak channel, not to defend beyond that boundary.
- **Account ids in process arguments.** Requests such as `copy <id>` name the account by
  its opaque vault id, which other processes of your user can see in the process list and
  which may appear in the shell's logs. Codes, labels and secrets are never passed this way.
- **`wl-copy` itself.** It may buffer the copied code in a temporary file of its own while
  it holds the clipboard; that is outside the helper's control.
- **Pasting.** Once you paste a code, the receiving application has it.
- **Clipboard managers that persist the selection.** A manager that copies the code into a
  selection of its own keeps it past the clear deadline: the plugin can only clear what
  `wl-copy` still owns. When such a manager takes the selection at once, the copy still
  counts as successful and nothing is cleared.
- **A keyring that locks mid-request.** Without **Unlock** the helper first asks whether
  the keyring is unlocked and only then reads the key. If the keyring locks in the few
  milliseconds between the two, the keyring's own unlock prompt can appear without you
  pressing **Unlock**; the helper gives up after 10 seconds, and cancelling it is safe.

## Development

```
manifest.json      Omarchy plugin manifest
Service.qml        state and the only place that runs the helper
HelperClient.qml   runs pa-helper by absolute path, parses its one-line JSON replies
Panel.qml          the bar icon (its own button) and the panel, rendering only
Model.js           pure logic: ordering, search, states, issuer glyphs
components/        panel rows, search field, footer, empty states
helper/            pa-helper, the Rust crate
tests/             Node tests for Model.js and the panel logic
install.sh
```

To work on a checkout, link it in place of the cloned plugin
(`ln -s ~/path/to/checkout ~/.config/omarchy/plugins/sviat.proton-authenticator`), run
`./install.sh` from it, and restart the shell with `omarchy restart shell` after QML edits.

Tests:

```bash
cd helper
cargo test --locked
cargo test --locked --release --features budget-probe --test budget   # locked-memory budget
cd ..
node --test tests/*.test.mjs
```

The Rust tests use synthetic vaults built by the tests themselves; no real vault or secret
is in the repository. SQLite is used only there, as a reference to check the helper's own
reader against. The budget test loads a maximum-size vault and checks that the helper stays
within an 8 MiB memory-lock limit.

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `clippy` with warnings as errors,
the tests including the budget test, a build on the minimum Rust version, `cargo deny`
with an allow-list of the reviewed crates, the Node tests, and a check that the helper and
manifest versions match.

## License

MIT, see [LICENSE](LICENSE).

This project is not affiliated with, endorsed by, or supported by Proton AG. Proton and
Proton Authenticator are trademarks of Proton AG; other names and brand glyphs belong to
their respective owners.
