# Security model

Priorities, in order: security, reliability, UX, UI. The design and its reasoning are in
[the design spec](superpowers/specs/2026-10-20-proton-authenticator-plugin-design.md).
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What it protects

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

## What it does not protect against

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
