# Troubleshooting

The bar icon reflects the status without decrypting anything; its tooltip and the panel
say what is wrong.

| Panel says | Meaning and fix |
| --- | --- |
| Keyring is locked | Press **Unlock** (or Enter). Your keyring's password prompt appears; the plugin never opens it on its own. |
| Proton Authenticator not found | No vault under `~/.local/share/me.proton.authenticator`. Install the official app, sign in and let it sync once. |
| Vault format not recognised | The vault did not match the expected format, usually after a Proton Authenticator update, or after a system WebKitGTK update (the app stores its vault through WebKit's IndexedDB). It is also shown when the vault exceeds the [limits](#limits) or one item cannot be read. The plugin shows nothing rather than partial data. Codes are still in the official app (**Open Proton**). Update the plugin; if the problem remains, open an issue with the app and WebKitGTK versions. Never attach your vault. |
| More than 1000 accounts | The vault holds more items than the plugin reads (`OUTPUT_TOO_LARGE`). Use the official app (**Open Proton**). |
| App lock is on | The official app's PIN/password lock is enabled. The vault key is then derived from that password and is not in the keyring, so the plugin cannot read it (`APP_LOCKED`). Turn the app lock off in the official app to use the plugin. |
| Proton is storing its key outside the keyring | The app keeps its key in its own database instead of the keyring. The plugin refuses that layout (`UNSAFE_KEY_STORAGE`). Make sure a keyring is running and open the official app; the plugin works once the app stores its key in the keyring. |
| No Secret Service keyring is running / The vault key is not in the keyring | Start the keyring (`gnome-keyring` on Omarchy) and open the official app once. |
| Run install.sh | The helper is missing, outdated, or a required tool is missing. Run the shown command (**Copy command** puts it on the clipboard). |
| The helper could not lock its memory | `MEMLOCK_FAILED`, see [below](#memlock_failed). |
| The vault is being written | The app was writing while the plugin read; it retries on the next check. |

## Limits

The plugin reads a vault of at most 1000 items; with more, it lists nothing and
says "More than 1000 accounts". It also fails closed, showing nothing rather than partial
data, when the vault database is larger than 2 MiB, when a stored field exceeds 64 KiB, or
when any single item cannot be read or decrypted.

## MEMLOCK_FAILED

The helper refuses to run without locked memory. Check `ulimit -l` in a new terminal; it
needs at least `8192` (KiB), which is systemd's default. Raising it takes root, e.g.
`DefaultLimitMEMLOCK=` in systemd's `system.conf`/`user.conf` or `/etc/security/limits.conf`.
