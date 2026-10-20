# Proton Authenticator: tray and background start

Question: does the desktop app (1.1.6, `proton-authenticator-bin`, `/usr/bin/proton-authenticator`) support a tray, a hidden/minimized start or autostart that the plugin could use for Sync?

Result: no. The app has no tray icon, no background mode and no start-hidden CLI flag. `openProton()` therefore launches the normal window with no arguments.

## Evidence

Source: ProtonMail/WebClients, `applications/authenticator/src-tauri` (default branch at the time of the check).

- `src-tauri/src/lib.rs`
  - The `main` window is created unconditionally in `setup` with `WebviewWindowBuilder` (800x600, no `visible(false)`).
  - Registered plugins: log, window-state, process, updater, single-instance, store, fs, dialog, opener, http.
  - No CLI plugin and no argument parsing. The single-instance callback ignores `_args` and only focuses the `main` window.
  - No `TrayIconBuilder`, no menu, no `on_window_event` close interception.
- `src-tauri/Cargo.toml`: no `tauri-plugin-cli`, no `tauri-plugin-autostart`. The `tauri` dependency has an empty feature list, so the `tray-icon` feature is not enabled.
- `src-tauri/tauri.conf.json`: no `trayIcon` section, no window definitions, no CLI plugin config.
- Code search in `applications/authenticator` for "tray" matches only `Cargo.lock`; "autostart" and "minimize" have no matches.

Local checks (static only, the binary was never executed):

- `strings` on `/usr/bin/proton-authenticator` shows `plugin:tray|*` entries and `core:tray:default`. These are Tauri's built-in command and permission names, present in every Tauri 2 build, not evidence of an app tray.
- No app-specific CLI flags found (`--hidden`, `--minimized`, `--background`, and similar).
- `~/.local/share/me.proton.authenticator/preferences.dat` is 40 bytes and holds only a theme setting (`theme` = `auto`). No tray, autostart or minimize keys.
- No `proton-authenticator` entry in `~/.config/autostart`.

## Consequences for the plugin

- Sync opens the app window; the user closes it manually after the sync finishes.
- A second launch while the app is running only focuses the existing window (single-instance plugin).
- `window-state` restores the last window geometry; it does not hide the window.

## Re-check when the app updates

Look for a tray or start-hidden option in the WebClients repo (`lib.rs`, `Cargo.toml`, the settings UI) before adding any flag to `openProton()`.
