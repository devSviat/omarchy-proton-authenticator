# Development

## Layout

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

## Working on a checkout

Link the checkout in place of the cloned plugin
(`ln -s ~/path/to/checkout ~/.config/omarchy/plugins/sviat.proton-authenticator`), run
`./install.sh` from it, and restart the shell with `omarchy restart shell` after QML edits.

## Tests

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

## CI

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `clippy` with warnings as errors,
the tests including the budget test, a build on the minimum Rust version, `cargo deny`
with an allow-list of the reviewed crates, the Node tests, and a check that the helper and
manifest versions match.

## Demo mode

For screenshots and UI work, the panel can show fake accounts built from the public
RFC 4226/6238 test seeds. Demo mode never reads the vault or the keyring, and pins made in
it are not saved.

```bash
omarchy bar set sviat.proton-authenticator demo true --json
omarchy bar set sviat.proton-authenticator demo false --json
```

The setting is deliberately absent from the settings UI.
