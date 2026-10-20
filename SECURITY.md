# Security policy

This plugin handles 2FA secrets, so security reports are taken seriously and handled first.

## Supported versions

Only the latest release on `main` receives fixes. After updating the plugin, re-run `./install.sh`
so the helper binary matches the plugin version (the panel shows "Run install.sh" until it does).

## Reporting a vulnerability

Please report privately through GitHub:
**Security → Report a vulnerability** on this repository
(https://github.com/devSviat/omarchy-proton-authenticator/security/advisories/new).

Do not open a public issue for security problems, and never include real TOTP codes, seeds,
vault files, keyring contents or account names in a report. A minimal reproduction with the
demo mode or a synthetic vault is ideal.

Expect an acknowledgement within a few days. Fixed issues are credited in the release notes
unless you prefer otherwise.

## Scope

In scope: anything that lets the plugin or its helper leak secrets (to disk, swap, core dumps,
process arguments, environment, logs, the QML scene, notifications or clipboard history), write to
the Proton vault or its directory, reach the network, crash or hang on a malformed vault, or run
code it should not.

Out of scope, by design (see the [threat model](docs/security.md)): malware already running as the same user,
which can read the vault key from the Secret Service directly, and clipboard managers that persist
the selection beyond the plugin's clear deadline.
