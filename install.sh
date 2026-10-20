#!/bin/bash

# Builds pa-helper from this checkout and installs only the binary into bin/.
# Run it from a clone: ./install.sh
# Nothing here uses sudo; missing packages are named, not installed.

# Sourcing would run this inside the caller's shell, set -e and all.
# zsh sets no BASH_SOURCE, so the check below cannot see it; keep this first
# and in syntax both shells parse.
if [ -n "${ZSH_VERSION:-}" ]; then
  echo "install.sh: run it with bash, do not source it: ./install.sh" >&2
  return 1 2>/dev/null || exit 1
fi

if [[ -n ${BASH_SOURCE[0]:-} && ${BASH_SOURCE[0]} != "$0" ]]; then
  echo "install.sh: run it, do not source it: ./install.sh" >&2
  return 1
fi

set -euo pipefail

PLUGIN_ID="sviat.proton-authenticator"

# Piped or eval'd copies (curl | bash, bash -c "$(cat install.sh)") have no
# script file behind them, so there is no checkout to build from.
script="${BASH_SOURCE[0]:-}"
if [[ -z $script || ! -f $script ]]; then
  echo "install.sh: run it from a clone of the repository, not through a pipe." >&2
  exit 1
fi
REPO="$(cd "$(dirname "$script")" && pwd -P)"
if [[ ! "$REPO/install.sh" -ef "$script" || ! -f "$REPO/helper/Cargo.toml" ]] ||
  ! grep -qF "\"id\": \"$PLUGIN_ID\"," "$REPO/manifest.json" 2>/dev/null; then
  echo "install.sh: $script is not inside a $PLUGIN_ID checkout." >&2
  exit 1
fi

if (( EUID == 0 )); then
  echo "install.sh: do not run this as root." >&2
  exit 1
fi

missing=0
need() {
  local ok="$1" what="$2" package="$3"
  if [[ $ok == "yes" ]]; then
    echo "  ok       $what"
  else
    echo "  missing  $what  (install: $package)" >&2
    missing=1
  fi
}
present() { [[ -x $1 ]] && echo yes || echo no; }

# rustup installs cargo under ~/.cargo/bin, which non-login shells often lack.
CARGO="$(command -v cargo || true)"
[[ -z $CARGO && -x "$HOME/.cargo/bin/cargo" ]] && CARGO="$HOME/.cargo/bin/cargo"

echo "Checking dependencies"
need "$([[ -n $CARGO ]] && echo yes || echo no)" "cargo" "pacman: rustup (then: rustup default stable) or rust"
need "$(present /usr/bin/secret-tool)" "/usr/bin/secret-tool" "pacman: libsecret"
need "$(present /usr/bin/gdbus)" "/usr/bin/gdbus" "pacman: glib2"
if [[ -x /usr/bin/wl-copy ]] && /usr/bin/wl-copy --help 2>&1 | grep -q -- '--sensitive'; then
  need yes "/usr/bin/wl-copy (--sensitive)" ""
else
  need no "/usr/bin/wl-copy with --sensitive" "pacman: wl-clipboard (2.3 or newer)"
fi
need "$(present /usr/bin/proton-authenticator)" "/usr/bin/proton-authenticator" "AUR: proton-authenticator-bin"

if (( missing )); then
  echo "install.sh: install the missing packages above, then run it again." >&2
  exit 1
fi

TARGET_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/$PLUGIN_ID/target"

echo
echo "Building pa-helper (crates come from crates.io, pinned by Cargo.lock)"
CARGO_TARGET_DIR="$TARGET_DIR" "$CARGO" build --release --locked \
  --manifest-path "$REPO/helper/Cargo.toml"

mkdir -p "$REPO/bin"
install -m 0755 "$TARGET_DIR/release/pa-helper" "$REPO/bin/pa-helper"

if ! reply="$("$REPO/bin/pa-helper" version)"; then
  echo "install.sh: bin/pa-helper was built but does not run: $reply" >&2
  if [[ $reply == *MEMLOCK_FAILED* ]]; then
    echo "  It locks its memory and needs ulimit -l of at least 8192 KiB (now: $(ulimit -l))." >&2
  fi
  exit 1
fi
if [[ ! $reply =~ \"protocol\":1[,}] ]]; then
  echo "install.sh: bin/pa-helper does not speak protocol 1: $reply" >&2
  exit 1
fi

echo
echo "Installed $REPO/bin/pa-helper ($reply)"
echo "Enable the plugin with: omarchy plugin enable $PLUGIN_ID"
