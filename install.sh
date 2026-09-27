#!/bin/sh
# FlowSight installer for machines that are not OPNsense or pfSense (they use a pkg).
#
#   curl -fsSL https://github.com/grioghar/flowsight/releases/latest/download/install.sh | sh
#   FLOWSIGHT_VERSION=1.0.0 ./install.sh          pin a version
#   ./install.sh --binary ./flowsightd            install a local build
#   ./install.sh --dry-run                        show what would be done; change nothing
#   ./install.sh --yes                            do not ask before applying
#
# This script only fetches the right binary. The binary installs itself:
# `flowsightd install` works out what this machine is, shows its plan, asks,
# applies it, keeps a backup of anything it replaces and checks the result.
set -eu
REPO="grioghar/flowsight"
VERSION="${FLOWSIGHT_VERSION:-latest}"
BIN_SRC=""
MODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BIN_SRC="$2"; shift 2 ;;
        --dry-run) MODE="-dry-run"; shift ;;
        --yes) MODE="-yes"; shift ;;
        *) printf '  unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

say() { printf '  %s\n' "$*"; }
fail() { printf '  ERROR: %s\n' "$*" >&2; exit 1; }
[ "$MODE" = "-dry-run" ] || [ "$(id -u)" = "0" ] || fail "run as root (or with --dry-run to see the plan)"

OS="$(uname -s | tr 'A-Z' 'a-z')"; ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) fail "unsupported architecture $ARCH" ;; esac
case "$OS" in linux|freebsd) ;; *) fail "unsupported OS $OS" ;; esac
[ -x /usr/local/sbin/opnsense-version ] && fail "this is OPNsense: install the os-flowsight package instead"
grep -qx pfSense /etc/platform 2>/dev/null && fail "this is pfSense: install the pfSense-pkg-flowsight package instead (pkg add with the release's .pkg)"

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
if [ -n "$BIN_SRC" ]; then
    cp "$BIN_SRC" "$TMP"
else
    if [ "$VERSION" = "latest" ]; then URL="https://github.com/$REPO/releases/latest/download/flowsightd-$OS-$ARCH"
    else URL="https://github.com/$REPO/releases/download/v$VERSION/flowsightd-$OS-$ARCH"; fi
    say "downloading $URL"
    if command -v curl >/dev/null; then curl -fsSL -o "$TMP" "$URL"; else fetch -qo "$TMP" "$URL"; fi
fi
chmod 755 "$TMP"
"$TMP" -version >/dev/null 2>&1 || fail "the downloaded file is not a flowsightd for $OS/$ARCH"

# Ask on the terminal when there is one: piped from curl, this script's own
# standard input is the script, not the keyboard.
set +e
if [ -z "$MODE" ] && [ -t 1 ] && { : </dev/tty; } 2>/dev/null; then
    "$TMP" install </dev/tty
elif [ -z "$MODE" ]; then
    "$TMP" install -yes
else
    "$TMP" install "$MODE"
fi
status=$?
set -e
if [ "$MODE" != "-dry-run" ] && [ $status -eq 0 ]; then
    echo
    say "UI: http://127.0.0.1:8080  (tunnel with: ssh -L 8080:127.0.0.1:8080 $(hostname))"
    say "to reach it from the LAN, set \"bind\" in the configuration file; the token protects it."
fi
exit $status
