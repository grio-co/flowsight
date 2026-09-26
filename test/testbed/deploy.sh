#!/bin/sh
# Deploy a development build to the test bed, and only the test bed.
#
#   test/testbed/deploy.sh            build this checkout, install it on the test bed, restart
#   test/testbed/deploy.sh status     what the test bed runs now
#   test/testbed/deploy.sh rollback   put back the binary the last deploy replaced
#
# FLOWSIGHT_REPO=<path> builds another checkout (a hotfix worktree) with this script.
#
# The test bed is VM 9100 (opnsense-test) on PVE2, with its own LAN on vmbr9
# (10.99.0.0/24) and the test client container 9101 (fs-client) behind it.
# The live gateway is VM 100 on the same host; this script refuses any VM
# whose name and description do not say it is the test bed.
#
# No credentials on the test bed are needed or changed: the build is copied
# to PVE2, served on the test bed's LAN for the length of the download, and
# fetched and installed from inside the VM through the QEMU guest agent.
#
# The build carries the license public key, so tier-gated features can be
# exercised, but not the release signing key: a development build refuses to
# self-update, so the test bed can never be moved off it by a release.
set -eu

PVE="${FLOWSIGHT_TESTBED_HOST:-pve2}"
VMID=9100
SERVE_ADDR=10.99.0.2   # PVE2's own address on the test bed LAN
PORT=18088
REPO="${FLOWSIGHT_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"  # the checkout to build

say()  { printf '  %s\n' "$*"; }
fail() { printf '  ERROR: %s\n' "$*" >&2; exit 1; }

# guest runs a shell command inside the test bed and prints its output.
guest() {
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$PVE" "timeout 180 qm guest exec $VMID --timeout 170 -- /bin/sh -c '$1'" |
        python3 -c 'import json,sys; r=json.load(sys.stdin); sys.stdout.write(r.get("out-data","")); sys.stderr.write(r.get("err-data","")); sys.exit(r.get("exitcode",1))'
}

# guard refuses to touch anything that is not the test bed.
guard() {
    conf="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$PVE" "qm config $VMID")" || fail "cannot read VM $VMID on $PVE"
    echo "$conf" | grep -q '^name: opnsense-test$' || fail "VM $VMID on $PVE is not named opnsense-test; refusing"
    echo "$conf" | grep -q 'Flowsight test bed' || fail "VM $VMID on $PVE is not described as the test bed; refusing"
    ssh -o BatchMode=yes "$PVE" "qm status $VMID" | grep -q running || fail "the test bed is not running (qm start $VMID on $PVE)"
}

status() {
    guest '/usr/local/sbin/flowsightd -version; service flowsight status; ls -l /usr/local/sbin/flowsightd /usr/local/sbin/flowsightd.previous 2>/dev/null; curl -s -m 5 -H "X-Requested-With: Flowsight" http://127.0.0.1:8080/api/firewall/status | head -c 300; echo'
}

case "${1:-deploy}" in
status)
    guard
    status
    exit 0
    ;;
rollback)
    guard
    guest 'test -x /usr/local/sbin/flowsightd.previous || { echo "no previous binary"; exit 1; }; install -m 755 /usr/local/sbin/flowsightd.previous /usr/local/sbin/flowsightd && service flowsight restart'
    status
    exit 0
    ;;
deploy) ;;
*) fail "usage: $0 [deploy|status|rollback]" ;;
esac

guard

cd "$REPO"
SHA="$(git rev-parse --short HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
DIRTY=""
git diff --quiet HEAD -- . ':!test/testbed' || DIRTY=".dirty"
VERSION="0.9.8-dev.$BRANCH.$SHA$DIRTY"
LICPUB="$(cat packaging/release/license.pub)"
OUT="$(mktemp -d)"
cleanup() {
    rm -rf "$OUT"
    ssh -o BatchMode=yes "$PVE" "pkill -f 'http.server $PORT' || true; rm -rf /tmp/flowsight-dev" 2>/dev/null || true
}
trap cleanup EXIT

say "building flowsightd $VERSION for freebsd/amd64"
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X main.Version=$VERSION -X github.com/grioghar/flowsight/internal/modules/license.PublicKeyBase64=$LICPUB" \
    -o "$OUT/flowsightd" ./cmd/flowsightd

say "copying to $PVE"
ssh -o BatchMode=yes "$PVE" "mkdir -p /tmp/flowsight-dev"
scp -q -o BatchMode=yes "$OUT/flowsightd" "$PVE:/tmp/flowsight-dev/flowsightd"
SUM="$(shasum -a 256 "$OUT/flowsightd" | cut -d' ' -f1)"

say "serving it on $SERVE_ADDR:$PORT for the download"
ssh -o BatchMode=yes "$PVE" "cd /tmp/flowsight-dev && (timeout 120 python3 -m http.server $PORT --bind $SERVE_ADDR >/dev/null 2>&1 &) ; sleep 1"

say "installing on the test bed (the running binary is kept as flowsightd.previous)"
guest "fetch -qo /tmp/flowsightd.new http://$SERVE_ADDR:$PORT/flowsightd && \
    test \"\$(sha256 -q /tmp/flowsightd.new)\" = $SUM && \
    chmod 755 /tmp/flowsightd.new && /tmp/flowsightd.new -version && \
    cp -p /usr/local/sbin/flowsightd /usr/local/sbin/flowsightd.previous && \
    install -m 755 /tmp/flowsightd.new /usr/local/sbin/flowsightd && rm -f /tmp/flowsightd.new && \
    service flowsight restart"

sleep 5
status
