#!/bin/sh
#
# Build and sign a FlowSight release.
#
#   release.sh build <version> [out dir]
#       Cross-compile flowsightd for every supported target with the release
#       public key baked in, into <out dir> (default dist/<version>).
#   release.sh docs <version> [out dir]
#       Copy a rendered manual (packaging/docs/build-docs.sh output in <out dir>/docs)
#       into release assets: the full PDF, the chapter PDFs and a docs tarball.
#   release.sh manifest <version> [out dir]
#       Sign every flowsightd-<os>-<arch> in <out dir> and write manifest.json.
#       Packages (os-flowsight-*.pkg, pfSense-pkg-flowsight-*.pkg, flowsight_*.deb) already in <out dir>
#       are listed with their sha256 but the updater only consumes binaries.
#
# The private key lives outside the repo: $FLOWSIGHT_SIGNING_KEY or
# ~/.config/flowsight-release/signing.key (base64 ed25519, from
# `go run ./cmd/flowsight-sign gen`). The matching public key is committed as
# packaging/release/signing.pub and compiled into release binaries; a binary
# built without it refuses to self-update.
#
# The FreeBSD package needs pkg(8) (build it on a FreeBSD/OPNsense host with
# packaging/freebsd/build-pkg.sh) and the .deb needs dpkg-deb
# (packaging/debian/build-deb.sh); copy their output into <out dir> before
# running "manifest". Then publish <out dir>/* as the GitHub release assets
# of tag v<version>; the updater reads releases/latest/download/manifest.json.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CMD="${1:?build|manifest}"; VERSION="${2:?version}"; OUT="${3:-$ROOT/dist/$VERSION}"
PUB="$(tr -d '\n' < "$HERE/signing.pub")"
LICPUB="$(tr -d '\n' < "$HERE/license.pub")"
KEY="${FLOWSIGHT_SIGNING_KEY:-$HOME/.config/flowsight-release/signing.key}"
TARGETS="freebsd/amd64 freebsd/arm64 linux/amd64 linux/arm64"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
size() { stat -f %z "$1" 2>/dev/null || stat -c %s "$1"; }

case "$CMD" in
build)
    mkdir -p "$OUT"
    for t in $TARGETS; do
        os="${t%/*}"; arch="${t#*/}"
        echo "building $os/$arch"
        (cd "$ROOT" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
            -ldflags "-s -w -X main.Version=$VERSION -X github.com/grioghar/flowsight/internal/modules/updater.PublicKeyBase64=$PUB -X github.com/grioghar/flowsight/internal/modules/license.PublicKeyBase64=$LICPUB" \
            -o "$OUT/flowsightd-$os-$arch" ./cmd/flowsightd)
    done
    # The license server is Linux-only and carries no keys of its own.
    for arch in amd64 arm64; do
        echo "building flowsight-licensed linux/$arch"
        (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "$OUT/flowsight-licensed-linux-$arch" ./cmd/flowsight-licensed)
    done
    cp "$ROOT/install.sh" "$OUT/install.sh"
    ls -la "$OUT"
    ;;
manifest)
    [ -r "$KEY" ] || { echo "signing key not found at $KEY" >&2; exit 1; }
    NOTES="${NOTES:-FlowSight $VERSION}"
    assets=""
    for t in $TARGETS; do
        os="${t%/*}"; arch="${t#*/}"; f="$OUT/flowsightd-$os-$arch"
        [ -f "$f" ] || { echo "missing $f (run build first)" >&2; exit 1; }
        h="$(sha "$f")"
        sig="$(cd "$ROOT" && go run ./cmd/flowsight-sign sign -key "$KEY" -sha256 "$h")"
        assets="$assets{\"os\":\"$os\",\"arch\":\"$arch\",\"url\":\"https://github.com/grioghar/flowsight/releases/download/v$VERSION/flowsightd-$os-$arch\",\"sha256\":\"$h\",\"size\":$(size "$f"),\"sig\":\"$sig\"},"
    done
    pkgs=""
    for f in "$OUT"/os-flowsight-*.pkg "$OUT"/pfSense-pkg-flowsight-*.pkg "$OUT"/flowsight_*.deb "$OUT"/flowsight-*.rpm "$OUT"/flowsight-manual-*.pdf "$OUT"/flowsight-docs-*.tar.gz; do
        [ -f "$f" ] || continue
        pkgs="$pkgs{\"name\":\"$(basename "$f")\",\"sha256\":\"$(sha "$f")\",\"size\":$(size "$f")},"
    done
    printf '{\n  "version": "%s",\n  "channel": "stable",\n  "published": "%s",\n  "notes": %s,\n  "assets": [%s],\n  "packages": [%s]\n}\n' \
        "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(printf '%s' "$NOTES" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
        "${assets%,}" "${pkgs%,}" > "$OUT/manifest.json"
    python3 -m json.tool "$OUT/manifest.json" >/dev/null
    (cd "$OUT" && for f in *; do [ -f "$f" ] || continue; [ "$f" = SHA256SUMS ] || printf '%s  %s\n' "$(sha "$f")" "$f"; done > SHA256SUMS)
    echo "wrote $OUT/manifest.json and SHA256SUMS"
    ;;
docs)
    D="$OUT/docs"; [ -d "$D" ] || { echo "no rendered docs at $D (run packaging/docs/build-docs.sh $VERSION $D)" >&2; exit 1; }
    cp "$D"/flowsight-manual-"$VERSION".pdf "$OUT/"
    mkdir -p "$OUT/chapters"; cp "$D"/chapters/*.pdf "$OUT/chapters/"
    (cd "$D" && tar -czf "$OUT/flowsight-docs-$VERSION.tar.gz" md html chapters flowsight-manual-"$VERSION".pdf)
    ls -la "$OUT"/flowsight-manual-"$VERSION".pdf "$OUT/flowsight-docs-$VERSION.tar.gz"; ls "$OUT/chapters" | wc -l
    ;;
*) echo "usage: release.sh build|docs|manifest <version> [out dir]" >&2; exit 1 ;;
esac
