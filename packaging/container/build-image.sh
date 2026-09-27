#!/bin/sh
# Build the FlowSight OCI image.
#
#   build-image.sh <version> <binaries dir> [--push <repository> | --load [--arch amd64|arm64]]
#
# The binaries dir holds flowsightd-linux-amd64 and/or flowsightd-linux-arm64
# (release.sh build puts them in dist/<version>). --push builds every
# architecture present and pushes one multi-architecture image;
# --load (the default) builds this machine's architecture into the local
# Docker (--arch picks another; the image has no build steps, so no
# emulation is needed). The image is FROM scratch: nothing is pulled.
set -eu
VERSION="${1:?version}"; BINS="${2:?binaries dir}"; shift 2
MODE=load; REPO=flowsight; ARCH=
while [ $# -gt 0 ]; do
    case "$1" in
        --push) MODE=push; REPO="${2:?repository}"; shift 2 ;;
        --load) MODE=load; shift ;;
        --arch) ARCH="${2:?arch}"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
CTX="$(mktemp -d)"; trap 'rm -rf "$CTX"' EXIT

cp "$HERE/Dockerfile" "$CTX/"
PLATFORMS=""
for a in amd64 arm64; do
    if [ -f "$BINS/flowsightd-linux-$a" ]; then
        cp "$BINS/flowsightd-linux-$a" "$CTX/"
        PLATFORMS="${PLATFORMS:+$PLATFORMS,}linux/$a"
    fi
done
[ -n "$PLATFORMS" ] || { echo "no flowsightd-linux-* in $BINS" >&2; exit 1; }

# The CA certificates of the build machine, for FlowSight's HTTPS feeds.
mkdir -p "$CTX/rootfs-root/etc/ssl/certs"
for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [ -s "$ca" ]; then cp "$ca" "$CTX/rootfs-root/etc/ssl/certs/ca-certificates.crt"; break; fi
done
[ -s "$CTX/rootfs-root/etc/ssl/certs/ca-certificates.crt" ] || { echo "no CA bundle found on this machine" >&2; exit 1; }
printf 'root:x:0:0:root:/root:/sbin/nologin\nflowsight:x:65532:65532:FlowSight:/var/lib/flowsight:/sbin/nologin\n' > "$CTX/rootfs-root/etc/passwd"
printf 'root:x:0:\nflowsight:x:65532:\n' > "$CTX/rootfs-root/etc/group"
for d in var/lib/flowsight var/log/flowsight run/flowsight usr/share/flowsight tmp; do
    mkdir -p "$CTX/rootfs-user/$d"
done
# The configuration lives on the data volume, so one volume holds all state.
mkdir -p "$CTX/rootfs-user/etc"
ln -s ../var/lib/flowsight/etc "$CTX/rootfs-user/etc/flowsight"
chmod 1777 "$CTX/rootfs-user/tmp"

TAG="$REPO:$VERSION"
if [ "$MODE" = push ]; then
    docker buildx build --platform "$PLATFORMS" --build-arg VERSION="$VERSION" -t "$TAG" --push "$CTX"
else
    arch="${ARCH:-$(docker version --format '{{.Server.Arch}}')}"
    [ -f "$CTX/flowsightd-linux-$arch" ] || { echo "no flowsightd-linux-$arch for this Docker" >&2; exit 1; }
    docker buildx build --platform "linux/$arch" --build-arg VERSION="$VERSION" -t "$TAG" --load "$CTX"
fi
echo "built $TAG ($PLATFORMS)"
