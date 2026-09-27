#!/bin/sh
# The web lab: the real daemon, real squid and real nftables, with real
# traffic, in a throwaway privileged container, so nothing outside it is
# touched. It proves web interception on a Linux gateway end to end:
#
#	client netns 10.10.0.2 --- 10.10.0.1  the container  10.20.0.2 --- server netns
#	                           (gateway: flowsightd, squid, nftables)
#
#   test/web-lab.sh [image]
#
# The image needs nft, conntrack, ip, curl and squid-openssl. Make one from
# the nftables lab's image (a Debian with those tools) once:
#
#   docker run --name fs-weblab-build --entrypoint sh <image> -c \
#     'apt-get update && apt-get install -y --no-install-recommends squid-openssl'
#   docker commit fs-weblab-build flowsight-weblab:local && docker rm -v fs-weblab-build
#
# KEEP=1 leaves the container running for a look afterwards.
set -eu
IMAGE="${1:-flowsight-weblab:local}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(docker version --format '{{.Server.Arch}}')"
WORK="$(mktemp -d)"; NAME="fs-web-lab-$$"
cleanup() {
	[ "${KEEP:-}" = 1 ] && echo "left running: docker exec -it $NAME bash; docker rm -f -v $NAME" || docker rm -f -v "$NAME" >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/flowsightd" ./cmd/flowsightd &&
	CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/labserver" ./internal/modules/nftables/testdata/labserver)
cp "$ROOT/test/web-lab-inside.sh" "$WORK/"
docker run -d --name "$NAME" --privileged --entrypoint sleep -v "$WORK:/lab:ro" "$IMAGE" infinity >/dev/null
docker exec "$NAME" sh /lab/web-lab-inside.sh
