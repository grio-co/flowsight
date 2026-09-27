#!/bin/sh
# Run the nftables lab (internal/modules/nftables/lab_test.go): real
# nftables and real traffic, in a throwaway privileged container, so nothing
# outside it is touched.
#
#   test/nftables-lab.sh [image]
#
# The image needs nft, conntrack, ip and curl (the kindest/node image has
# them, as does debian with nftables, conntrack, iproute2 and curl
# installed). The container is removed afterwards.
set -eu
IMAGE="${1:-$(docker inspect flowsight-test-control-plane -f '{{.Image}}' 2>/dev/null || true)}"
[ -n "$IMAGE" ] || { echo "give an image with nft, conntrack, ip and curl" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(docker version --format '{{.Server.Arch}}')"
WORK="$(mktemp -d)"; NAME="fs-nft-lab-$$"
trap 'docker rm -f -v "$NAME" >/dev/null 2>&1; rm -rf "$WORK"' EXIT
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go test -c -o "$WORK/nftables.test" ./internal/modules/nftables/ &&
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/labserver" ./internal/modules/nftables/testdata/labserver)
docker run -d --name "$NAME" --privileged --entrypoint sleep -v "$WORK:/lab:ro" "$IMAGE" infinity >/dev/null
docker exec -e FLOWSIGHT_NFT_LAB=1 -e FLOWSIGHT_LAB_SERVER=/lab/labserver "$NAME" /lab/nftables.test -test.run TestLab -test.v
