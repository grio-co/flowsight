#!/bin/sh
# Run the tc lab (internal/modules/tc/lab_test.go): real queues and real
# traffic with measured rates, in a throwaway privileged container, so
# nothing outside it is touched.
#
#   test/tc-lab.sh [image]
#
# The image needs tc, ip and curl (the web lab's image, or the kindest/node
# image). On a kernel without ifb (Docker Desktop's) only the download path
# is proven; the upload path needs a full kernel (see the lab's comment).
# The container is removed afterwards.
set -eu
IMAGE="${1:-flowsight-weblab:local}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(docker version --format '{{.Server.Arch}}')"
WORK="$(mktemp -d)"; NAME="fs-tc-lab-$$"
trap 'docker rm -f -v "$NAME" >/dev/null 2>&1; rm -rf "$WORK"' EXIT
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go test -c -o "$WORK/tc.test" ./internal/modules/tc/ &&
	CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/labserver" ./internal/modules/nftables/testdata/labserver)
docker run -d --name "$NAME" --privileged --entrypoint sleep -v "$WORK:/lab:ro" "$IMAGE" infinity >/dev/null
docker exec -e FLOWSIGHT_TC_LAB=1 -e FLOWSIGHT_LAB_SERVER=/lab/labserver "$NAME" /lab/tc.test -test.run TestLab -test.v
