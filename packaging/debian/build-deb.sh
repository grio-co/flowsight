#!/bin/sh
# Build a .deb for Debian/Ubuntu with dpkg-deb alone.
#   build-deb.sh <version> <arch: amd64|arm64> <flowsightd binary> <out dir> [docs dir]
set -eu
VERSION="${1:?}"; ARCH="${2:?}"; BIN="${3:?}"; OUT="${4:?}"; DOCS="${5:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/local/sbin" "$STAGE/lib/systemd/system" "$STAGE/etc/flowsight" "$STAGE/usr/share/flowsight" "$OUT"
install -m 755 "$BIN" "$STAGE/usr/local/sbin/flowsightd"
install -m 644 "$HERE/../systemd/flowsight.service" "$STAGE/lib/systemd/system/flowsight.service"
if [ -n "$DOCS" ] && [ -d "$DOCS" ]; then
    D="$STAGE/usr/share/doc/flowsight"; install -d "$D/chapters"
    cp -R "$DOCS"/md "$DOCS"/html "$D/" 2>/dev/null || true
    cp "$DOCS"/flowsight-manual-*.pdf "$D/" 2>/dev/null || true
    cp "$DOCS"/chapters/*.pdf "$D/chapters/" 2>/dev/null || true
    find "$D" -type f -exec chmod 644 {} +
fi
cat > "$STAGE/DEBIAN/control" <<CTRL
Package: flowsight
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: FlowSight <flowsight@grio.co>
Depends: unbound
Recommends: squid-openssl | squid, ntopng, suricata
Homepage: https://github.com/grioghar/flowsight
Description: L7 visibility, policy and enforcement for gateways
 Application and web visibility per device, per-group policy compiled onto
 Unbound, squid and the packet filter, TLS transparency, reports and alerting.
CTRL
cat > "$STAGE/DEBIAN/postinst" <<'PI'
#!/bin/sh
# The package put the binary and the unit in place; flowsightd install does
# the rest (configuration, enabling, starting, checking) and leaves the
# package's files alone. A problem it reports does not fail the package.
/usr/local/sbin/flowsightd install -yes -packaged </dev/null ||
    echo "FlowSight is installed, but the installer reported a problem above."
exit 0
PI
cat > "$STAGE/DEBIAN/prerm" <<'PR'
#!/bin/sh
# Take FlowSight's resolver files away before stopping it, as the OPNsense
# package does: left in place, Unbound goes on applying its DNS blocks after
# FlowSight is gone. On an upgrade the new version writes them again.
removed=
for f in /etc/unbound/unbound.conf.d/flowsight-*; do
    [ -e "$f" ] && rm -f "$f" && removed=1
done
[ -n "$removed" ] && unbound-control reload >/dev/null 2>&1 || true
systemctl disable --now flowsight >/dev/null 2>&1 || true
PR
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT/flowsight_${VERSION}_${ARCH}.deb"
ls -la "$OUT"/flowsight_"${VERSION}"_"${ARCH}".deb
