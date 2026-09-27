#!/bin/sh
#
# Build the pfSense-pkg-flowsight package with pkg(8) alone, on any FreeBSD
# or pfSense host: the binary is cross-compiled from any machine with Go,
# the package files are copied from the repo, and pkg create wraps them with
# a manifest. The result installs with `pkg add` on pfSense CE (and Plus,
# best effort), and registers itself the way Netgate's packages do: its
# scripts hand over to pfSense's /etc/rc.packages, which reads info.xml,
# records the package (and its filter hook) in config.xml, adds the menu and
# the service, and calls flowsight_install().
#
#   build-pkg.sh <version> <arch: amd64|aarch64> <flowsightd binary> <package files dir> <out dir> [docs dir]
#
set -eu

VERSION="${1:?version}"
ARCH="${2:?arch}"
BIN="${3:?flowsightd binary}"
SRC="${4:?package files dir}"
OUT="${5:?out dir}"
DOCS="${6:-}"
NAME=pfSense-pkg-flowsight

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/usr/local/sbin" "$STAGE/usr/local/share/flowsight" "$OUT"

install -m 755 "$BIN" "$STAGE/usr/local/sbin/flowsightd"
# Only the package's own files: never a copy tool's metadata (macOS writes
# ._name sidecars into archives, and pfSense includes every
# /etc/inc/priv/*.inc, so one there is printed on every GUI page).
(cd "$SRC" && find . -type f ! -name '._*' ! -name '.DS_Store' | while read -r f; do
    dest="$STAGE/${f#./}"
    case "$f" in
        ./usr/local/etc/rc.d/*) mode=755 ;;
        *) mode=644 ;;
    esac
    install -d "$(dirname "$dest")"
    install -m "$mode" "$f" "$dest"
done)
sed -i '' "s/%%PKGVERSION%%/$VERSION/" "$STAGE/usr/local/share/$NAME/info.xml" 2>/dev/null ||
    sed -i "s/%%PKGVERSION%%/$VERSION/" "$STAGE/usr/local/share/$NAME/info.xml"

if [ -n "$DOCS" ] && [ -d "$DOCS" ]; then
    D="$STAGE/usr/local/share/flowsight/docs"; install -d "$D/chapters"
    cp -R "$DOCS"/md "$DOCS"/html "$D/" 2>/dev/null || true
    cp "$DOCS"/flowsight-manual-*.pdf "$D/" 2>/dev/null || true
    cp "$DOCS"/chapters/*.pdf "$D/chapters/" 2>/dev/null || true
    find "$D" -type f -exec chmod 644 {} +
fi

if [ -f "$(dirname "$0")/../oui.txt" ]; then
    install -m 644 "$(dirname "$0")/../oui.txt" "$STAGE/usr/local/share/flowsight/oui.txt"
fi

cat > "$STAGE/+MANIFEST" <<EOF
name: $NAME
version: "$VERSION"
origin: security/$NAME
comment: "FlowSight: L7 visibility, policy and enforcement"
desc: <<EOD
FlowSight for pfSense: application and web visibility per device, DNS, web
and application policy compiled onto pfSense's own resolver, proxy and
packet filter, TLS transparency with an optional inspection CA, firewall
rule hygiene, reports and alerting. One static binary, no cloud.
EOD
maintainer: flowsight@grio.co
www: https://github.com/grioghar/flowsight
abi: "FreeBSD:*:$ARCH"
arch: "freebsd:*:$ARCH"
prefix: /
licenselogic: single
licenses: [APACHE20]
categories: [security, net]
deps: {
  squid: {origin: www/squid, version: "6.0"}
}
annotations: {
  tier: "community"
}
EOF

cat > "$STAGE/+POST_INSTALL" <<EOF
#!/bin/sh
install -d -m 755 /var/db/flowsight /var/log/flowsight /var/run/flowsight /usr/local/etc/flowsight
# pfSense records the package, its filter hook, menu and service, and runs
# flowsight_install(): the resolver include, then a filter reload that
# generates FlowSight's anchors.
/usr/local/bin/php -f /etc/rc.packages $NAME POST-INSTALL
# The package put the binary and the service in place; flowsightd install
# starts it and checks it, and leaves the package's files alone.
/usr/local/sbin/flowsightd install -yes -packaged </dev/null ||
    echo "FlowSight is installed, but the installer reported a problem above."
echo ""
echo "FlowSight is installed. Open Services > FlowSight in the GUI."
echo "Nothing is enforced until you turn on policy enforcement there."
EOF

cat > "$STAGE/+PRE_DEINSTALL" <<EOF
#!/bin/sh
# flowsight_deinstall(): stop the daemon, withdraw every rule FlowSight
# loaded, remove its resolver include. Policy and data stay.
/usr/local/bin/php -f /etc/rc.packages $NAME DEINSTALL
EOF

cat > "$STAGE/+POST_DEINSTALL" <<EOF
#!/bin/sh
# pfSense forgets the package, and so its filter hook; regenerate the
# ruleset so the (now empty) anchors are no longer referenced.
/usr/local/bin/php -f /etc/rc.packages $NAME POST-DEINSTALL
/etc/rc.filter_configure_sync >/dev/null 2>&1 || true
EOF

(cd "$STAGE" && find usr etc -type f ! -name '._*' | sed 's#^#/#' | sort > "$STAGE/plist")
mkdir -p "$STAGE/pkgout"
pkg create -r "$STAGE" -m "$STAGE" -p "$STAGE/plist" -o "$STAGE/pkgout" -f txz
mv "$STAGE"/pkgout/$NAME-"$VERSION".* "$OUT/$NAME-$VERSION-$ARCH.pkg"
ls -la "$OUT/$NAME-$VERSION-$ARCH.pkg"
