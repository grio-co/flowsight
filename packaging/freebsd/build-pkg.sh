#!/bin/sh
#
# Build the os-flowsight package for OPNsense/FreeBSD with pkg(8) alone.
#
# No ports tree, no plugins framework: the binary is cross-compiled from any
# machine with Go, the plugin files are copied from the repo, and pkg create
# wraps them with a manifest. The result installs with `pkg add` and shows up
# in System > Firmware > Plugins like any other plugin.
#
#   build-pkg.sh <version> <arch: amd64|aarch64> <flowsightd binary> <plugin src dir> <out dir> [docs dir]
# The docs dir is the output of packaging/docs/build-docs.sh; when given, the
# manual (Markdown, HTML, PDFs) is installed under /usr/local/share/flowsight/docs.
#
set -eu

VERSION="${1:?version}"
ARCH="${2:?arch}"
BIN="${3:?flowsightd binary}"
SRC="${4:?plugin src dir}"
OUT="${5:?out dir}"
DOCS="${6:-}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/usr/local/sbin" "$STAGE/usr/local/share/flowsight" "$STAGE/usr/local/etc/flowsight" "$OUT"

install -m 755 "$BIN" "$STAGE/usr/local/sbin/flowsightd"
(cd "$SRC" && find . -type f | while read -r f; do
    dest="$STAGE/usr/local/${f#./}"
    case "$f" in
        ./etc/rc.d/*) mode=755 ;;
        ./www/*|./opnsense/*|./etc/inc/*) mode=644 ;;
        *) mode=644 ;;
    esac
    install -d "$(dirname "$dest")"
    install -m "$mode" "$f" "$dest"
done)

if [ -n "$DOCS" ] && [ -d "$DOCS" ]; then
    D="$STAGE/usr/local/share/flowsight/docs"; install -d "$D/chapters"
    cp -R "$DOCS"/md "$DOCS"/html "$D/" 2>/dev/null || true
    cp "$DOCS"/flowsight-manual-*.pdf "$D/" 2>/dev/null || true
    cp "$DOCS"/chapters/*.pdf "$D/chapters/" 2>/dev/null || true
    find "$D" -type f -exec chmod 644 {} +
fi

# OUI registry if the repo ships one; the identity module reads it from share.
if [ -f "$(dirname "$0")/../oui.txt" ]; then
    install -m 644 "$(dirname "$0")/../oui.txt" "$STAGE/usr/local/share/flowsight/oui.txt"
fi

cat > "$STAGE/+MANIFEST" <<EOF
name: os-flowsight
version: "$VERSION"
origin: opnsense/os-flowsight
comment: "FlowSight: L7 visibility, policy and enforcement"
desc: <<EOD
FlowSight is an open alternative to Zenarmor for OPNsense: application and
web visibility per device, DNS, web and application policy compiled onto the
firewall's own resolver, proxy and packet filter, TLS transparency with an
optional inspection CA, firewall rule hygiene, reports and alerting. One
static binary, no cloud, no licence gates.
EOD
maintainer: flowsight@grio.co
www: https://github.com/grioghar/flowsight
abi: "FreeBSD:*:$ARCH"
arch: "freebsd:*:$ARCH"
prefix: /usr/local
licenselogic: single
licenses: [APACHE20]
categories: [opnsense, net]
deps: {
  squid: {origin: www/squid, version: "6.0"}
}
annotations: {
  plugin_type: "os-flowsight",
  tier: "community"
}
EOF

cat > "$STAGE/+POST_INSTALL" <<'EOF'
#!/bin/sh
install -d -m 755 /var/db/flowsight /var/log/flowsight /var/run/flowsight /usr/local/etc/flowsight
# Register the service and enable the plugin's firewall hooks on first install.
sysrc -q flowsight_enable=YES >/dev/null
if [ -x /usr/local/sbin/configctl ]; then
    # The CLI php has no include path for the OPNsense libraries; give it one.
    cd /usr/local/www && php -d include_path=".:/usr/local/etc/inc:/usr/local/www:/usr/local/opnsense/mvc" -r '
require_once("config.inc"); global $config;
if (!isset($config["OPNsense"]["flowsight"]["general"]["enabled"])) {
    $config["OPNsense"]["flowsight"]["general"]["enabled"] = "1";
    write_config("FlowSight: plugin installed");
}' 2>/dev/null || true
    rm -f /var/lib/php/tmp/opnsense_menu_cache.xml
    # Detach fully: pkg may be driven by something waiting on our descriptors.
    /usr/sbin/daemon -f /bin/sh -c 'sleep 1; /usr/local/etc/rc.d/configd restart; sleep 3; configctl filter reload; configctl webgui restart' \
        </dev/null >/dev/null 2>&1
fi
# The package put the binary and the service in place; flowsightd install
# starts it and checks it, and leaves the package's files alone.
/usr/local/sbin/flowsightd install -yes -packaged </dev/null ||
    echo "FlowSight is installed, but the installer reported a problem above."
echo ""
echo "FlowSight is installed. Open Services > FlowSight in the GUI."
echo "Nothing is enforced until you turn on policy enforcement there."
EOF

cat > "$STAGE/+PRE_DEINSTALL" <<'EOF'
#!/bin/sh
service flowsight stop >/dev/null 2>&1 || true
sysrc -q -x flowsight_enable >/dev/null 2>&1 || true
# Withdraw everything FlowSight put in front of traffic; leave data and policy.
pfctl -a flowsight/web -F nat >/dev/null 2>&1 || true
pfctl -a flowsight/policy -F rules >/dev/null 2>&1 || true
for f in /var/unbound/etc/flowsight-*.conf /var/unbound/etc/flowsight-*.rpz /usr/local/etc/unbound.opnsense.d/flowsight-*; do
    [ -e "$f" ] && rm -f "$f"
done
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml
EOF

cat > "$STAGE/+POST_DEINSTALL" <<'EOF'
#!/bin/sh
if [ -x /usr/local/sbin/configctl ]; then
    configctl unbound restart >/dev/null 2>&1 &
    configctl filter reload >/dev/null 2>&1 || true
fi
EOF

(cd "$STAGE" && find usr -type f | sed 's#^#/#' | sort > "$STAGE/plist")
mkdir -p "$STAGE/pkgout"
pkg create -r "$STAGE" -m "$STAGE" -p "$STAGE/plist" -o "$STAGE/pkgout" -f txz
# One file name per architecture, so several can sit in one release directory.
mv "$STAGE"/pkgout/os-flowsight-"$VERSION".* "$OUT/os-flowsight-$VERSION-$ARCH.pkg"
ls -la "$OUT/os-flowsight-$VERSION-$ARCH.pkg"
