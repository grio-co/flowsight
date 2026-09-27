#!/bin/sh
# Build an RPM for RHEL, Rocky, Alma and Fedora with rpmbuild alone (no
# spec in a build root, no source tarball dance).
#   build-rpm.sh <version> <arch: x86_64|aarch64> <flowsightd binary> <out dir> [docs dir]
# The docs dir (output of packaging/docs/build-docs.sh) is installed under
# /usr/share/doc/flowsight when given.
# Building the aarch64 package on an x86_64 host needs rpmbuild told that the
# target is acceptable (the binary is already cross-compiled):
#   printf 'buildarch_compat: x86_64: aarch64\narch_compat: x86_64: aarch64\n' >> ~/.rpmrc
set -eu
VERSION="${1:?}"; ARCH="${2:?}"; BIN="${3:?}"; OUT="${4:?}"; DOCS="${5:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOP="$(mktemp -d)"; trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP/BUILD" "$TOP/RPMS" "$TOP/SOURCES" "$TOP/SPECS" "$TOP/SRPMS" "$TOP/root" "$OUT"
R="$TOP/root"
install -D -m 755 "$BIN" "$R/usr/local/sbin/flowsightd"
install -D -m 644 "$HERE/../systemd/flowsight.service" "$R/usr/lib/systemd/system/flowsight.service"
install -d -m 750 "$R/etc/flowsight" "$R/var/lib/flowsight" "$R/var/log/flowsight"
if [ -n "$DOCS" ] && [ -d "$DOCS" ]; then
    install -d "$R/usr/share/doc/flowsight"
    cp -R "$DOCS"/md "$DOCS"/html "$R/usr/share/doc/flowsight/" 2>/dev/null || true
    cp "$DOCS"/flowsight-manual-*.pdf "$R/usr/share/doc/flowsight/" 2>/dev/null || true
    mkdir -p "$R/usr/share/doc/flowsight/chapters"; cp "$DOCS"/chapters/*.pdf "$R/usr/share/doc/flowsight/chapters/" 2>/dev/null || true
fi
cat > "$TOP/SPECS/flowsight.spec" <<SPEC
Name:           flowsight
Version:        $VERSION
Release:        1
Summary:        L7 visibility, policy and enforcement for gateways
License:        Apache-2.0
URL:            https://github.com/grioghar/flowsight
BuildArch:      $ARCH
Requires:       unbound
Recommends:     squid, ntopng, suricata
%global __strip /bin/true
%global _build_id_links none
%global debug_package %{nil}

%description
FlowSight: application and web visibility per device, per-group policy
compiled onto Unbound, squid and the packet filter, TLS transparency,
reports and alerting. One static binary, embedded store, no cloud.

%install
cp -a $R/. %{buildroot}/

%post
# The package put the binary and the unit in place; flowsightd install does
# the rest (configuration, enabling, starting, checking) and leaves the
# package's files alone. A problem it reports does not fail the package.
/usr/local/sbin/flowsightd install -yes -packaged </dev/null ||
    echo "FlowSight is installed, but the installer reported a problem above."

%preun
# On removal (not upgrade): take away what FlowSight put in front of
# traffic, then stop it.
if [ "\$1" = 0 ]; then
    /usr/local/sbin/flowsightd uninstall -withdraw -yes </dev/null >/dev/null 2>&1 || true
    systemctl disable --now flowsight >/dev/null 2>&1 || true
fi

%files
/usr/local/sbin/flowsightd
/usr/lib/systemd/system/flowsight.service
%dir %attr(750,root,root) /etc/flowsight
%dir %attr(750,root,root) /var/lib/flowsight
%dir %attr(750,root,root) /var/log/flowsight
$( [ -n "$DOCS" ] && [ -d "$DOCS" ] && echo "%doc /usr/share/doc/flowsight" )
SPEC
rpmbuild --define "_topdir $TOP" --target "$ARCH" -bb "$TOP/SPECS/flowsight.spec" >/dev/null
cp "$TOP"/RPMS/"$ARCH"/flowsight-"$VERSION"-1."$ARCH".rpm "$OUT/"
ls -la "$OUT/flowsight-$VERSION-1.$ARCH.rpm"
