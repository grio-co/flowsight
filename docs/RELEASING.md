# Releasing

A release is a git tag `vX.Y.Z` plus a GitHub release whose assets the
installed daemons read: `manifest.json` (signed asset list), the raw
`flowsightd-<os>-<arch>` binaries the updater swaps in, the OPNsense packages
`os-flowsight-<ver>-<amd64|aarch64>.pkg` (also uploaded under the stable
names `os-flowsight-<arch>.pkg`), the Debian packages `flowsight_<ver>_<arch>.deb`,
the RPMs `flowsight-<ver>-1.<x86_64|aarch64>.rpm`, the license server
binaries, the manual (`flowsight-manual-<ver>.pdf`, one PDF per chapter under
`chapters/`, and `flowsight-docs-<ver>.tar.gz` with Markdown and HTML),
`install.sh` and `SHA256SUMS`. Every package also carries the manual inside.

Every change ships with its documentation (see `CLAUDE.md` at the repository
root); a release is the moment that promise reaches customers, so check
`docs/` before tagging.

## Version numbers

Versions are `major.minor.patch`. **The version number only increments when
the product owner approves it.** Until then every fix or update ships as a
revision of the current version: `0.9.8r<YYYYMMDDHHMM>` (UTC time of the
build), for example `0.9.8r202609211730`, tagged `v0.9.8r202609211730`. The
updater orders a revision after its base and revisions by their timestamp;
package managers (pkg, dpkg, rpm) order them the same way. Release notes for
a revision start with what it fixes.

## Keys

Release binaries carry two ed25519 public keys injected at build time:
`packaging/release/signing.pub` (release assets, checked by the updater) and
`packaging/release/license.pub` (license documents, checked by the license
module; the matching private key lives on the license server); the private key never enters the repo (default path
`~/.config/flowsight-release/signing.key`, or `$FLOWSIGHT_SIGNING_KEY`). A
binary built without the key refuses to self-update. Rotating the key means
shipping one release signed by the old key that carries the new public key.

## Steps

```sh
# 1. binaries with the key baked in, into dist/<ver>
packaging/release/release.sh build 0.9.3

# 2. OPNsense packages on a FreeBSD/OPNsense host with pkg(8)
sh packaging/freebsd/build-pkg.sh 0.9.3 amd64   dist/0.9.3/flowsightd-freebsd-amd64 plugin/os-flowsight/src dist/0.9.3
sh packaging/freebsd/build-pkg.sh 0.9.3 aarch64 dist/0.9.3/flowsightd-freebsd-arm64 plugin/os-flowsight/src dist/0.9.3

# 3. Debian packages on a host with dpkg-deb
sh packaging/debian/build-deb.sh 0.9.3 amd64 dist/0.9.3/flowsightd-linux-amd64 dist/0.9.3
sh packaging/debian/build-deb.sh 0.9.3 arm64 dist/0.9.3/flowsightd-linux-arm64 dist/0.9.3

# 3b. RPMs on a host with rpmbuild (docs dir optional, as for the others; for the
#     aarch64 build on an x86_64 host first: printf 'buildarch_compat: x86_64: aarch64\narch_compat: x86_64: aarch64\n' >> ~/.rpmrc)
sh packaging/rpm/build-rpm.sh 0.9.3 x86_64  dist/0.9.3/flowsightd-linux-amd64 dist/0.9.3 dist/0.9.3/docs
sh packaging/rpm/build-rpm.sh 0.9.3 aarch64 dist/0.9.3/flowsightd-linux-arm64 dist/0.9.3 dist/0.9.3/docs

# 3c. the manual: Markdown -> HTML + PDF (full and per chapter), then into the release assets
sh packaging/docs/build-docs.sh 0.9.3 dist/0.9.3/docs      # needs pandoc + weasyprint (see the script header)
packaging/release/release.sh docs 0.9.3
# pass dist/0.9.3/docs as the last argument of build-pkg.sh and build-deb.sh so the packages carry it

# 3d. the container image, every architecture, pushed to the registry (FROM scratch: nothing is pulled)
sh packaging/container/build-image.sh 0.9.3 dist/0.9.3 --push <registry>/flowsight

# 4. sign and write manifest.json + SHA256SUMS
NOTES="$(cat notes.md)" packaging/release/release.sh manifest 0.9.3

# 5. publish
git tag -a v0.9.3 -m "FlowSight 0.9.3" && git push origin v0.9.3
gh release create v0.9.3 dist/0.9.3/* --title "FlowSight 0.9.3" --notes-file notes.md
```

Before publishing, prove the updater on a test box: serve `manifest.json`
pointing at a higher-versioned test build from any HTTP server, set the
updater's manifest URL to it, `POST /api/updater/check`, `/apply`, confirm the
new version answers, then `/rollback`. The updater only ever applies a
version greater than the running one, and only when sha256 and signature
match.
