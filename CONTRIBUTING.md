# Contributing to FlowSight

The rules that apply to every change (documentation, naming, engineering,
versioning) are in [`CLAUDE.md`](CLAUDE.md); the release procedure is
[`docs/RELEASING.md`](docs/RELEASING.md). This file covers the few
repository-level conventions that live nowhere else.

## Before you commit

```sh
go build ./... && go vet ./... && go test ./...
golangci-lint run ./...        # configuration in .golangci.yml
```

The same checks run in CI (`.github/workflows/ci.yml`) on every push and
pull request. Every change ships with its documentation under `docs/` and a
`docs/CHANGELOG.md` entry (see `CLAUDE.md`).

## Tags and releases

Tags are how the updater, the package managers and the release page find a
build, so their shape matters.

- **Release tags are semver with a `v` prefix: `vX.Y.Z`**, for example
  `v0.9.8`. The GitHub release for that tag carries the assets listed in
  `docs/RELEASING.md` (`manifest.json`, binaries, packages, `install.sh`,
  `SHA256SUMS`).
- **Revisions of a release** (everything shipped between approved version
  bumps, see `docs/RELEASING.md`) are tagged `vX.Y.ZrYYYYMMDDHHMM`, for
  example `v0.9.8r202609211730`. The `v` prefix is required: `install.sh`
  and `release.sh` build download URLs as `releases/download/v<version>/…`,
  so a tag without it is not found by the installer or the updater.
- **Any tag that is not a release must carry a slash-separated prefix**
  saying what it is, so that it can never be mistaken for a release and so
  that `git tag --list 'v*'` returns releases only:
  - `plugin/<name>-vX.Y.Z` for a component released on its own cadence
    (for example `plugin/os-flowsight-v1.2.0`);
  - `test/<description>` for builds pushed to a test bed;
  - `wip/<description>` for anything else that must be pinned but not
    published.
- Tags are annotated (`git tag -a`), never moved and never deleted once
  pushed: installed daemons and package repositories refer to them by name.
  A mistaken release is superseded by a new revision, not by re-tagging.

Existing tags that predate this convention are left as they are.
