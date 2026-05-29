# Tero Vector distribution

This directory holds the release machinery for the Tero fork of Vector.
The fork tracks upstream `vectordotdev/vector` and adds the `policy`
transform (see `src/transforms/policy/`); everything else is the
unmodified upstream tree.

## What's produced

Each release publishes:

- A multi-arch Docker image to **`ghcr.io/usetero/vector`** at
  `:<VERSION>` and `:latest` covering `linux/amd64` and `linux/arm64`.
- Two binary tarballs attached to the GitHub Release:
  - `vector-<VERSION>-x86_64-unknown-linux-gnu.tar.gz`
  - `vector-<VERSION>-aarch64-unknown-linux-gnu.tar.gz`
- A `.sha256` checksum next to each tarball.

The binaries are built with `--features
"target-<TRIPLE>,transforms-policy"`, i.e. upstream Vector's standard
feature set for the target triple **plus** our `policy` transform.

## How a release is cut

1. Land PRs to `master` using Conventional Commits. `feat:`, `fix:`,
   `chore:`, etc.
2. `tero-release-please.yaml` watches `master`. After each merge it opens
   (or updates) a single "release PR" that bumps
   `.release-please-manifest.json`, `Cargo.toml` version, and
   `CHANGELOG.md`.
3. When the release PR is merged, release-please creates the
   `v<VERSION>` tag and the corresponding GitHub Release.
4. The tag push triggers `tero-release.yaml`, which builds the binaries
   and image and attaches the tarballs to the release.

## Versioning

Versions follow `<UPSTREAM>-tero.<N>` (e.g. `0.56.0-tero.1`). The base
`<UPSTREAM>` should match the upstream Vector version this fork is
rebased on. `<N>` is bumped automatically by release-please each release.

When rebasing onto a newer upstream Vector:

1. Rebase `master` onto the new upstream tag.
2. Manually edit `.release-please-manifest.json` to reset the base, e.g.
   `0.56.0-tero.5` → `0.57.0-tero.0`.
3. Merge a `chore(release): rebase onto upstream vX.Y.Z` commit; the
   next release-please PR bumps to `0.57.0-tero.1`.

## One-time setup: disable upstream release workflows

Upstream's `release.yml` and `publish.yml` also fire on `v*` tag pushes
and try to publish to channels we don't own (Docker Hub `timberio/vector`,
S3 `packages.timber.io`, Homebrew, the upstream GHCR). They will fail
loudly without those credentials.

In the fork repository: **Settings → Actions → Workflows → disable**:

- `Release`  (`.github/workflows/release.yml`)
- `Publish`  (`.github/workflows/publish.yml`)

This is settings-only and avoids editing any upstream file. The
disablement persists across rebases.

If you ever need the upstream pipelines back (e.g. to mirror Vector's
own release artifacts), re-enable them from the same panel.

## Manual smoke test

Trigger `tero-release.yaml` from the Actions tab with `workflow_dispatch`:

- `version`: `0.0.0-tero.dryrun` (or any string)
- `dry_run`: `true`

This builds the binaries and Docker image without pushing to GHCR or
attaching release assets.

## Files in this directory

- `Dockerfile` — Debian-slim runtime that receives a prebuilt `vector`
  binary via the build context and bakes it into a multi-arch image.
- `README.md` — this file.

Build orchestration lives in `.github/workflows/tero-release.yaml`.
