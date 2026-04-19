# Releasing opnDossier

This document describes the release process for opnDossier.

## Table of Contents

- [Version Numbering](#version-numbering)
- [Prerequisites](#prerequisites)
- [Pre-release Checklist](#pre-release-checklist)
- [Creating a Release](#creating-a-release)
- [Post-release Verification](#post-release-verification)
- [Release Candidates](#release-candidates)
- [Hotfix Process](#hotfix-process)
- [Troubleshooting](#troubleshooting)

## Version Numbering

opnDossier follows [Semantic Versioning 2.0.0](https://semver.org/):

| Version Component | When to Increment                                        | Example                                 |
| ----------------- | -------------------------------------------------------- | --------------------------------------- |
| **MAJOR** (X.0.0) | Breaking changes to CLI interface, config format, or API | Removing a flag, changing output format |
| **MINOR** (0.X.0) | New features, backward-compatible additions              | New audit plugin, new output format     |
| **PATCH** (0.0.X) | Bug fixes, documentation, performance improvements       | Fix parsing bug, typo fixes             |

### Pre-release Tags

- **Release Candidates**: `v1.2.0-rc1`, `v1.2.0-rc2` - Feature-complete, needs testing
- **Beta**: `v1.2.0-beta.1` - Feature incomplete, early testing
- **Alpha**: `v1.2.0-alpha.1` - Experimental, unstable

## Prerequisites

### Required Tools

Install these tools before creating a release:

```bash
# Install via mise (recommended - see .mise.toml)
mise install

# Or install manually:
# goreleaser - https://goreleaser.com/install/
brew install goreleaser/tap/goreleaser

# git-cliff - https://git-cliff.org/docs/installation
brew install git-cliff

# cosign v3 - https://docs.sigstore.dev/cosign/installation/
# Note: v3+ uses keyless signing by default with .sigstore.json bundles
brew install cosign

# cyclonedx-gomod (for SBOM) - https://github.com/CycloneDX/cyclonedx-gomod
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

# go-licenses (for third-party notices) - https://github.com/google/go-licenses
go install github.com/google/go-licenses@latest

# quill (for macOS code signing, optional) - https://github.com/anchore/quill
# Only needed if you want to sign and notarize macOS binaries
curl -sSfL https://raw.githubusercontent.com/anchore/quill/main/install.sh | sh -s -- -b /usr/local/bin
```

### Environment Variables (Optional)

For signed releases, configure these environment variables:

```bash
# macOS Code Signing with Quill (optional)
# See: https://github.com/anchore/quill
export QUILL_SIGN_P12="path/to/certificate.p12"      # or base64-encoded P12
export QUILL_SIGN_PASSWORD="certificate-password"
export QUILL_NOTARY_KEY="path/to/AuthKey_XXXXX.p8"   # Apple API key
export QUILL_NOTARY_KEY_ID="XXXXXXXXXX"              # Key ID from App Store Connect
export QUILL_NOTARY_ISSUER="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Issuer UUID

# Linux Package Signing (optional)
export RPM_SIGNING_KEY_FILE="path/to/rpm-key"
export DEB_SIGNING_KEY_FILE="path/to/deb-key"
export APK_SIGNING_KEY_FILE="path/to/apk-key"
```

> [!NOTE]
> Cosign v3 uses keyless signing via Sigstore OIDC, so no signing keys are needed for artifact signatures when running in GitHub Actions.

### GitHub Permissions

The release workflow requires:

- `contents: write` - Create releases and upload assets
- `id-token: write` - SLSA provenance and Cosign keyless signing

### GitHub Secrets

For GPG signing of release artifacts, add these repository secrets:

| Secret            | Description                                                                         |
| ----------------- | ----------------------------------------------------------------------------------- |
| `GPG_PRIVATE_KEY` | Base64-encoded GPG private key (`gpg --armor --export-secret-keys EMAIL \| base64`) |
| `GPG_PASSPHRASE`  | Passphrase for the GPG key                                                          |

> [!NOTE]
> GPG signing is optional. If these secrets are not set, releases will still be created with Cosign signatures for checksums.

## Pre-release Checklist

Before creating a release, verify:

- [ ] All CI checks pass on `main` branch
- [ ] All issues/PRs for the milestone are closed
- [ ] `CHANGELOG.md` is up to date (or will be auto-generated)
- [ ] Version references in code are correct (if any hardcoded)
- [ ] `action.yml` default `version:` input is bumped to the new tag
- [ ] README GitHub Action examples (`uses:` lines) are swept to the new tag
- [ ] README "Pinning" section SHA-pin example is updated to the new release commit SHA
- [ ] Documentation reflects new features/changes
- [ ] Breaking changes are documented

### Verify CI Status

```bash
# Check CI status for main branch
gh run list --branch main --limit 5

# View specific workflow run
gh run view <run-id>
```

### Close Milestone

```bash
# List open milestones
gh milestone list --state open

# Close milestone (goreleaser will also auto-close on release)
gh milestone edit <milestone-number> --state closed
```

## Creating a Release

### Step 1: Validate Configuration

```bash
# Check goreleaser configuration
goreleaser check

# Preview what would be built (no publish)
goreleaser release --snapshot --clean

# Check generated artifacts
ls -la dist/
```

> [!NOTE]
> The release workflow automatically generates `THIRD_PARTY_NOTICES` via the `just notices` command as a GoReleaser before-hook. This file provides human-readable license attribution for all dependencies and is included in all distribution archives and packages. The formatting is controlled by the template at `packaging/notices.tpl`.

### RELEASE_NOTES.md convention

`RELEASE_NOTES.md` in the repo root holds only the **most recent release's** notes. Overwrite it on each release — the GitHub Release body is populated from this file via `gh release create --notes-file RELEASE_NOTES.md` (see [Step 4](#step-4-create-github-release) below). Historical per-release entries live in `CHANGELOG.md`, which follows the [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) workflow described in [Step 2](#step-2-generate-changelog-preview) below; never accumulate past releases inside `RELEASE_NOTES.md`.

### Step 2: Generate Changelog Preview

`CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/). During development, commits flow into `## [Unreleased]` at the top of `CHANGELOG.md`. On release, git-cliff promotes the Unreleased section to `## [vX.Y.Z] - YYYY-MM-DD` and seeds a new empty Unreleased section for the next cycle.

Commit types are mapped to Keep-a-Changelog buckets by `cliff.toml`:

| Commit prefix                                                                | Changelog section |
| ---------------------------------------------------------------------------- | ----------------- |
| `feat:`                                                                      | **Added**         |
| `fix:` (except `fix(security)`)                                              | **Fixed**         |
| `fix(security):`, `security:`                                                | **Security**      |
| `deprecate:`, `*(deprecate):`                                                | **Deprecated**    |
| `remove:`, `*(remove):`                                                      | **Removed**       |
| `perf:`, `refactor:`, `docs:`, `chore:`, `ci:`, `test:`, `style:`, `revert:` | **Changed**       |

Commits whose body carries `BREAKING CHANGE:` land in **Changed** and are prefixed with `[**breaking**]` in the bullet — hand-curate migration notes beneath the release header when this happens.

```bash
# Preview the Unreleased section as it would appear for the next tag
git-cliff --unreleased

# Preview the full changelog (all tagged versions + Unreleased)
git-cliff --output /dev/stdout

# Generate the final changelog for a specific version and write to disk
just changelog-version vX.Y.Z
```

### Step 3: Create and Push Tag

```bash
# Ensure you're on main with latest changes
git checkout main
git pull origin main

# Create annotated tag
git tag -a v1.2.0 -m "Release v1.2.0"

# Push tag to trigger release workflow
git push origin v1.2.0
```

### Step 4: Create GitHub Release

Option A: **Via GitHub UI** (Recommended)

1. Go to [Releases](https://github.com/EvilBit-Labs/opnDossier/releases)
2. Click "Draft a new release"
3. Select the tag you just pushed
4. Click "Generate release notes" for auto-generated notes
5. Review and edit the release notes
6. Click "Publish release"

Option B: **Via CLI**

```bash
# Create release from tag (triggers workflow)
gh release create v1.2.0 \
  --title "v1.2.0" \
  --generate-notes

# Or with custom notes
gh release create v1.2.0 \
  --title "v1.2.0" \
  --notes-file RELEASE_NOTES.md
```

### Step 5: Monitor Release Workflow

```bash
# Watch the release workflow
gh run watch

# Or list recent workflow runs
gh run list --workflow=release.yml --limit 5
```

## Post-release Verification

After the release workflow completes:

### Verify Artifacts

```bash
# List release assets
gh release view v1.2.0

# Download and verify checksums
gh release download v1.2.0 --pattern "*checksums*"
sha256sum -c opnDossier_checksums.txt
```

### Verify SLSA Provenance

```bash
# Install slsa-verifier
brew install slsa-framework/tap/slsa-verifier

# Download provenance
gh release download v1.2.0 --pattern "*.intoto.jsonl"

# Verify provenance
slsa-verifier verify-artifact \
  --provenance-path opnDossier-v1.2.0.intoto.jsonl \
  --source-uri github.com/EvilBit-Labs/opnDossier \
  --source-tag v1.2.0 \
  opnDossier_checksums.txt
```

### Verify Cosign Signatures (v3)

```bash
# Download checksum file and its signature bundle
gh release download v1.2.0 --pattern "*checksums*"
gh release download v1.2.0 --pattern "*.sigstore.json"

# Verify signature with Cosign v3 (keyless, using Sigstore bundle format)
cosign verify-blob \
  --certificate-identity "https://github.com/EvilBit-Labs/opnDossier/.github/workflows/release.yml@refs/tags/v1.2.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle opnDossier_checksums.txt.sigstore.json \
  opnDossier_checksums.txt
```

> [!NOTE]
> Cosign v3 uses `.sigstore.json` bundle format instead of separate `.sig` and `.pem` files.

### Verify GPG Signatures

All release archives and packages are signed with the EvilBit Labs software signing key.

```bash
# Import the public key (one-time setup)
curl -sSL https://raw.githubusercontent.com/EvilBit-Labs/opnDossier/main/keys/software-signing.asc | gpg --import

# Or from a local clone
gpg --import keys/software-signing.asc

# Download an artifact and its signature
gh release download v1.2.0 --pattern "opnDossier_Linux_x86_64.tar.gz*"

# Verify the signature
gpg --verify opnDossier_Linux_x86_64.tar.gz.sig opnDossier_Linux_x86_64.tar.gz
```

**Key details:**

- **Email**: `software@evilbitlabs.io`
- **Fingerprint**: `138B FA78 8F37 7661 EA48 2C1D EFC6 F4CA BED2 2E8E`
- **Key type**: RSA 4096
- **Expires**: 2030-02-03

### Test Installation

```bash
# Test binary download and execution
gh release download v1.2.0 --pattern "*Darwin_arm64*"
tar -xzf opnDossier_Darwin_arm64.tar.gz
./opndossier --version

# Test package installation (Linux)
# Debian/Ubuntu
sudo dpkg -i opndossier_1.2.0_amd64.deb
opndossier --version

# RHEL/Fedora
sudo rpm -i opndossier-1.2.0-1.x86_64.rpm
opndossier --version
```

## Release Candidates

Use release candidates for significant releases that need broader testing.

### Creating an RC

```bash
# Tag release candidate
git tag -a v1.2.0-rc1 -m "Release candidate 1 for v1.2.0"
git push origin v1.2.0-rc1

# Create pre-release on GitHub
gh release create v1.2.0-rc1 \
  --title "v1.2.0-rc1" \
  --prerelease \
  --generate-notes
```

### Promoting RC to Release

If the RC is stable:

```bash
# Tag the same commit as final release
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0

# Create the final release
gh release create v1.2.0 --title "v1.2.0" --generate-notes
```

## Hotfix Process

For urgent fixes to a released version:

### Step 1: Create Hotfix Branch

```bash
# Branch from the release tag
git checkout -b hotfix/v1.2.1 v1.2.0

# Make the fix
# ... edit files ...

# Commit with conventional commit format
git commit -m "fix(parser): handle edge case in XML parsing"
```

### Step 2: Create PR and Merge

```bash
# Push hotfix branch
git push origin hotfix/v1.2.1

# Create PR targeting main
gh pr create --title "fix: critical parsing bug" --base main

# After review and merge, tag the release
git checkout main
git pull
git tag -a v1.2.1 -m "Hotfix release v1.2.1"
git push origin v1.2.1
```

## Troubleshooting

### Common Issues

#### goreleaser check fails

```bash
# Validate YAML syntax
yamllint .goreleaser.yaml

# Check for deprecated options
goreleaser check --deprecated
```

#### Cosign signing fails

```bash
# Verify cosign is configured for keyless signing
cosign version

# Test keyless signing locally
echo "test" | cosign sign-blob --yes - --bundle test.bundle
```

#### SLSA provenance fails

Check the workflow logs:

```bash
gh run view <run-id> --log-failed
```

### Manual Release (Emergency)

If the automated workflow fails, you can release manually:

```bash
# Build locally
goreleaser release --clean

# Or skip certain steps
goreleaser release --clean --skip=sign
```

## macOS Signing (Quill)

macOS binaries are signed and notarized using [Quill](https://github.com/anchore/quill), an open-source alternative to `gon` that works cross-platform. The post-build hook lives in `.goreleaser.yaml` (search for `quill sign-and-notarize`) and is invoked from `.github/workflows/release.yml` — see the `Run GoReleaser` step's `env` block, where the `QUILL_*` vars are wired from repository secrets.

All `QUILL_*` inputs are **optional**. If `QUILL_SIGN_P12` is unset the entire hook is a no-op — the universal binary ships unsigned and nothing downstream fails. Set every variable in the table below (as repository secrets for CI, or exported locally for manual builds) if you want a fully signed and notarized macOS release.

### Required variables (all or none)

Either configure the full set or leave them all unset. Partial configuration will fail at notarization time.

| Variable              | Purpose                                                                                                                         | Source                                                                                                                                          |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `QUILL_SIGN_P12`      | Developer ID Application certificate (P12 file path or base64-encoded contents). Acts as the on/off toggle for the entire hook. | Export from Keychain Access after enrolling in the [Apple Developer Program](https://developer.apple.com/programs/).                            |
| `QUILL_SIGN_PASSWORD` | Passphrase that unlocks the P12.                                                                                                | Set when exporting the P12.                                                                                                                     |
| `QUILL_NOTARY_KEY`    | App Store Connect API key (path to `AuthKey_XXXXX.p8` or base64-encoded contents).                                              | Download once from [App Store Connect → Users and Access → Integrations → App Store Connect API](https://appstoreconnect.apple.com/access/api). |
| `QUILL_NOTARY_KEY_ID` | 10-character Key ID for the API key above.                                                                                      | Shown next to the key in App Store Connect.                                                                                                     |
| `QUILL_NOTARY_ISSUER` | UUID of the issuer that owns the API key.                                                                                       | Shown at the top of the API keys page in App Store Connect.                                                                                     |

### Optional variables

| Variable         | Default                                                | Effect if unset                                                                    |
| ---------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| `QUILL_LOG_FILE` | `/tmp/quill-universal.log` (set in `.goreleaser.yaml`) | Quill logs to stderr only; the release workflow keeps the goreleaser default path. |

### How the hook behaves

- **Snapshot builds** (`workflow_dispatch` or `--snapshot`): ad-hoc signing only, notarization skipped (`--dry-run=true --ad-hoc=true`). Useful for smoke-testing without consuming Apple notarization quota.
- **Release builds** (tag push): full sign + notarize against Apple (`--dry-run=false --ad-hoc=false`).
- The hook runs on the lipo'd universal binary, not per-arch, so the signed artifact is what ends up in the tarball.
- If `QUILL_SIGN_P12` is empty the templated `quill sign-and-notarize` command is not emitted at all — nothing to debug when signing is intentionally off.

### Verify a signed macOS binary

After downloading the release tarball:

```bash
tar -xzf opnDossier_Darwin_arm64.tar.gz
codesign -dv --verbose=4 ./opndossier      # Shows Authority, TeamIdentifier, Timestamp
codesign --verify --strict --verbose=2 ./opndossier
spctl -a -vv -t exec ./opndossier          # Gatekeeper check; should say "accepted" + "notarized"
```

`quill` itself can also round-trip the check:

```bash
quill extract signature ./opndossier       # Inspects the embedded signature
```

See the [Quill README](https://github.com/anchore/quill#readme) for the full command surface and troubleshooting tips.

## Release Artifacts

Each release includes:

| Artifact                                    | Description                                                           |
| ------------------------------------------- | --------------------------------------------------------------------- |
| `opnDossier_<OS>_<arch>.tar.gz`             | Binary archives (Linux, macOS, FreeBSD) with man page and completions |
| `opnDossier_<OS>_<arch>.zip`                | Binary archive (Windows) with THIRD_PARTY_NOTICES                     |
| `opndossier_<version>_amd64.deb`            | Debian/Ubuntu package with THIRD_PARTY_NOTICES in /usr/share/doc      |
| `opndossier-<version>-1.x86_64.rpm`         | RHEL/Fedora package with THIRD_PARTY_NOTICES in /usr/share/doc        |
| `opndossier_<version>_x86_64.apk`           | Alpine package with THIRD_PARTY_NOTICES                               |
| `opndossier-<version>-1-x86_64.pkg.tar.zst` | Arch Linux package with THIRD_PARTY_NOTICES                           |
| `opnDossier_checksums.txt`                  | SHA256 checksums for all artifacts                                    |
| `opnDossier_checksums.txt.sigstore.json`    | Cosign v3 signature bundle                                            |
| `*.sig`                                     | GPG detached signatures for archives/packages                         |
| `*.bom.json`                                | Software Bill of Materials (CycloneDX SBOM)                           |
| `THIRD_PARTY_NOTICES`                       | Human-readable license attribution for all dependencies               |

## Quick Release Checklist

Copy-paste checklist for cutting a release. See sections above for details on each step.

### Pre-flight

- [ ] CI green on `main` — `gh run list --branch main --limit 5`
- [ ] `just ci-check` passes locally (lint, tests, race detector)
- [ ] Milestone closed — `gh milestone list --state open`, then close if exists
- [ ] No uncommitted or unrelated changes on `main`

### Prepare

- [ ] Preview Unreleased section — `git-cliff --unreleased` (confirms commits are bucketed into Added / Changed / Deprecated / Removed / Fixed / Security correctly)
- [ ] Generate changelog — `just changelog-version vX.Y.Z` (promotes `## [Unreleased]` to `## [vX.Y.Z] - YYYY-MM-DD`)
- [ ] Review `CHANGELOG.md` — verify entries are correct, complete, and in the right Keep-a-Changelog buckets
- [ ] Hand-curate **Breaking Changes** / **Migration** subsections beneath the new release header if any commits carry `BREAKING CHANGE:`
- [ ] Write or update `RELEASE_NOTES.md`
- [ ] Bump `action.yml` default `version:` input to the new tag (e.g. `vX.Y.Z`)
- [ ] Sweep README GitHub Action examples (`uses: EvilBit-Labs/opnDossier@vX.Y.Z` lines) to the new tag — grep for the previous tag to catch every callsite
- [ ] Sweep user-guide docs for stale version examples — `grep -rn "vPREV\.Y\.Z" docs/user-guide/` and update all matches to the new tag (covers `getting-started.md` version-output example, `installation.md` cosign TAG example, and any future callsites)
- [ ] Update the SHA-pin example in the README "Pinning" section to the new release commit SHA (`git rev-parse vX.Y.Z` after the tag is pushed, or the commit you intend to tag)
- [ ] Commit `RELEASE_NOTES.md`, `CHANGELOG.md`, `action.yml`, and `README.md` to `main`
- [ ] Push to `main`

### Tag and Release

- [ ] Ensure you are on `main` with latest — `git checkout main && git pull origin main`
- [ ] Create annotated tag — `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Push tag — `git push origin vX.Y.Z`
- [ ] Create GitHub release — `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file RELEASE_NOTES.md`

> **Reminder:** Always tag the commit on `main`, never a feature branch head (see GOTCHAS.md #12.1).

### Post-release Verification

- [ ] Monitor workflow — `gh run watch` or `gh run list --workflow=release.yml`
- [ ] Verify artifacts — `gh release view vX.Y.Z`
- [ ] Verify cosign signature — download checksums + `.sigstore.json`, run `cosign verify-blob`
- [ ] Test binary — download, run `opndossier --version`, confirm version
- [ ] Verify Docker — `docker pull ghcr.io/evilbit-labs/opndossier:vX.Y.Z`
- [ ] Verify Homebrew cask updated (if `HOMEBREW_TAP_TOKEN` is set)
