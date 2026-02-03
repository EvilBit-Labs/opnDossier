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
- `packages: write` - Push Docker images to ghcr.io
- `id-token: write` - SLSA provenance and Cosign keyless signing

## Pre-release Checklist

Before creating a release, verify:

- [ ] All CI checks pass on `main` branch
- [ ] All issues/PRs for the milestone are closed
- [ ] `CHANGELOG.md` is up to date (or will be auto-generated)
- [ ] Version references in code are correct (if any hardcoded)
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

### Step 2: Generate Changelog Preview

```bash
# Preview changelog for unreleased commits
git-cliff --unreleased

# Preview full changelog
git-cliff --output /dev/stdout
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

### Verify Docker Image

```bash
# Pull and test the image
docker pull ghcr.io/evilbit-labs/opndossier:v1.2.0
docker run --rm ghcr.io/evilbit-labs/opndossier:v1.2.0 --version

# Verify image tags
docker pull ghcr.io/evilbit-labs/opndossier:latest
docker pull ghcr.io/evilbit-labs/opndossier:v1
docker pull ghcr.io/evilbit-labs/opndossier:v1.2
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

### Test Installation

```bash
# Test binary download and execution
gh release download v1.2.0 --pattern "*Darwin_arm64*"
tar -xzf opnDossier_Darwin_arm64.tar.gz
./opndossier --version

# Test package installation (Linux)
# Debian/Ubuntu
sudo dpkg -i opndossier_1.2.0_linux_amd64.deb
opndossier --version

# RHEL/Fedora
sudo rpm -i opndossier_1.2.0_linux_amd64.rpm
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

#### Docker push fails

```bash
# Verify GitHub Container Registry login
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_ACTOR --password-stdin

# Check repository permissions
gh api repos/EvilBit-Labs/opnDossier --jq '.permissions'
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
goreleaser release --clean --skip=docker,sign
```

## macOS Code Signing (Optional)

macOS binaries can be signed and notarized using [Quill](https://github.com/anchore/quill), an open-source alternative to `gon` that works cross-platform.

### Setup

1. Obtain an Apple Developer certificate and API key from [App Store Connect](https://appstoreconnect.apple.com/access/api)
2. Export the certificate as a P12 file
3. Set the environment variables listed in [Environment Variables](#environment-variables-optional)

### How It Works

The goreleaser configuration includes a post-build hook for macOS:

- **Snapshot builds**: Ad-hoc signing only (no notarization)
- **Release builds**: Full signing and notarization with Apple

If `QUILL_SIGN_P12` is not set, macOS signing is skipped entirely.

## Release Artifacts

Each release includes:

| Artifact                                      | Description                                 |
| --------------------------------------------- | ------------------------------------------- |
| `opnDossier_<OS>_<arch>.tar.gz`               | Binary archives (Linux, macOS, FreeBSD)     |
| `opnDossier_<OS>_<arch>.zip`                  | Binary archive (Windows)                    |
| `opndossier_<version>_linux_amd64.deb`        | Debian/Ubuntu package                       |
| `opndossier_<version>_linux_amd64.rpm`        | RHEL/Fedora package                         |
| `opndossier_<version>_linux_amd64.apk`        | Alpine package                              |
| `opndossier_<version>_linux_amd64.pkg.tar.xz` | Arch Linux package                          |
| `opnDossier_checksums.txt`                    | SHA256 checksums for all artifacts          |
| `opnDossier_checksums.txt.sigstore.json`      | Cosign v3 signature bundle                  |
| `*.bom.json`                                  | Software Bill of Materials (CycloneDX SBOM) |

Docker images are pushed to:

- `ghcr.io/evilbit-labs/opndossier:<tag>` (e.g., `v1.2.0`)
- `ghcr.io/evilbit-labs/opndossier:v<major>` (e.g., `v1`)
- `ghcr.io/evilbit-labs/opndossier:v<major>.<minor>` (e.g., `v1.2`)
- `ghcr.io/evilbit-labs/opndossier:latest`
