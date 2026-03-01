# Releasing opnDossier

This document outlines the complete process for preparing and releasing a new version of opnDossier. The project uses GoReleaser for automated releases, git-cliff for changelog generation, and follows semantic versioning principles with comprehensive security compliance.

## Overview

The opnDossier release process is designed to be:

- **Local-First**: All commands run locally using the justfile and GoReleaser
- **Consistent**: Following conventional commits and semantic versioning
- **Comprehensive**: Includes binaries, Docker images, checksums, and SBOMs
- **Secure**: Includes SLSA Level 3 provenance, Cosign signatures, and comprehensive security scanning
- **Security Compliant**: Full compliance with industry security standards

## Prerequisites

Before starting a release, ensure you have:

1. **Required Tools** (managed via `mise install`):

   - `git-cliff` for changelog generation
   - `goreleaser` for release automation
   - `cosign` for artifact signing
   - `gosec` for security scanning (run `just install-security-tools` if needed)
   - `cyclonedx-gomod` for SBOM generation (run `just install-security-tools` if needed)
   - `go-licenses` for third-party license notices generation
   - Proper GitHub permissions for the repository

2. **Environment Setup**:

   - `GITHUB_TOKEN` with appropriate permissions
   - For macOS notarization (optional):
     - `MACOS_SIGN_P12`
     - `MACOS_SIGN_PASSWORD`
     - `MACOS_NOTARY_ISSUER_ID`
     - `MACOS_NOTARY_KEY_ID`
     - `MACOS_NOTARY_KEY`
   - For enhanced security scanning (optional):
     - `SNYK_TOKEN` for Snyk vulnerability scanning
     - `FOSSA_API_KEY` for FOSSA license analysis

3. **Clean Working Directory**:

   ```bash
   git status  # Should show no uncommitted changes
   git pull origin main  # Ensure you're up to date
   ```

4. **Docker Login** (for pushing container images):

   ```bash
   echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
   ```

## Release Process

### Step 1: Pre-Release Validation

1. **Run Full Test Suite**:

   ```bash
   just ci-full
   ```

   This runs:

   - Pre-commit checks (`just check`)
   - Code formatting checks (`just format-check`)
   - Linting (`just lint`)
   - All tests including integration tests (`just test`, `just test-integration`)
   - Security scanning and SBOM generation (`just security-all`)
   - GoReleaser configuration validation (`just release-check`)
   - Documentation build (`just docs-test`)

2. **Test Release Build** (Optional but Recommended):

   ```bash
   just release-snapshot
   ```

   This creates a snapshot build without publishing to verify everything works.

3. **Security Validation**:

   ```bash
   # Run all security checks (gosec + SBOM)
   just security-all

   # Or run individual checks
   just scan                  # Run gosec security scanner
   just sbom                  # Generate SBOM with cyclonedx-gomod
   ```

### Step 2: Update Changelog

The project uses `git-cliff` with conventional commits to automatically generate changelogs.

1. **Generate Changelog for Unreleased Changes**:

   ```bash
   just changelog-unreleased
   ```

2. **Review the Generated Changelog**:

   - Open `CHANGELOG.md` and review the unreleased section
   - Ensure all important changes are captured
   - Verify that conventional commit formatting is working correctly

3. **Generate Changelog for Specific Version** (if needed):

   ```bash
   just changelog-version v1.2.3
   ```

### Step 3: Version Tagging

opnDossier follows semantic versioning (SemVer) with the format `vMAJOR.MINOR.PATCH`:

- **MAJOR**: Incompatible API changes or breaking changes
- **MINOR**: New functionality in a backwards compatible manner
- **PATCH**: Backwards compatible bug fixes

1. **Create Version Tag**:

   ```bash
   # Replace X.Y.Z with your version number
   git tag vX.Y.Z
   ```

   Note: Don't push the tag yet - this will be done after the release is created.

   Examples:

   - `v1.0.0` - First stable release
   - `v1.1.0` - New features added
   - `v1.0.1` - Bug fixes only
   - `v2.0.0-rc1` - Release candidate
   - `v2.0.0-beta1` - Beta release

### Step 4: Local Release

All releases are performed locally using the justfile commands:

1. **Login to GitHub Container Registry** (for Docker images):

   ```bash
   echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
   ```

2. **Run the Release**:

   ```bash
   just release
   ```

   This runs `goreleaser release --clean` which:

   - Generates third-party license notices (`THIRD_PARTY_NOTICES`) using `just notices`
   - Dynamically generates shell completions (bash, zsh, fish, PowerShell) using Cobra
   - Dynamically generates man pages for all commands using Cobra
   - Builds binaries for all platforms (FreeBSD, Linux, macOS, Windows)
   - Creates archives with proper naming and includes LICENSE, README.md, CHANGELOG.md, THIRD_PARTY_NOTICES
   - Generates native packages (.deb, .rpm, .apk, .pkg.tar.xz) with nfpm including:
     - Man pages in `/usr/share/man/man1/`
     - Shell completions for bash, zsh, and fish
     - Complete documentation including THIRD_PARTY_NOTICES
   - Generates checksums file (`opnDossier_checksums.txt`)
   - Creates Software Bill of Materials (SBOM) for archives and packages
   - Signs all artifacts with Cosign (keyless signing)
   - Builds and pushes Docker images to GitHub Container Registry
   - Creates the GitHub release with all artifacts attached
   - Uses git-cliff generated changelog for release notes

3. **Push the Git Tag** (after successful release):

   ```bash
   git push origin vX.Y.Z
   ```

### Alternative: Snapshot Release

For testing the release process without publishing:

```bash
just release-snapshot
```

This creates all artifacts locally but doesn't publish to GitHub or push Docker images.

## Security Features

### Automated Security Scanning

The release process includes comprehensive security scanning:

1. **Vulnerability Scanning**: Grype scans all dependencies for known vulnerabilities
2. **SBOM Generation**: Syft generates Software Bill of Materials in SPDX format
3. **License Analysis**: FOSSA verifies license compliance
4. **Additional Security**: Snyk provides enhanced vulnerability scanning

### SLSA Level 3 Provenance

Every release includes SLSA Level 3 provenance attestation:

- **Build Integrity**: Cryptographic proof of build process integrity
- **Source Verification**: Links artifacts to exact source code versions
- **Build Environment**: Documents the build environment and tools used
- **Automated Generation**: Generated automatically via GitHub Actions

### Cosign Signatures

All release artifacts are signed using Cosign:

- **Keyless Signing**: Uses OIDC-based keyless signing
- **Artifact Verification**: Users can verify artifact authenticity
- **Bundle Format**: Signatures include in-toto attestation bundles
- **Automated Process**: Integrated into the release workflow

### Verification Commands

Users can verify releases using:

```bash
# Verify checksums
sha256sum -c opnDossier_checksums.txt

# Verify Cosign signatures (requires cosign)
cosign verify-blob \
  --bundle cosign.bundle \
  opnDossier_checksums.txt

# Verify individual artifacts with Cosign
cosign verify-blob \
  --bundle cosign.bundle \
  opnDossier_Linux_x86_64.tar.gz
```

**Note**: SLSA provenance is generated via GitHub Actions for automated releases. For manual releases, SLSA provenance can be generated separately using the SLSA framework tools.

## GoReleaser Configuration

The `.goreleaser.yaml` file configures the following release artifacts:

### Binaries

- **Platforms**: FreeBSD, Linux, macOS, Windows
- **Architectures**: amd64, arm64 (FreeBSD arm64 excluded)
- **Binary Name**: `opndossier`
- **Build Flags**: CGO disabled, stripped binaries with version info

### Archives

- **Format**: tar.gz (zip for Windows)
- **Naming**: `opnDossier_OS_ARCH` format
- **Includes**: LICENSE, README.md, CHANGELOG.md, THIRD_PARTY_NOTICES

### Docker Images

Two Docker image variants are built:

1. **Standard Image**:

   - `ghcr.io/evilbit-labs/opndossier:latest`
   - `ghcr.io/evilbit-labs/opndossier:vX.Y.Z`
   - `ghcr.io/evilbit-labs/opndossier:vX.Y`
   - `ghcr.io/evilbit-labs/opndossier:vX`

2. **POCL Variant**:

   - Same tags with `-pocl` suffix
   - Uses different build branch

### Additional Artifacts

- **Checksums**: `opnDossier_checksums.txt`
- **SBOM**: Software Bill of Materials for archives and packages
- **License Notices**: `THIRD_PARTY_NOTICES` with complete license attribution for all dependencies
- **Source Code**: Automatically included
- **Universal Binaries**: For macOS (replaces individual arch binaries)

## Dynamic Documentation Generation

opnDossier uses Cobra's built-in capabilities to dynamically generate shell completions and man pages during the release process. This ensures documentation is always current with the actual command structure.

### Shell Completions

The CLI supports generating completions for multiple shells:

```bash
# Generate bash completion
opndossier completion bash > ~/.bash_completion

# Generate zsh completion
opndossier completion zsh > "${fpath[1]}/_opndossier"

# Generate fish completion
opndossier completion fish > ~/.config/fish/completions/opndossier.fish

# Generate PowerShell completion
opndossier completion powershell > opndossier.ps1
```

### Man Pages

Generate comprehensive man pages for all commands:

```bash
# Generate man pages in current directory
opndossier man ./

# Generate man pages in system location
sudo opndossier man /usr/local/share/man/man1/
```

### Release Integration

During the release process, GoReleaser automatically:

1. Generates third-party license notices using `go-licenses` via the `just notices` command
2. Builds a temporary binary with correct version information
3. Generates shell completions for bash, zsh, fish, and PowerShell
4. Generates man pages for all commands and subcommands
5. Includes these files in native packages (.deb, .rpm, .apk, .pkg.tar.xz)
6. Cleans up temporary files

This ensures that:

- Package installations include working completions and man pages
- Documentation is always synchronized with the actual CLI interface
- No manual maintenance of static documentation files is required
- License attribution is transparent and complete for end users

## Version Information

Version information is injected into the binary at build time:

- **Main Version**: Set via ldflags in GoReleaser (`main.version`)
- **Build Date**: Available in CLI via `opndossier version`
- **Git Commit**: Available in CLI via `opndossier version`

The version is displayed using:

```bash
opndossier version
```

## Changelog Generation

The project uses `git-cliff` with a custom `cliff.toml` configuration:

### Commit Categories

Commits are automatically categorized based on conventional commit prefixes:

- **Features**: `feat:` commits
- **Bug Fixes**: `fix:` commits
- **Security**: `fix(security):` commits or security-related changes
- **Documentation**: `doc:` commits
- **Performance**: `perf:` commits
- **Refactor**: `refactor:` commits
- **Styling**: `style:` commits
- **Testing**: `test:` commits
- **Miscellaneous**: `chore:` and `ci:` commits
- **Revert**: `revert:` commits

### Commit Message Format

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:

- `feat(auth): add OAuth2 support`
- `fix(parser): handle malformed XML gracefully`
- `docs: update installation instructions`

## Troubleshooting

### Common Issues

1. **GoReleaser Configuration Errors**:

   ```bash
   just check-goreleaser
   ```

2. **Missing git-cliff**:

   ```bash
   mise install          # Installs all tools via mise.toml
   ```

3. **Missing Security Tools**:

   ```bash
   just install-security-tools   # Install gosec, cyclonedx-gomod
   ```

4. **Build Failures**:

   - Check Go version compatibility (requires Go 1.26+)
   - Ensure all tests pass: `just test`
   - Verify dependencies: `go mod tidy`

5. **Docker Login Issues**:

   - Verify GITHUB_TOKEN permissions
   - Check container registry access
   - Ensure you're logged in: `docker login ghcr.io`
   - Test Docker access: `docker pull ghcr.io/evilbit-labs/opndossier:latest`

6. **Security Scan Failures**:

   - Check for high-severity vulnerabilities in dependencies
   - Review SBOM for unexpected dependencies
   - Verify license compliance with FOSSA

### Release Validation

After a release, verify:

1. **GitHub Release Page**:

   - Release notes are generated correctly
   - All binary artifacts are attached
   - Checksums file is present
   - SBOM files are included
   - THIRD_PARTY_NOTICES is included in archives and packages
   - SLSA provenance attestation is attached

2. **Docker Images**:

   ```bash
   docker pull ghcr.io/evilbit-labs/opndossier:latest
   docker run --rm ghcr.io/evilbit-labs/opndossier:latest version
   ```

3. **Binary Downloads**:

   - Test download and execution of binaries for your platform
   - Verify version information is correct

4. **Security Verification**:

   ```bash
   # Verify checksums
   sha256sum -c opnDossier_checksums.txt

   # Verify SLSA provenance
   slsa-verifier verify-artifact \
     --provenance-path opnDossier-v1.0.0.intoto.jsonl \
     --source-uri github.com/EvilBit-Labs/opnDossier \
     opnDossier_checksums.txt
   ```

## Release Schedule

opnDossier follows these release practices:

- **Patch Releases**: As needed for critical bug fixes
- **Minor Releases**: When new features are ready and tested
- **Major Releases**: For breaking changes or significant milestones
- **Pre-releases**: Beta and RC versions for testing before major releases

## Security Considerations

- All releases are signed and checksummed
- Docker images include security labels and provenance information
- macOS binaries can be notarized when certificates are configured
- Dependencies are automatically updated via Dependabot
- CodeQL analysis runs on all releases
- SLSA Level 3 provenance provides build integrity verification
- Cosign signatures ensure artifact authenticity
- Comprehensive vulnerability scanning with Grype and Snyk
- License compliance verified with FOSSA
- Third-party license notices provide transparency for all dependencies

## Post-Release Tasks

After a successful release:

1. **Update Documentation**: Ensure docs reflect new features
2. **Close Milestones**: Close the GitHub milestone for the release
3. **Announce Release**: Update relevant channels about the new version
4. **Monitor Issues**: Watch for any issues reported with the new release
5. **Security Monitoring**: Monitor for any security issues in dependencies

## Rollback Procedure

If a release has critical issues:

1. **Create Hotfix**: Fix the issue in a new patch release
2. **Update GitHub Release**: Mark problematic release as pre-release if needed
3. **Docker Images**: Latest tag will point to the new fixed version
4. **Communication**: Notify users about the issue and fix
5. **Security Assessment**: Re-run security scans to ensure no new vulnerabilities

---

For questions about the release process, please refer to the project's [https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md) or open an issue.
