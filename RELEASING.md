# Releasing opnDossier

This document outlines the complete process for preparing and releasing a new version of opnDossier. The project uses GoReleaser for automated releases, git-cliff for changelog generation, and follows semantic versioning principles.

## Overview

The opnDossier release process is designed to be:

- **Local-First**: All commands run locally using the justfile and GoReleaser
- **Consistent**: Following conventional commits and semantic versioning
- **Comprehensive**: Includes binaries, Docker images, checksums, and SBOMs
- **Secure**: Includes macOS notarization and code signing when configured

## Prerequisites

Before starting a release, ensure you have:

1. **Required Tools**:

   - `git-cliff` installed (run `just install-git-cliff` if needed)
   - `goreleaser` installed
   - Proper GitHub permissions for the repository

2. **Environment Setup**:

   - `GITHUB_TOKEN` with appropriate permissions
   - For macOS notarization (optional):
     - `MACOS_SIGN_P12`
     - `MACOS_SIGN_PASSWORD`
     - `MACOS_NOTARY_ISSUER_ID`
     - `MACOS_NOTARY_KEY_ID`
     - `MACOS_NOTARY_KEY`

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
   just full-checks
   ```

   This runs:

   - Code formatting checks (`just format-check`)
   - Linting (`just lint`)
   - All tests (`just test`)
   - GoReleaser configuration validation (`just check-goreleaser`)

2. **Test Release Build** (Optional but Recommended):

   ```bash
   just build-snapshot
   ```

   This creates a snapshot build without publishing to verify everything works.

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

   - Dynamically generates shell completions (bash, zsh, fish, PowerShell) using Cobra
   - Dynamically generates man pages for all commands using Cobra
   - Builds binaries for all platforms (FreeBSD, Linux, macOS, Windows)
   - Creates archives with proper naming and includes LICENSE, README.md, CHANGELOG.md
   - Generates native packages (.deb, .rpm, .apk, .pkg.tar.xz) with nfpm including:
     - Man pages in `/usr/share/man/man1/`
     - Shell completions for bash, zsh, and fish
     - Complete documentation
   - Generates checksums file (`opnDossier_checksums.txt`)
   - Creates Software Bill of Materials (SBOM) for archives and packages
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

## GoReleaser Configuration

The `.goreleaser.yaml` file configures the following release artifacts:

### Binaries

- **Platforms**: FreeBSD, Linux, macOS, Windows
- **Architectures**: amd64, arm64 (FreeBSD arm64 excluded)
- **Binary Name**: `opnDossier`
- **Build Flags**: CGO disabled, stripped binaries with version info

### Archives

- **Format**: tar.gz (zip for Windows)
- **Naming**: `opnDossier_OS_ARCH` format
- **Includes**: LICENSE, README.md, CHANGELOG.md

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
- **SBOM**: Software Bill of Materials for archives
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

1. Builds a temporary binary with correct version information
2. Generates shell completions for bash, zsh, fish, and PowerShell
3. Generates man pages for all commands and subcommands
4. Includes these files in native packages (.deb, .rpm, .apk, .pkg.tar.xz)
5. Cleans up temporary files

This ensures that:

- Package installations include working completions and man pages
- Documentation is always synchronized with the actual CLI interface
- No manual maintenance of static documentation files is required

## Version Information

Version information is injected into the binary at build time:

- **Main Version**: Set via ldflags in GoReleaser (`main.version`)
- **Build Date**: Available in CLI via `opnDossier version`
- **Git Commit**: Available in CLI via `opnDossier version`

The version is displayed using:

```bash
opnDossier version
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
   just install-git-cliff
   ```

3. **Build Failures**:

   - Check Go version compatibility (requires Go 1.24+)
   - Ensure all tests pass: `just test`
   - Verify dependencies: `go mod tidy`

4. **Docker Login Issues**:

   - Verify GITHUB_TOKEN permissions
   - Check container registry access
   - Ensure you're logged in: `docker login ghcr.io`
   - Test Docker access: `docker pull ghcr.io/evilbit-labs/opndossier:latest`

### Release Validation

After a release, verify:

1. **GitHub Release Page**:

   - Release notes are generated correctly
   - All binary artifacts are attached
   - Checksums file is present

2. **Docker Images**:

   ```bash
   docker pull ghcr.io/evilbit-labs/opndossier:latest
   docker run --rm ghcr.io/evilbit-labs/opndossier:latest version
   ```

3. **Binary Downloads**:

   - Test download and execution of binaries for your platform
   - Verify version information is correct

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

## Post-Release Tasks

After a successful release:

1. **Update Documentation**: Ensure docs reflect new features
2. **Close Milestones**: Close the GitHub milestone for the release
3. **Announce Release**: Update relevant channels about the new version
4. **Monitor Issues**: Watch for any issues reported with the new release

## Rollback Procedure

If a release has critical issues:

1. **Create Hotfix**: Fix the issue in a new patch release
2. **Update GitHub Release**: Mark problematic release as pre-release if needed
3. **Docker Images**: Latest tag will point to the new fixed version
4. **Communication**: Notify users about the issue and fix

---

For questions about the release process, please refer to the project's [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue.
