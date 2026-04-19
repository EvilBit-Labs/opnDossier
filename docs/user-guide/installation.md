# Installation Guide

This guide covers various methods to install opnDossier on your system.

## Prerequisites

- **Linux, macOS, FreeBSD, or Windows** (cross-platform support)
- **Go 1.26+** (only required for `go install` or building from source)

## Installation Methods

### 1. Homebrew (macOS)

```bash
brew install EvilBit-Labs/tap/opndossier
```

This installs the binary along with shell completions for bash, zsh, and fish. Man pages are included and can be accessed with `man opndossier`.

### 2. Linux Packages

Native packages are published with each release. Download the appropriate package from the [releases page](https://github.com/EvilBit-Labs/opnDossier/releases/latest):

**Debian / Ubuntu (.deb):**

```bash
sudo dpkg -i opndossier_*_amd64.deb
```

**Red Hat / CentOS / Fedora (.rpm):**

```bash
sudo rpm -i opndossier-*-1.x86_64.rpm
```

**Alpine (.apk):**

```bash
sudo apk add --allow-untrusted opndossier_*_x86_64.apk
```

**Arch Linux:**

```bash
sudo pacman -U opndossier-*-1-x86_64.pkg.tar.zst
```

Native packages include man pages, shell completions, and documentation.

To verify a downloaded package before installing, see [Verifying Downloads](#verifying-downloads) below.

### 3. Download Pre-built Binaries

Pre-built binaries are available for multiple platforms from the [releases page](https://github.com/EvilBit-Labs/opnDossier/releases/latest):

```bash
# Download the latest release for your platform
curl -LO https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/opnDossier_Linux_x86_64.tar.gz

# Verify the download (see "Verifying Downloads" below)
curl -LO https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/opnDossier_checksums.txt
sha256sum -c opnDossier_checksums.txt --ignore-missing

# Extract and install
tar xzf opnDossier_Linux_x86_64.tar.gz
chmod +x opndossier
sudo mv opndossier /usr/local/bin/
```

Available platforms:

- Linux (amd64, arm64)
- macOS (universal binary -- amd64 + arm64)
- FreeBSD (amd64)
- Windows (amd64, zip archive)

**Windows:**

Download the `.zip` archive from the [releases page](https://github.com/EvilBit-Labs/opnDossier/releases/latest), extract it, and add the directory containing `opndossier.exe` to your `PATH`.

### 4. Docker

```bash
docker pull ghcr.io/evilbit-labs/opndossier:latest

# Run against a local config file
docker run --rm -v "$(pwd):/data" ghcr.io/evilbit-labs/opndossier:latest convert /data/config.xml
```

### 5. Go Install

If you have Go 1.26+ installed:

```bash
go install github.com/EvilBit-Labs/opnDossier@latest
```

This installs the latest release to your `$GOPATH/bin` directory.

### 6. Build from Source

```bash
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier
go build -o opndossier main.go
```

## Updating

### Homebrew

```bash
brew upgrade opndossier
```

### Linux Packages

Download and install the latest package from the [releases page](https://github.com/EvilBit-Labs/opnDossier/releases/latest). The package manager will handle the upgrade.

### Pre-built Binaries / Source

Download the latest binary or pull and rebuild from source.

### Docker

```bash
docker pull ghcr.io/evilbit-labs/opndossier:latest
```

### Go Install

```bash
go install github.com/EvilBit-Labs/opnDossier@latest
```

## Verifying Downloads

Every release publishes a `opnDossier_checksums.txt` file containing SHA-256 hashes for all release artifacts (packages, binaries, and archives). The checksum file is signed with [Cosign](https://docs.sigstore.dev/cosign/overview/) keyless signatures via Sigstore.

### SHA-256 Checksums

```bash
# Download the checksum file
curl -LO https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/opnDossier_checksums.txt

# Verify your downloaded file against the checksums
# Linux:
sha256sum -c opnDossier_checksums.txt --ignore-missing
# macOS:
shasum -a 256 -c opnDossier_checksums.txt
```

### Cosign Signature Verification

If you have [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) installed, you can verify the checksum file itself was produced by the official release pipeline:

```bash
# Download the signature bundle
curl -LO https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/opnDossier_checksums.txt.sigstore.json

# Verify (replace TAG with the release tag, e.g. v1.4.0)
cosign verify-blob \
  --certificate-identity "https://github.com/EvilBit-Labs/opnDossier/.github/workflows/release.yml@refs/tags/TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle opnDossier_checksums.txt.sigstore.json \
  opnDossier_checksums.txt
```

## Verify Your Installation

After installing, verify your installation:

```bash
# Check version
opndossier version

# Test basic functionality
opndossier --help

# Test shell completion
opndossier completion bash  # Should show bash completion script
```

## Configuration (Optional)

opnDossier works out of the box with no configuration file. All settings can be passed as command-line flags or environment variables. If you want to set persistent defaults, you can create a configuration file.

### Configuration File

opnDossier looks for `~/.opnDossier.yaml` if it exists:

```yaml
# ~/.opnDossier.yaml
verbose: false
quiet: false
format: markdown
```

You can also point to a different file with `--config /path/to/config.yaml`.

### Environment Variables

Settings can also be set via environment variables:

```bash
# Add to ~/.bashrc, ~/.zshrc, etc.
export OPNDOSSIER_VERBOSE=false
```

See the [Configuration Guide](configuration.md) for the full list of options and precedence rules.

## Shell Completion

opnDossier includes shell completion support:

### Bash

```bash
# Add to ~/.bashrc
source <(opndossier completion bash)

# Or install globally
opndossier completion bash > /etc/bash_completion.d/opndossier
```

### Zsh

```bash
# Add to ~/.zshrc
source <(opndossier completion zsh)

# Or for oh-my-zsh
opndossier completion zsh > ~/.oh-my-zsh/completions/_opndossier
```

### Fish

```bash
opndossier completion fish | source

# Or save to file
opndossier completion fish > ~/.config/fish/completions/opndossier.fish
```

### PowerShell

```powershell
# Add to PowerShell profile
opndossier completion powershell | Out-String | Invoke-Expression
```

## Troubleshooting

### Common Issues

1. **Command not found**

   First, check whether the binary is on your system:

   ```bash
   which opndossier
   ```

   If nothing is returned, the fix depends on how you installed:

   - **Homebrew:** Run `brew link opndossier` or start a new shell session.

   - **Linux package (deb/rpm/apk):** The package installs to `/usr/bin/` -- verify the package is installed with your package manager (e.g., `dpkg -l | grep opndossier`).

   - **Pre-built binary:** Ensure you moved the binary to a directory in your `PATH` (e.g., `/usr/local/bin/`).

   - **Go install:** Add the Go bin directory to your `PATH`:

     ```bash
     export PATH=$PATH:$(go env GOPATH)/bin
     ```

     Add this line to `~/.bashrc`, `~/.zshrc`, or your shell's config file to make it permanent.

   - **Windows:** Verify the binary is on your `PATH`:

     ```powershell
     where.exe opndossier
     ```

     If not found, add the directory containing `opndossier.exe` to your `PATH` via **System Properties > Environment Variables**, or in PowerShell:

     ```powershell
     $env:PATH += ";C:\path\to\opndossier"
     ```

2. **Permission denied**

   ```bash
   # Make binary executable (pre-built binary or source build)
   chmod +x opndossier
   ```

3. **Config file not found**

   A configuration file is not required. If you are using one and see this error, verify its location:

   ```bash
   ls -la ~/.opnDossier.yaml

   # Or specify a custom location
   opndossier --config /path/to/config.yaml convert config.xml
   ```

### Debugging Installation

```bash
# Verify the binary runs
opndossier version

# Test with verbose output
opndossier --verbose --help
```

If you installed via `go install` or built from source and need to troubleshoot the Go toolchain:

```bash
go env GOPATH GOBIN
go version
```

## Next Steps

After installation:

1. Follow the [Getting Started](getting-started.md) tutorial to process your first config
2. Read the [Configuration Guide](configuration.md) to set up your preferences
3. Check the [Commands Overview](commands/overview.md) for the full command reference
4. Review [Common Workflows](workflows.md) for real-world patterns

---

For installation issues, see our [troubleshooting guide](../examples/troubleshooting.md) or open an issue on GitHub.
