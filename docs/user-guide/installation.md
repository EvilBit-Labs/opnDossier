# Installation Guide

This guide covers various methods to install opnDossier on your system.

## Prerequisites

- **Go 1.24.2+** (for building from source, 1.26+ recommended)
- **Linux, macOS, or Windows** (cross-platform support)

## Installation Methods

### 1. Go Install (Recommended)

The simplest way to install opnDossier if you have Go installed:

```bash
go install github.com/EvilBit-Labs/opnDossier@latest
```

This will install the latest release to your `$GOPATH/bin` directory.

### 2. Build from Source

#### Clone and Build

```bash
# Clone the repository
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier

# Install dependencies and build
just install
just build

# Or build manually
go build -o opndossier main.go
```

#### Using Just (Task Runner)

The project uses [Just](https://just.systems/) for task management:

```bash
# Install Just if you don't have it
cargo install just

# Available tasks
just --list

# Install dependencies
just install

# Build the application
just build

# Run tests
just test

# Run all quality checks
just check
```

### 3. Download Pre-built Binaries

Pre-built binaries are available for multiple platforms:

```bash
# Download the latest release for your platform
curl -L https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/opnDossier-linux-amd64 -o opndossier

# Download the SHA-256 checksum file for verification
curl -L https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/checksums.txt -o checksums.txt

# Verify the binary integrity
sha256sum -c checksums.txt 2>/dev/null | grep opnDossier-linux-amd64 || \
shasum -a 256 -c checksums.txt 2>/dev/null | grep opnDossier-linux-amd64 || \
echo "Warning: Could not verify checksum. Proceed with caution."

# Make executable and install (only if verification passed)
chmod +x opndossier
sudo mv opndossier /usr/local/bin/

# Clean up checksum file
rm checksums.txt
```

**Security Note:** Always verify binary integrity before installation. The checksum verification ensures the binary hasn't been tampered with during download.

Available platforms:

- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

## Verification

Verify your installation:

```bash
# Check version
opndossier version

# Test basic functionality
opndossier --help

# Test shell completion
opndossier completion bash  # Should show bash completion script
```

## Configuration Setup

### 1. Create Configuration File

opnDossier looks for a configuration file at `~/.opnDossier.yaml`:

```bash
touch ~/.opnDossier.yaml
```

You can also specify a custom config file location with the `--config` flag.

### 2. Basic Configuration

Create a basic configuration file:

```yaml
# ~/.opnDossier.yaml
verbose: false
quiet: false
format: markdown
```

### 3. Environment Variables

Set up environment variables for your shell:

```bash
# Add to ~/.bashrc, ~/.zshrc, etc.
export OPNDOSSIER_VERBOSE=false
```

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

   ```bash
   # Check if Go bin is in PATH
   echo $GOPATH/bin
   export PATH=$PATH:$GOPATH/bin
   ```

2. **Permission denied**

   ```bash
   # Make binary executable
   chmod +x opndossier
   ```

3. **Config file not found**

   ```bash
   # Verify config file location
   ls -la ~/.opnDossier.yaml

   # Use custom config location
   opndossier --config /path/to/config.yaml convert config.xml
   ```

### Debugging Installation

```bash
# Check Go environment
go env GOPATH GOBIN

# Verify build
go version
go build -v .

# Test with verbose output
opndossier --verbose --help
```

## Development Installation

For development and contributing:

```bash
# Clone with development setup
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier

# Install dependencies (Go modules + pre-commit hooks)
just install

# Run quality checks
just check

# Run CI-equivalent checks
just ci-check
```

## Next Steps

After installation:

1. Read the [Configuration Guide](configuration.md) to set up your preferences
2. Check the [Usage Guide](usage.md) for common workflows
3. Review [Examples](../examples/) for practical use cases

## Updating

### Go Install Method

```bash
# Update to latest version
go install github.com/EvilBit-Labs/opnDossier@latest
```

### Source Build Method

```bash
# Update source and rebuild
git pull origin main
just build
```

### Binary Method

Download and replace the binary with the latest release.

---

For installation issues, see our [troubleshooting guide](../examples/troubleshooting.md) or open an issue on GitHub.
