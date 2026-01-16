# Installation Guide

This guide covers various methods to install opnDossier on your system.

## Prerequisites

- **Go 1.21+** (for building from source)
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
go build -o opnDossier main.go
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
curl -L https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/opnDossier-linux-amd64 -o opnDossier

# Download the SHA-256 checksum file for verification
curl -L https://github.com/EvilBit-Labs/opnDossier/releases/latest/download/checksums.txt -o checksums.txt

# Verify the binary integrity
sha256sum -c checksums.txt 2>/dev/null | grep opnDossier-linux-amd64 || \
shasum -a 256 -c checksums.txt 2>/dev/null | grep opnDossier-linux-amd64 || \
echo "Warning: Could not verify checksum. Proceed with caution."

# Make executable and install (only if verification passed)
chmod +x opnDossier
sudo mv opnDossier /usr/local/bin/

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
opnDossier --version

# Test basic functionality
opnDossier --help

# Verify Fang enhancements are working
opnDossier completion bash  # Should show bash completion script
```

## Configuration Setup

### 1. Create Configuration Directory

```bash
# Configuration file location (following XDG Base Directory Specification)
mkdir -p ~/.config/opnDossier
touch ~/.config/opnDossier/config.yaml
```

### 2. Basic Configuration

Create a basic configuration file:

```yaml
# ~/.config/opnDossier/config.yaml
verbose: false
quiet: false
```

### 3. Environment Variables

Set up environment variables for your shell:

```bash
# Add to ~/.bashrc, ~/.zshrc, etc.
export OPNDOSSIER_VERBOSE=false
```

## Shell Completion

opnDossier includes shell completion support via Fang:

### Bash

```bash
# Add to ~/.bashrc
source <(opnDossier completion bash)

# Or install globally
opnDossier completion bash > /etc/bash_completion.d/opnDossier
```

### Zsh

```bash
# Add to ~/.zshrc
source <(opnDossier completion zsh)

# Or for oh-my-zsh
opnDossier completion zsh > ~/.oh-my-zsh/completions/_opnDossier
```

### Fish

```bash
opnDossier completion fish | source

# Or save to file
opnDossier completion fish > ~/.config/fish/completions/opnDossier.fish
```

### PowerShell

```powershell
# Add to PowerShell profile
opnDossier completion powershell | Out-String | Invoke-Expression
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
   chmod +x opnDossier
   ```

3. **Config file not found**

   ```bash
   # Verify config file location
   ls -la ~/.config/opnDossier/config.yaml

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

# Install development dependencies
just install-dev

# Run development checks
just dev-check

# Set up pre-commit hooks
just setup-hooks
```

## Container Installation

### Docker

```bash
# Build container image
docker build -t opndossier .

# Run in container
docker run --rm -v $(pwd):/data opndossier convert /data/config.xml
```

### Kubernetes

The following example mounts the configuration file to `/app/config/config.yaml` and uses the `--config` flag to specify its location. Alternatively, you can mount the config to `/etc/opndossier/config.yaml` or use environment variables for configuration.

**ConfigMap:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: opndossier-config
data:
  config.yaml: |
    verbose: "false"
```

**Job:**

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: opndossier-job
spec:
  template:
    spec:
      containers:
        - name: opndossier
          image: opndossier:latest
          args: [convert, /data/config.xml, --config, /app/config/config.yaml]
          volumeMounts:
            - name: config
              mountPath: /app/config
              subPath: config.yaml
            - name: data
              mountPath: /data
      volumes:
        - name: config
          configMap:
            name: opndossier-config
        - name: data
          persistentVolumeClaim:
            claimName: opndossier-data
      restartPolicy: Never
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
