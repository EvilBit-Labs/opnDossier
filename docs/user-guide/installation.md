# Installation Guide

This guide covers various methods to install opnFocus on your system.

## Prerequisites

- **Go 1.21+** (for building from source)
- **Linux, macOS, or Windows** (cross-platform support)

## Installation Methods

### 1. Go Install (Recommended)

The simplest way to install opnFocus if you have Go installed:

```bash
go install github.com/unclesp1d3r/opnFocus@latest
```

This will install the latest release to your `$GOPATH/bin` directory.

### 2. Build from Source

#### Clone and Build

```bash
# Clone the repository
git clone https://github.com/unclesp1d3r/opnFocus.git
cd opnFocus

# Install dependencies and build
just install
just build

# Or build manually
go build -o opnfocus main.go
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
curl -L https://github.com/unclesp1d3r/opnFocus/releases/latest/download/opnfocus-linux-amd64 -o opnfocus
chmod +x opnfocus
sudo mv opnfocus /usr/local/bin/
```

Available platforms:

- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

## Verification

Verify your installation:

```bash
# Check version
opnfocus --version

# Test basic functionality
opnfocus --help

# Verify Fang enhancements are working
opnfocus completion bash  # Should show bash completion script
```

## Configuration Setup

### 1. Create Configuration Directory

```bash
# Configuration file location
mkdir -p ~/.config
touch ~/.opnFocus.yaml
```

### 2. Basic Configuration

Create a basic configuration file:

```yaml
# ~/.opnFocus.yaml
log_level: info
log_format: text
verbose: false
quiet: false
```

### 3. Environment Variables

Set up environment variables for your shell:

```bash
# Add to ~/.bashrc, ~/.zshrc, etc.
export OPNFOCUS_LOG_LEVEL=info
export OPNFOCUS_LOG_FORMAT=text
```

## Shell Completion

opnFocus includes shell completion support via Fang:

### Bash

```bash
# Add to ~/.bashrc
source <(opnfocus completion bash)

# Or install globally
opnfocus completion bash > /etc/bash_completion.d/opnfocus
```

### Zsh

```bash
# Add to ~/.zshrc
source <(opnfocus completion zsh)

# Or for oh-my-zsh
opnfocus completion zsh > ~/.oh-my-zsh/completions/_opnfocus
```

### Fish

```bash
opnfocus completion fish | source

# Or save to file
opnfocus completion fish > ~/.config/fish/completions/opnfocus.fish
```

### PowerShell

```powershell
# Add to PowerShell profile
opnfocus completion powershell | Out-String | Invoke-Expression
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
   chmod +x opnfocus
   ```

3. **Config file not found**

   ```bash
   # Verify config file location
   ls -la ~/.opnFocus.yaml

   # Use custom config location
   opnfocus --config /path/to/config.yaml convert config.xml
   ```

### Debugging Installation

```bash
# Check Go environment
go env GOPATH GOBIN

# Verify build
go version
go build -v .

# Test with verbose output
opnfocus --verbose --help
```

## Development Installation

For development and contributing:

```bash
# Clone with development setup
git clone https://github.com/unclesp1d3r/opnFocus.git
cd opnFocus

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
docker build -t opnfocus .

# Run in container
docker run --rm -v $(pwd):/data opnfocus convert /data/config.xml
```

### Kubernetes

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: opnfocus-config
data:
  config.yaml: |
    log_level: "info"
    log_format: "json"
---
apiVersion: batch/v1
kind: Job
metadata:
  name: opnfocus-job
spec:
  template:
    spec:
      containers:
      - name: opnfocus
        image: opnfocus:latest
        args: ["convert", "/data/config.xml"]
        volumeMounts:
        - name: config
          mountPath: /.opnFocus.yaml
          subPath: config.yaml
        - name: data
          mountPath: /data
      volumes:
      - name: config
        configMap:
          name: opnfocus-config
      - name: data
        persistentVolumeClaim:
          claimName: opnfocus-data
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
go install github.com/unclesp1d3r/opnFocus@latest
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

For installation issues, see our [troubleshooting guide](../troubleshooting.md) or open an issue on GitHub.
