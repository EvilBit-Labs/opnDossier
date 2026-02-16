# opnDossier - OPNsense Configuration Processor

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11920/badge)](https://www.bestpractices.dev/projects/11920) [![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org) [![License](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE) [![codecov](https://codecov.io/gh/EvilBit-Labs/opnDossier/graph/badge.svg?token=WD1QD9ITZF)](https://codecov.io/gh/EvilBit-Labs/opnDossier) [![Documentation](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/index.md) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/EvilBit-Labs/opnDossier?utm_source=oss&utm_medium=github&utm_campaign=EvilBit-Labs%2FopnDossier&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews) [![wakatime](https://wakatime.com/badge/user/2d2fbc27-e3f7-4ec1-b2a7-935e48bad498/project/018dae18-42c0-4e3e-8330-14d39f574bd5.svg)](https://wakatime.com/badge/user/2d2fbc27-e3f7-4ec1-b2a7-935e48bad498/project/018dae18-42c0-4e3e-8330-14d39f574bd5) [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FEvilBit-Labs%2FopnDossier.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FEvilBit-Labs%2FopnDossier?ref=badge_shield)

## Overview

opnDossier is a command-line tool for network operators and security professionals working with OPNsense firewalls. Transform complex XML configuration files into clear, readable documentation and identify security issues, misconfigurations, and optimization opportunities.

Built for offline operation in secure environments - no external dependencies, no telemetry, complete airgapped support.

### What It Does

- **Security Analysis** - Automatically detect vulnerabilities, insecure protocols, weak configurations
- **Dead Rule Detection** - Find unreachable firewall rules and unused interfaces
- **Configuration Validation** - Comprehensive checks for misconfigurations and best-practice issues
- **Multi-Format Export** - Convert to markdown documentation, JSON, or YAML for integration
- **Offline Operation** - Works completely offline, perfect for airgapped networks

## Quick Start

### Installation

Download pre-built binaries for Linux, macOS, or Windows from [releases](https://github.com/EvilBit-Labs/opnDossier/releases), or install from source:

```bash
go install github.com/EvilBit-Labs/opnDossier@latest
```

### Basic Usage

```bash
# Analyze your config and display in terminal
opnDossier display config.xml

# Generate security report
opnDossier convert config.xml -o security-report.md

# Export to JSON for automation
opnDossier convert -f json config.xml -o output.json
```

## Analysis & Security Features

opnDossier automatically analyzes your OPNsense configuration to identify security issues, misconfigurations, and optimization opportunities.

### Security Vulnerability Detection

Identifies common security issues in your firewall configuration:

- **Insecure Protocols** - Detects HTTP admin interfaces, Telnet, unencrypted SNMP
- **Weak Configurations** - Finds default community strings, overly permissive rules
- **Certificate Issues** - Identifies expired certificates, weak key sizes
- **Credential Exposure** - Detects plaintext passwords or weak authentication

Example output:

```text
SECURITY FINDINGS:
- [HIGH] Admin interface accessible via HTTP (port 80)
- [HIGH] SNMP using default community string 'public'
- [MEDIUM] Firewall rule allows ANY to ANY on port 22
- [MEDIUM] VPN certificate expires in 14 days
```

### Dead Rule Detection

Automatically identifies firewall rules that will never be reached:

- Rules positioned after "block all" rules
- Duplicate rules with identical criteria
- Rules referencing deleted interfaces or aliases

Example output:

```text
DEAD RULES DETECTED:
- Rule #15: Allow SSH from LAN - unreachable (blocked by rule #12)
- Rule #23: Allow HTTPS from DMZ - references deleted interface 'dmz0'
- Rule #31: Block RDP - duplicate of rule #28
```

### Configuration Validation

Comprehensive checks for structural and logical issues:

- **Required Fields** - Validates hostname, domain, network interfaces
- **Data Types** - Ensures IP addresses, subnets, ports are valid
- **Cross-Field Validation** - Checks relationships between configuration elements
- **Network Topology** - Validates gateway assignments, routing tables, VLAN configurations

Example validation report:

```text
VALIDATION ERRORS:
- opnsense.interfaces.wan.ipaddr: IP address '300.300.300.300' is invalid
- opnsense.system.hostname: hostname is required
- opnsense.firewall.rules: gateway 'WAN_GW' referenced but not defined
```

### Unused Resource Detection

Finds enabled resources not actively used:

- Interfaces enabled but not referenced in rules or services
- Aliases defined but never used in firewall rules
- VPN tunnels configured but disabled
- Services running without corresponding firewall rules

### Compliance Checking

Built-in validation against security and operational best practices (planned v2.1). Tracking: [#174](https://github.com/EvilBit-Labs/opnDossier/issues/174).

- STIG compliance checks (planned v2.1)
- Industry-standard security baselines (planned v2.1)
- SANS security guidelines (planned v2.1)
- Custom compliance profiles (planned v2.1)

## Features

### Analysis & Reporting

- **Security vulnerability detection** - Identify insecure protocols, weak configurations, credential exposure
- **Dead rule detection** - Find unreachable firewall rules and duplicate rules
- **Unused resource analysis** - Detect unused interfaces, aliases, and services
- **Configuration validation** - Comprehensive structural and logical validation
- **Compliance checking (planned v2.1)** - Industry-standard security baselines and best practices

### Output & Export

- **Multi-format export** - Generate markdown documentation, JSON, or YAML output
- **Terminal display** - Rich terminal output with syntax highlighting and theme support
- **File export** - Save processed configurations with overwrite protection
- **Template-based reports** - Customizable markdown templates (legacy, deprecated v3.0)
- **International character support** - UTF-8, US-ASCII, ISO-8859-1, and Windows-1252 input encodings

### Performance & Architecture

- **Streaming processing** - Memory-efficient handling of large configuration files
- **Fast & lightweight** - Built with Go for performance and reliability
- **Offline operation** - Works completely offline, perfect for airgapped environments
- **Cross-platform** - Native binaries for Linux, macOS, and Windows

### Security & Privacy

- **No external dependencies** - Operates completely offline
- **No telemetry** - Zero data collection or external communication
- **Secure by design** - Input validation, sanitization, and SBOM generation throughout
- **Vulnerability scanning** - Automated dependency scanning and security checks in CI/CD

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform:

- [Linux (amd64, arm64)](https://github.com/EvilBit-Labs/opnDossier/releases)
- [macOS (Intel, Apple Silicon)](https://github.com/EvilBit-Labs/opnDossier/releases)
- [Windows (amd64)](https://github.com/EvilBit-Labs/opnDossier/releases)

Extract and run:

```bash
tar -xzf opnDossier-*.tar.gz
./opnDossier --help
```

### Install via Go

**Prerequisites:** Go 1.21 or later

```bash
go install github.com/EvilBit-Labs/opnDossier@latest
```

### Build from Source

```bash
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier
go build -o opnDossier main.go
```

For development builds with additional tooling, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage Examples

### Security Analysis

```bash
# Generate comprehensive security report
opnDossier convert config.xml -o security-report.md

# Display configuration with security findings in terminal
opnDossier display config.xml

# Export findings to JSON for automation/integration
opnDossier convert -f json config.xml -o findings.json
```

### Configuration Documentation

```bash
# Convert OPNsense config to markdown documentation
opnDossier convert config.xml -o firewall-docs.md

# Generate YAML for configuration management tools
opnDossier convert -f yaml config.xml -o config.yaml

# Display in terminal with custom wrap width
opnDossier display --wrap 100 config.xml
```

### Validation

```bash
# Validate configuration file
opnDossier validate config.xml

# Validate and convert in one step
opnDossier convert --validate config.xml -o report.md
```

### Advanced Options

```bash
# Include system tunables in report
opnDossier convert config.xml -o comprehensive.md --include-tunables

# Verbose output for troubleshooting
opnDossier --verbose convert config.xml

# Quiet mode - only show errors
opnDossier --quiet convert config.xml -o output.md
```

## Configuration

opnDossier can be configured via command-line flags, environment variables, or a configuration file.

### Configuration Options

| Setting         | CLI Flag       | Environment Variable     | Config File         | Description                      |
| --------------- | -------------- | ------------------------ | ------------------- | -------------------------------- |
| Verbose logging | `--verbose`    | `OPNDOSSIER_VERBOSE`     | `verbose: true`     | Enable debug/verbose output      |
| Quiet mode      | `--quiet`      | `OPNDOSSIER_QUIET`       | `quiet: true`       | Suppress all non-error output    |
| Input file      | (positional)   | `OPNDOSSIER_INPUT_FILE`  | `input_file: path`  | Default input configuration file |
| Output file     | `-o, --output` | `OPNDOSSIER_OUTPUT_FILE` | `output_file: path` | Default output file path         |

For a complete list of all configuration options, see the [Configuration Reference](docs/user-guide/configuration-reference.md).

### Configuration File Example

Create `~/.opnDossier.yaml`:

```yaml
# Logging
verbose: false
quiet: false

# File paths
input_file: /path/to/default/config.xml
output_file: ./output.md
```

### Usage Examples

```bash
# Using CLI flags
opnDossier --verbose convert config.xml

# Using environment variables
export OPNDOSSIER_VERBOSE=true
opnDossier convert config.xml

# Using config file (automatically loaded from ~/.opnDossier.yaml)
opnDossier convert config.xml
```

## Output Formats

opnDossier supports multiple output formats for different use cases:

- **Markdown** - Human-readable documentation with formatted tables and sections
- **JSON** - Machine-readable format for automation and integration
- **YAML** - Configuration management and structured data export
- **Terminal Display** - Rich syntax-highlighted output with theme support

Specify format with `-f` or `--format` flag:

```bash
opnDossier convert -f json config.xml -o output.json
opnDossier convert -f yaml config.xml -o output.yaml
opnDossier convert -f markdown config.xml -o output.md  # default
```

## Documentation

- **[User Guide](docs/user-guide/)** - Installation, usage, and configuration
- **[Security Documentation](docs/security/)** - Vulnerability scanning and security features
- **[API Reference](docs/api.md)** - Detailed API documentation
- **[Examples](docs/examples/)** - Real-world usage examples

For developers:

- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project
- **[Architecture Documentation](docs/development/architecture.md)** - System design and architecture

## Support

- **Issues** - [GitHub Issues](https://github.com/EvilBit-Labs/opnDossier/issues)
- **Discussions** - [GitHub Discussions](https://github.com/EvilBit-Labs/opnDossier/discussions)
- **Documentation** - [Full Documentation](docs/index.md)
- **Contributing** - [Contributing Guide](CONTRIBUTING.md)

## Troubleshooting

- If you see garbled characters, confirm the XML declaration encoding matches the file's actual encoding.
- Supported input encodings include UTF-8, US-ASCII, ISO-8859-1, and Windows-1252; convert legacy files to UTF-8 if needed.

## Security

opnDossier is designed with security as a first-class concern:

- **No external dependencies** - Operates completely offline
- **No telemetry** - No data collection or external communication
- **Secure by design** - Input validation, sanitization, and SBOM generation
- **Automated scanning** - Daily vulnerability scans and dependency audits in CI/CD

For security vulnerabilities, please see our [security policy](SECURITY.md).

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Acknowledgements

- Inspired by [TKCERT/pfFocus](https://github.com/TKCERT/pfFocus) for pfSense configurations
- Terminal UI powered by [Charm](https://charm.sh/) - [glamour](https://github.com/charmbracelet/glamour), [lipgloss](https://github.com/charmbracelet/lipgloss), [log](https://github.com/charmbracelet/log), [bubbles](https://github.com/charmbracelet/bubbles)
- CLI framework by [spf13/cobra](https://github.com/spf13/cobra) and [spf13/viper](https://github.com/spf13/viper)
- Markdown generation by [nao1215/markdown](https://github.com/nao1215/markdown)
- Documentation built with [MkDocs](https://www.mkdocs.org/) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)

---

Built for network operators and security professionals.
