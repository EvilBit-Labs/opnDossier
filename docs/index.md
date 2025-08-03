# OPNsense Configuration Processor

Welcome to the **OPNsense Configuration Processor** documentation! This CLI tool helps you process OPNsense `config.xml` files and convert them to human-readable markdown format.

## Features

- 🔧 **Parse OPNsense XML configurations** - Process complex configuration files with ease
- ✅ **Configuration Validation** - Comprehensive validation with detailed error reporting
- 📝 **Convert to Markdown** - Generate human-readable documentation
- 🎨 **Terminal Display** - View results with syntax highlighting in your terminal
- 💾 **Export to Files** - Save processed configurations to markdown files
- 🔌 **Offline Operation** - Works completely offline, no external dependencies
- 🚀 **Streaming Processing** - Memory-efficient handling of large configuration files

## Quick Start

```bash
# Convert a configuration file to markdown
opndossier convert config.xml -o output.md

# Display the result in terminal with syntax highlighting
opndossier display config.xml

# Get help for any command
opndossier --help
```

## Project Philosophy

This tool follows the **operator-focused** philosophy:

- **Built for operators, by operators** - Intuitive workflows designed for network administrators
- **Offline-first architecture** - Functions in airgapped environments
- **Structured data approach** - Versioned, portable, and auditable outputs
- **Framework-first development** - Leverages established Go libraries and patterns

## Architecture

The tool uses a layered CLI architecture built with modern Go libraries:

| Component          | Technology                                                  | Purpose                                     |
| ------------------ | ----------------------------------------------------------- | ------------------------------------------- |
| CLI Framework      | [Cobra](https://github.com/spf13/cobra)                     | Command structure & argument parsing        |
| Configuration      | [Viper](https://github.com/spf13/viper)                     | Layered configuration (files, env, flags)   |
| CLI Enhancement    | [Charm Fang](https://github.com/charmbracelet/fang)         | Enhanced UX layer (styled help, completion) |
| Structured Logging | [Charm Log](https://github.com/charmbracelet/log)           | Structured, leveled logging                 |
| Terminal Styling   | [Charm Lipgloss](https://github.com/charmbracelet/lipgloss) | Styled terminal output formatting           |
| Markdown Rendering | [Charm Glamour](https://github.com/charmbracelet/glamour)   | Markdown rendering in terminal              |
| XML Processing     | Go's built-in `encoding/xml`                                | Native XML parsing and validation           |

### Data Model Architecture

opnDossier uses a hierarchical model structure that organizes OPNsense configuration into logical domains:

- **System Domain**: Core system settings, users, groups, system services
- **Network Domain**: Interfaces, routing, VLANs, network addressing
- **Security Domain**: Firewall rules, NAT, VPN, certificates
- **Services Domain**: DNS, DHCP, monitoring, web services

This hierarchical approach provides logical organization, improved maintainability, domain-specific validation, and better extensibility. See the [Model Refactor Documentation](model_refactor.md) for detailed information.

### Processor Workflow

The processor implements a comprehensive four-phase pipeline:

1. **Normalize**: Fill defaults, canonicalize addresses, sort for determinism
2. **Validate**: Struct tag validation, custom checks, cross-field validation
3. **Analyze**: Dead rule detection, security analysis, performance checks
4. **Transform**: Multi-format output (Markdown, JSON, YAML)

See the [Sample Report](sample-report.md) for an example of the comprehensive analysis output.

### Configuration Management

opnDossier implements comprehensive configuration management with Viper:

**Precedence Order (highest to lowest):**

1. Command-line flags
2. Environment variables (`OPNDOSSIER_*`)
3. Configuration file (`~/.opnDossier.yaml`)
4. Default values

**Configuration Options:**

- `verbose`: Enable debug logging
- `quiet`: Suppress all output except errors
- `log_level`: Set log level (debug, info, warn, error)
- `log_format`: Set log format (text, json)
- `input_file`: Default input file path
- `output_file`: Default output file path

## Validation & Error Handling

opnDossier includes comprehensive validation capabilities:

### Validation Features

- **Structure Validation** - Ensures required fields are present (hostname, domain, etc.)
- **Data Type Validation** - Verifies IP addresses, subnet masks, and network configurations
- **Cross-Field Validation** - Checks relationships between configuration elements
- **Streaming Limits** - Handles large files efficiently with memory-conscious processing

### Error Output Examples

**Parse Error:**

```text
parse error at line 45, column 12: XML syntax error: expected element name after <
```

**Validation Error:**

```text
validation error at opnsense.system.hostname: hostname is required
```

**Aggregated Report:**

```text
validation failed with 3 errors: hostname is required (and 2 more)
  - opnsense.system.hostname: hostname is required
  - opnsense.system.domain: domain is required
  - opnsense.interfaces.lan.subnet: subnet mask '35' must be valid (0-32)
```

## Getting Started

Check out the [Installation Guide](user-guide/installation.md) to get started, or dive into the [Usage Guide](user-guide/usage.md) to learn how to use the tool effectively.

## Documentation

- **[User Guide](user-guide/)** - Installation, configuration, and usage instructions
- **[Examples](examples/)** - Comprehensive usage examples and common workflows
- **[Developer Guide](dev-guide/)** - API documentation, architecture, and development guidelines
- **[Compliance Standards](compliance-standards.md)** - Security and compliance framework documentation
- **[CIS-like Firewall Reference](cis-like-firewall-reference.md)** - Firewall configuration reference

## Contributing

Interested in contributing? See our [Contributing Guide](dev-guide/contributing.md) for information on how to get involved with the project.

---

*This documentation is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) and follows our established documentation standards.*
