# OPNsense Configuration Processor

Welcome to the **OPNsense Configuration Processor** documentation! This CLI tool helps you process OPNsense `config.xml` files and convert them to human-readable markdown format.

## Features

- 🔧 **Parse OPNsense XML configurations** - Process complex configuration files with ease
- 📝 **Convert to Markdown** - Generate human-readable documentation
- 🎨 **Terminal Display** - View results with syntax highlighting in your terminal
- 💾 **Export to Files** - Save processed configurations to markdown files
- 🔌 **Offline Operation** - Works completely offline, no external dependencies

## Quick Start

```bash
# Convert a configuration file to markdown
opnfocus convert config.xml -o output.md

# Display the result in terminal with syntax highlighting
opnfocus display config.xml

# Get help for any command
opnfocus --help
```

## Project Philosophy

This tool follows the **operator-focused** philosophy:

- **Built for operators, by operators** - Intuitive workflows designed for network administrators
- **Offline-first architecture** - Functions in airgapped environments
- **Structured data approach** - Versioned, portable, and auditable outputs
- **Framework-first development** - Leverages established Go libraries and patterns

## Architecture

The tool uses a layered CLI architecture built with modern Go libraries:

| Component          | Technology                                                  | Purpose                                   |
| ------------------ | ----------------------------------------------------------- | ----------------------------------------- |
| CLI Framework      | [Cobra](https://github.com/spf13/cobra)                     | Command structure & argument parsing     |
| Configuration      | [Viper](https://github.com/spf13/viper)                     | Layered configuration (files, env, flags) |
| CLI Enhancement    | [Charm Fang](https://github.com/charmbracelet/fang)         | Enhanced UX layer (styled help, completion) |
| Structured Logging | [Charm Log](https://github.com/charmbracelet/log)           | Structured, leveled logging               |
| Terminal Styling   | [Charm Lipgloss](https://github.com/charmbracelet/lipgloss) | Styled terminal output formatting        |
| Markdown Rendering | [Charm Glamour](https://github.com/charmbracelet/glamour)   | Markdown rendering in terminal            |
| XML Processing     | Go's built-in `encoding/xml`                                | Native XML parsing and validation         |

### Configuration Management

opnFocus implements comprehensive configuration management with Viper:

**Precedence Order (highest to lowest):**
1. Command-line flags
2. Environment variables (`OPNFOCUS_*`)
3. Configuration file (`~/.opnFocus.yaml`)
4. Default values

**Configuration Options:**
- `verbose`: Enable debug logging
- `quiet`: Suppress all output except errors
- `log_level`: Set log level (debug, info, warn, error)
- `log_format`: Set log format (text, json)
- `input_file`: Default input file path
- `output_file`: Default output file path

## Getting Started

Check out the [Installation Guide](user-guide/installation.md) to get started, or dive into the [Usage Guide](user-guide/usage.md) to learn how to use the tool effectively.

## Contributing

Interested in contributing? See our [Contributing Guide](dev-guide/contributing.md) for information on how to get involved with the project.

---

*This documentation is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) and follows our established documentation standards.*
