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
opnfocus convert config.xml --display

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

The tool is built using:

| Component | Technology |
|-----------|------------|
| CLI Framework | [Cobra](https://github.com/spf13/cobra) |
| Configuration | [Charm Fang](https://github.com/charmbracelet/fang) |
| Terminal Styling | [Charm Lipgloss](https://github.com/charmbracelet/lipgloss) |
| Markdown Rendering | [Charm Glamour](https://github.com/charmbracelet/glamour) |
| XML Processing | Go's built-in `encoding/xml` |

## Getting Started

Check out the [Installation Guide](user-guide/installation.md) to get started, or dive into the [Usage Guide](user-guide/usage.md) to learn how to use the tool effectively.

## Contributing

Interested in contributing? See our [Contributing Guide](dev-guide/contributing.md) for information on how to get involved with the project.

---

*This documentation is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) and follows our established documentation standards.*
