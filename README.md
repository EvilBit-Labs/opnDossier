# OPNsense Configuration Processor

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-mkdocs-blue.svg)](http://127.0.0.1:8000/)

## Overview

A command-line tool designed specifically for network operators and administrators working with OPNsense firewalls. This tool transforms complex XML configuration files into clear, human-readable markdown documentation, making it easier to understand, document, and audit your network configurations.

**Built for operators, by operators** - with a focus on offline operation, structured data, and intuitive workflows.

## ✨ Features

- 🔧 **Parse OPNsense XML configurations** - Process complex configuration files with ease
- 📝 **Convert to Markdown** - Generate human-readable documentation from XML configs
- 🎨 **Terminal Display** - View results with syntax highlighting directly in your terminal
- 💾 **Export to Files** - Save processed configurations as markdown files
- 🔌 **Offline Operation** - Works completely offline, perfect for airgapped environments
- 🛡️ **Security-First** - No external dependencies, no telemetry, secure by design
- ⚡ **Fast & Lightweight** - Built with Go for performance and reliability

## 🚀 Quick Start

### Installation

**Prerequisites:** Go 1.21 or later

```bash
# Clone the repository
git clone https://github.com/your-username/opnFocus.git
cd opnFocus

# Install dependencies and build
just install
just build
```

**Alternative installation methods:**

```bash
# Direct Go installation
go install github.com/your-username/opnFocus@latest

# Or build from source
go build -o opnfocus main.go
```

### Basic Usage

```bash
# Convert OPNsense config to markdown and save to file
opnfocus convert config.xml -o documentation.md

# Display result in terminal with syntax highlighting
opnfocus convert config.xml --display

# Get help for any command
opnfocus --help
opnfocus convert --help
```

## 🏗️ Architecture

Built with modern Go practices and established libraries:

| Component | Technology |
|-----------|------------|
| CLI Framework | [Cobra](https://github.com/spf13/cobra) |
| Configuration | [Charm Fang](https://github.com/charmbracelet/fang) |
| Terminal Styling | [Charm Lipgloss](https://github.com/charmbracelet/lipgloss) |
| Markdown Rendering | [Charm Glamour](https://github.com/charmbracelet/glamour) |
| XML Processing | Go's built-in `encoding/xml` |

## 🛠️ Development

This project follows comprehensive development standards and uses modern Go tooling:

```bash
# Development workflow using Just
just test      # Run tests
just lint      # Run linters
just check     # Run all pre-commit checks
just dev       # Run in development mode
just docs      # Serve documentation locally
```

### Project Structure

```
opnfocus/
├── cmd/                 # Application entry point
├── internal/
│   ├── config/         # Configuration handling
│   ├── parser/         # XML parsing logic
│   ├── converter/      # Data conversion logic
│   └── display/        # Output formatting
├── docs/               # MkDocs documentation
├── justfile           # Task runner configuration
└── AGENTS.md          # Development standards
```

## 🤝 Contributing

We welcome contributions! This project follows strict coding standards and development practices.

**Before contributing:**
1. Read our [development standards](AGENTS.md)
2. Check existing issues and pull requests
3. Follow our Git workflow and commit message standards

**Development process:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Follow our coding standards (see [AGENTS.md](AGENTS.md))
4. Write tests and ensure >80% coverage: `just test`
5. Run all checks: `just ci-check`
6. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
7. Submit a pull request

**Quality standards:**
- All code must pass `golangci-lint`
- Tests required for new functionality
- Documentation updates for user-facing changes
- Follow Go best practices and project conventions

## 📖 Documentation

- **[Full Documentation](http://127.0.0.1:8000/)** - Complete user and developer guides
- **[Development Standards](AGENTS.md)** - Coding standards and architectural principles
- **[API Reference](docs/dev-guide/api.md)** - Detailed API documentation

## 🔒 Security

This tool is designed with security as a first-class concern:

- **No external dependencies** - Operates completely offline
- **No telemetry** - No data collection or external communication
- **Secure by default** - Follows security best practices
- **Input validation** - All inputs are validated and sanitized

For security issues, please see our security policy.

## 📄 License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- Inspired by [TKCERT/pfFocus](https://github.com/TKCERT/pfFocus) for pfSense configurations
- Built with [Charm](https://charm.sh/) libraries for beautiful terminal experiences
- Follows [Google Go Style Guide](https://google.github.io/styleguide/go/) for code quality

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/unclesp1d3r/opnFocus/issues)
- **Discussions:** [GitHub Discussions](https://github.com/unclesp1d3r/opnFocus/discussions)
- **Documentation:** [Full Documentation](http://127.0.0.1:8000/)

---

*Built with ❤️ for network operators everywhere.*
