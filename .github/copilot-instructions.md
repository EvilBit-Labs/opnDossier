# Copilot Instructions for opnFocus

## Project Overview

opnFocus is a command-line tool designed for network operators working with OPNsense firewalls. It processes XML configuration files into human-readable Markdown documentation. The project emphasizes offline operation, structured data, and intuitive workflows.

## Architecture

- **Core Components:**
  - `cmd/`: Entry points for CLI commands.
  - `internal/config/`: Configuration management.
  - `internal/converter/`: XML to Markdown conversion logic.
  - `internal/display/`: Output formatting.
  - `internal/export/`: File export functionality.
  - `internal/log/`: Logging utilities.
  - `internal/model/`: Data models for OPNsense configurations.
  - `internal/parser/`: XML parsing logic.
  - `templates/`: Markdown templates for documentation.
- **Offline-First Design:**
  - No external dependencies.
  - Airgap-compatible.
  - Local processing of all operations.

## Development Standards

- **Coding Standards:** Refer to `AGENTS.md` and `DEVELOPMENT_STANDARDS.md` for Go-specific conventions and project-specific rules.
- **Commit Messages:** Follow the [Conventional Commits](https://www.conventionalcommits.org) specification.
- **Security Principles:**
  - No secrets in code.
  - Use environment variables for sensitive data.
  - Validate and sanitize user inputs.

## Developer Workflows

### Build

Use `just` commands for streamlined workflows:

```bash
just install
just build
```

Alternatively, build directly:

```bash
go build -o opnfocus main.go
```

### Test

Run tests using:

```bash
go test ./...
```

### Debugging

- Use verbose logging by enabling debug mode in `internal/log/logger.go`.
- Check XML test data in `internal/parser/testdata/` for debugging parsing issues.

## Integration Points

- **External Dependencies:** None. The project is designed for offline operation.
- **Cross-Component Communication:**
  - XML parsing (`internal/parser/`) feeds data models (`internal/model/`).
  - Data models are converted to Markdown (`internal/converter/`) and exported (`internal/export/`).

## Examples

### Parsing XML

```bash
opnfocus parse -i config.xml -o output.md
```

### Exporting Markdown

```bash
opnfocus export -f output.md
```

## References

- [AGENTS.md](../AGENTS.md): Coding standards and architectural principles.
- [DEVELOPMENT_STANDARDS.md](../DEVELOPMENT_STANDARDS.md): Go-specific conventions.
- [ARCHITECTURE.md](../ARCHITECTURE.md): Detailed system design.
- [README.md](../README.md): Project overview and quick start.

---

Feedback is welcome to improve these instructions further.
