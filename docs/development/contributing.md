# Contributing Guide

Thank you for your interest in contributing to opnDossier! This guide will help you get started with development and understand our contribution process.

## Development Environment Setup

### Prerequisites

- **Go 1.26+**
- **Git** with GPG signing configured
- **[Just](https://just.systems/)** - Task runner (required for CI-equivalent checks)
- **[golangci-lint](https://golangci-lint.run/usage/install/)** - Go linter (latest version recommended)
- **[pre-commit](https://pre-commit.com/)** - Git hook framework

### Getting Started

1. Fork the repository on GitHub

2. Clone your fork locally:

   ```bash
   git clone https://github.com/yourusername/opnDossier.git
   cd opnDossier
   ```

3. Install dependencies and set up pre-commit hooks:

   ```bash
   just install
   ```

4. Run tests to ensure everything works:

   ```bash
   just test
   ```

5. Run all quality checks (CI-equivalent):

   ```bash
   just ci-check
   ```

## Development Workflow

### Code Organization

The project follows standard Go conventions:

- `cmd/` - CLI commands (Cobra framework)
- `internal/` - Internal packages
  - `cfgparser/` - XML parsing and validation
  - `config/` - Configuration management (Viper)
  - `converter/` - Data conversion and report generation
  - `model/` - Data models (re-export layer over `internal/schema/`)
  - `schema/` - Canonical data model structs
  - `compliance/` - Plugin interfaces
  - `plugins/` - Compliance plugin implementations (stig, sans, firewall)
  - `audit/` - Audit engine and plugin management
  - `display/` - Terminal display formatting
  - `export/` - File export functionality
  - `logging/` - Structured logging (wraps `charmbracelet/log`)
  - `progress/` - CLI progress indicators
  - `validator/` - Configuration validation
- `docs/` - Documentation (MkDocs format)
- `testdata/` - Test fixtures and sample configuration files

### Making Changes

1. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our [development standards](standards.md) and the coding standards in [AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md)

3. Add tests for new functionality:

   ```bash
   just test
   ```

4. Run benchmarks if modifying parser performance:

   ```bash
   go test -run=^$ -bench=. ./internal/cfgparser/
   ```

5. Run linting:

   ```bash
   just lint
   ```

6. Run all CI-equivalent checks before committing:

   ```bash
   just ci-check
   ```

### Parser Development

When modifying XML parsing logic:

- The parser lives in `internal/cfgparser/`
- Data models are defined in `internal/schema/` with re-exports in `internal/model/`
- Test with sample files in `testdata/`
- Add benchmarks for performance-critical changes
- Preserve backward compatibility in the `Parser` interface

### Testing

We maintain several types of tests:

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test complete workflows end-to-end
- **Golden file tests**: Snapshot tests using `sebdah/goldie/v2`
- **Performance tests**: Benchmarks for parser memory and speed
- **Error handling tests**: Verify proper error reporting

Run specific test suites:

```bash
# All tests
just test

# Specific package
go test ./internal/cfgparser/

# Benchmarks only
go test -run=^$ -bench=. ./internal/cfgparser/

# With coverage
go test -cover ./...

# Race detection
just test-race
```

## Commit Standards

### Commit Message Format

```text
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

**Scopes:** `(parser)`, `(converter)`, `(audit)`, `(cli)`, `(model)`, `(plugin)`, `(builder)`, `(schema)`

### DCO Sign-off

All commits must include a DCO sign-off:

```bash
git commit -s -m "feat(parser): add support for new XML element"
```

## Pull Request Process

1. **Before submitting**:

   - Ensure `just ci-check` passes (pre-commit hooks + lint + tests)
   - Update documentation if needed
   - Include tests for new functionality

2. **PR Description**:

   - Clearly describe what changes were made
   - Reference any related issues
   - Include examples of new functionality
   - Note any breaking changes

3. **Review process**:

   - All PRs require at least one review (human or CodeRabbit)
   - CI must pass (golangci-lint, gofumpt, tests, CodeQL, Grype)
   - Documentation updates may be requested

## Coding Standards

Please follow the coding standards documented in [AGENTS.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md), which covers:

- Go coding conventions and naming
- Error handling patterns
- Logging with `charmbracelet/log`
- Thread safety patterns
- XML element presence detection
- Testing standards

## Performance Considerations

This project processes potentially large XML files, so performance matters:

- Add benchmarks for significant algorithmic changes
- Consider memory allocation patterns
- Test with sample files of varying sizes in `testdata/`
- The parser limits input to 10MB by default (`DefaultMaxInputSize`)

## Getting Help

- Check existing issues and documentation first
- Open an issue for bugs or feature requests
- Review AGENTS.md for detailed development standards
- Review the architecture documentation in `docs/development/`

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](https://github.com/EvilBit-Labs/opnDossier/blob/main/LICENSE).

Thank you for contributing to opnDossier!
