# Contributing Guide

Thank you for your interest in contributing to the OPNsense Configuration Processor! This guide will help you get started with development and understand our contribution process.

## Development Environment Setup

### Prerequisites

- Go 1.21 or later
- Git
- Just (command runner) - optional but recommended

### Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/yourusername/opnFocus.git
   cd opnFocus
   ```

3. Install dependencies:

   ```bash
   go mod download
   ```

4. Run tests to ensure everything works:

   ```bash
   go test ./...
   ```

## Development Workflow

### Code Organization

The project follows standard Go conventions:

- `cmd/` - CLI commands and main entry points
- `internal/` - Internal packages not exported to external users
  - `config/` - Configuration management and validation
  - `parser/` - XML parsing and streaming logic
  - `model/` - Data structures representing OPNsense configuration
- `docs/` - Documentation (MkDocs format)
- `testdata/` - Test fixtures and sample files

### Making Changes

1. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our [development standards](../DEVELOPMENT_STANDARDS.md)

3. Add tests for new functionality:

   ```bash
   go test ./... -v
   ```

4. Run benchmarks if modifying parser performance:

   ```bash
   go test -run=^$ -bench=. ./internal/parser/
   ```

5. Run linting:

   ```bash
   golangci-lint run
   ```

### Validation Development

When working on configuration validation:

- Follow the patterns established in `internal/config/validator.go`
- Add comprehensive test cases covering both valid and invalid inputs
- Use the `ValidationError` type for reporting validation issues
- Include field paths and descriptive error messages
- See [Validator Patterns](../DEVELOPMENT_STANDARDS.md#validator-patterns) for detailed guidance

### Parser Development

When modifying XML parsing logic:

- Maintain streaming behavior to handle large files efficiently
- Ensure memory usage remains constant (O(1)) as file size increases
- Add benchmarks for performance-critical changes
- Test with both small sample files and large generated XML
- Preserve backward compatibility in the `Parser` interface

### Testing

We maintain several types of tests:

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test complete workflows end-to-end
- **Validation tests**: Comprehensive coverage of validation rules
- **Performance tests**: Benchmarks for parser memory and speed
- **Error handling tests**: Verify proper error reporting

Run specific test suites:

```bash
# All tests
go test ./...

# Specific package
go test ./internal/config/

# Benchmarks only
go test -run=^$ -bench=. ./internal/parser/

# With coverage
go test -cover ./...
```

## Pull Request Process

1. **Before submitting**:
   - Ensure all tests pass
   - Run linting tools
   - Update documentation if needed
   - Add changelog entry if appropriate

2. **PR Description**:
   - Clearly describe what changes were made
   - Reference any related issues
   - Include examples of new functionality
   - Note any breaking changes

3. **Review process**:
   - All PRs require at least one review
   - CI must pass (tests, linting, benchmarks)
   - Documentation updates may be requested

## Coding Standards

Please follow our [Development Standards](../DEVELOPMENT_STANDARDS.md) which cover:

- Go coding conventions
- Error handling patterns
- Validation architecture
- Testing practices
- Performance guidelines

## Documentation

- Update relevant documentation for user-facing changes
- Add inline comments for complex logic
- Update API documentation for interface changes
- Follow MkDocs formatting for documentation updates

## Performance Considerations

This project processes potentially large XML files, so performance matters:

- Profile memory usage for parser changes
- Maintain streaming behavior rather than loading entire files
- Add benchmarks for significant algorithmic changes
- Consider memory allocation patterns

## Getting Help

- Check existing issues and documentation first
- Open an issue for bugs or feature requests
- Ask questions in GitHub discussions
- Review the development standards and architecture documentation

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

Thank you for contributing to making OPNsense configuration processing better!
