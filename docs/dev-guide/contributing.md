# Contributing Guide

Thank you for your interest in contributing to opnFocus! This guide covers everything you need to know to contribute effectively.

## Getting Started

### Prerequisites

- **Go 1.21+** - Latest stable version recommended
- **Just** - Task runner for development workflows
- **Git** - Version control
- **golangci-lint** - Linting tool

### Development Setup

```bash
# Clone the repository
git clone https://github.com/unclesp1d3r/opnFocus.git
cd opnFocus

# Install development dependencies
just install-dev

# Verify setup
just check

# Run tests
just test
```

## Architecture Overview

opnFocus uses a layered CLI architecture:

- **Cobra**: Command structure & argument parsing
- **Viper**: Layered configuration (files, env, flags)
- **Fang**: Enhanced UX layer (styled help, completion)
- **charmbracelet/log**: Structured, leveled logging
- **Lipgloss**: Styled terminal output formatting
- **Glamour**: Markdown rendering in terminal

### Project Structure

```
opnfocus/
├── cmd/                 # CLI commands (Cobra)
├── internal/
│   ├── config/         # Configuration management (Viper)
│   ├── parser/         # XML parsing logic
│   ├── converter/      # Data conversion logic
│   ├── display/        # Output formatting (Lipgloss)
│   ├── export/         # File export logic
│   └── log/            # Logging utilities
├── docs/               # Documentation
└── tests/              # Test files
```

## Development Workflow

### 1. Create a Feature Branch

```bash
# Create and switch to a new branch
git checkout -b feat/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 2. Development Commands

```bash
# Run during development
just dev           # Run in development mode
just test          # Run tests
just lint          # Run linters
just check         # Run all pre-commit checks

# Build and test
just build         # Build the application
just install       # Install locally
```

### 3. Code Quality Standards

All code must pass these checks:

```bash
# Linting (must pass)
just lint

# Tests (>80% coverage required)
just test

# All pre-commit checks
just check
```

### 4. Commit Standards

We use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Feature commits
git commit -m \"feat(parser): add support for new XML schema\"

# Bug fixes  
git commit -m \"fix(config): resolve environment variable precedence\"

# Documentation
git commit -m \"docs(readme): update configuration examples\"

# Breaking changes
git commit -m \"feat(api)!: change configuration file format\"
```

**Commit Types:**

- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code formatting
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions/changes
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Maintenance tasks

## Coding Standards

### Go Style Guide

Follow the [Google Go Style Guide](https://google.github.io/styleguide/go/) and project conventions:

```go
// Package documentation is required
// Package cmd provides the command-line interface for opnFocus.
package cmd

import (
    // Standard library first
    \"context\"
    \"fmt\"
    
    // Third-party packages
    \"github.com/spf13/cobra\"
    
    // Local packages last
    \"github.com/unclesp1d3r/opnFocus/internal/config\"
)

// Function documentation required for exported functions
// LoadConfig loads application configuration from multiple sources
// with proper precedence handling.
func LoadConfig(cfgFile string) (*Config, error) {
    // Implementation
}
```

### Error Handling

Use proper error wrapping and context:

```go
// Good: Wrap errors with context
func processFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf(\"failed to open file %s: %w\", path, err)
    }
    defer file.Close()
    
    // Process file...
    if err := someOperation(); err != nil {
        return fmt.Errorf(\"failed to process file %s: %w\", path, err)
    }
    
    return nil
}

// Bad: Don't use log.Fatal or panic in library code
func badExample() {
    log.Fatal(\"This terminates the program\") // Never do this
}
```

### Logging Standards

Use structured logging with charmbracelet/log:

```go
// Good: Structured logging with context
logger := log.New(log.Config{
    Level:  \"info\",
    Format: \"text\",
})

logger.Info(\"Starting conversion\", \"input_file\", inputPath)
logger.Debug(\"Processing section\", \"section\", sectionName, \"count\", itemCount)

// With context
ctxLogger := logger.WithContext(ctx).WithFields(\"operation\", \"convert\")
ctxLogger.Error(\"Conversion failed\", \"error\", err)
```

### Testing Standards

Write comprehensive tests with >80% coverage:

```go
func TestConfigLoad(t *testing.T) {
    tests := []struct {
        name        string
        configFile  string
        envVars     map[string]string
        want        *Config
        wantErr     bool
    }{
        {
            name:       \"default config\",
            configFile: \"\",
            envVars:    nil,
            want:       &Config{LogLevel: \"info\"},
            wantErr:    false,
        },
        {
            name:       \"env var override\",
            configFile: \"\",
            envVars:    map[string]string{\"OPNFOCUS_LOG_LEVEL\": \"debug\"},
            want:       &Config{LogLevel: \"debug\"},
            wantErr:    false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Set up environment
            for k, v := range tt.envVars {
                t.Setenv(k, v)
            }
            
            got, err := LoadConfig(tt.configFile)
            if (err != nil) != tt.wantErr {
                t.Errorf(\"LoadConfig() error = %v, wantErr %v\", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf(\"LoadConfig() = %v, want %v\", got, tt.want)
            }
        })
    }
}
```

## Configuration Management

### Understanding the Stack

The configuration system uses **Viper** for layered configuration management:

1. **CLI flags** (highest priority) - Cobra integration
2. **Environment variables** (`OPNFOCUS_*`) - Viper handling
3. **Configuration file** (`~/.opnFocus.yaml`) - Viper loading
4. **Default values** (lowest priority) - Viper defaults

### Adding New Configuration Options

1. **Add to Config struct:**

```go
// internal/config/config.go
type Config struct {
    // Existing fields...
    NewOption string `mapstructure:\"new_option\"`
}
```

2. **Set default value:**

```go
func LoadConfigWithViper(cfgFile string, v *viper.Viper) (*Config, error) {
    // Existing defaults...
    v.SetDefault(\"new_option\", \"default_value\")
    // ...
}
```

3. **Add CLI flag:**

```go
// cmd/root.go
func init() {
    // Existing flags...
    rootCmd.PersistentFlags().String(\"new_option\", \"default_value\", \"Description of new option\")
}
```

4. **Add validation:**

```go
func (c *Config) Validate() error {
    // Existing validation...
    if c.NewOption == \"\" {
        validationErrors = append(validationErrors, ValidationError{
            Field:   \"new_option\",
            Message: \"new_option cannot be empty\",
        })
    }
    // ...
}
```

5. **Update documentation:**

- Add to README examples
- Update `docs/user-guide/configuration.md`
- Add to CLI help text

## CLI Enhancement with Fang

### Understanding Fang's Role

**Fang** provides enhanced UX features on top of Cobra:

- Styled help and error messages
- Automatic `--version` flag
- Shell completion commands
- Improved terminal formatting

### Adding New Commands

```go
// cmd/newcommand.go
var newCmd = &cobra.Command{
    Use:   \"new [args]\",
    Short: \"Brief description\",
    Long: `Detailed description with configuration info:
    
CONFIGURATION:
  This command respects the global configuration precedence:
  CLI flags > environment variables (OPNFOCUS_*) > config file > defaults`,
    
    RunE: func(cmd *cobra.Command, args []string) error {
        // Get config and logger from root command
        cfg := GetConfig()
        logger := GetLogger()
        
        // Implementation...
        return nil
    },
}

func init() {
    rootCmd.AddCommand(newCmd)
    newCmd.Flags().String(\"option\", \"default\", \"Option description\")
}
```

## Testing

### Test Categories

1. **Unit Tests** - Test individual functions
2. **Integration Tests** - Test component interactions
3. **CLI Tests** - Test command-line interface

### Running Tests

```bash
# All tests
just test

# Specific package
go test ./internal/config

# With coverage
go test -cover ./...

# Race detection
go test -race ./...

# Verbose output
go test -v ./...
```

### Test File Organization

```
internal/config/
├── config.go
├── config_test.go          # Unit tests
└── testdata/
    ├── valid-config.yaml
    └── invalid-config.yaml

cmd/
├── convert.go
├── convert_test.go         # CLI tests
└── testdata/
    └── sample-config.xml
```

## Documentation

### Documentation Standards

1. **Code Documentation** - GoDoc comments for all exported functions
2. **User Documentation** - Markdown files in `docs/`
3. **CLI Help** - Detailed help text in commands
4. **Examples** - Working examples in documentation

### Updating Documentation

When adding features:

1. Update relevant `docs/` files
2. Update CLI help text
3. Add examples to README
4. Update configuration documentation

## Pull Request Process

### Before Submitting

1. **Run all checks:**

   ```bash
   just check  # Must pass all checks
   ```

2. **Update documentation:**

   - Code comments
   - User guides if needed
   - CLI help text

3. **Add tests:**

   - Unit tests for new functions
   - Integration tests for new features
   - CLI tests for new commands

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Configuration Changes
- [ ] New configuration options documented
- [ ] CLI help updated
- [ ] Examples provided

## Checklist
- [ ] Code follows project standards
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Review Process

1. **Automated Checks** - All CI checks must pass
2. **Code Review** - At least one maintainer review
3. **Testing** - Ensure comprehensive test coverage
4. **Documentation** - Verify docs are updated

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- `MAJOR.MINOR.PATCH`
- Breaking changes increment MAJOR
- New features increment MINOR
- Bug fixes increment PATCH

### Release Checklist

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create release PR
4. Tag release after merge
5. GoReleaser handles the rest

## Getting Help

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and general discussion
- **Code Reviews** - Technical discussions

### Issue Templates

Use appropriate issue templates:

- Bug Report
- Feature Request
- Documentation Issue
- Question

### Development Questions

For development questions:

1. Check existing documentation
2. Search existing issues
3. Ask in GitHub Discussions
4. Create an issue if needed

---

Thank you for contributing to opnFocus! Your contributions help make network configuration management better for everyone.
