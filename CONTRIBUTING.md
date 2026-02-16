# Contributing Guide

Thank you for your interest in contributing to opnDossier! This guide covers everything you need to know to contribute effectively.

## Getting Started

### Quality Standards

opnDossier follows strict coding standards and development practices:

- All code must pass `golangci-lint`
- Tests required for new functionality (>80% coverage)
- Documentation updates for user-facing changes
- Follow Go best practices and project conventions
- All pre-commit checks must pass before submitting PR

### Prerequisites

- **Go 1.21+** - Latest stable version recommended
- **Just** - Task runner for development workflows
- **Git** - Version control
- **golangci-lint** - Linting tool

### Development Setup

```bash
# Clone the repository
git clone https://github.com/EvilBit-Labs/opnDossier.git
cd opnDossier

# Install development dependencies
just install-dev

# Verify setup
just check

# Run tests
just test
```

## Architecture Overview

opnDossier uses a layered CLI architecture:

- **Cobra**: Command structure & argument parsing
- **Viper**: Layered configuration (files, env, flags)
- **Fang**: Enhanced UX layer (styled help, completion)
- **charmbracelet/log**: Structured, leveled logging
- **Lipgloss**: Styled terminal output formatting
- **Glamour**: Markdown rendering in terminal

### Project Structure

```text
opndossier/
├── cmd/                 # CLI commands (Cobra)
├── internal/
│   ├── config/         # Configuration management (Viper)
│   ├── parser/         # XML parsing logic
│   ├── converter/      # Data conversion logic
│   ├── markdown/       # Markdown generation
│   ├── display/        # Terminal display (Lipgloss)
│   ├── log/           # Logging utilities
│   └── model/         # Data structures
├── docs/              # Documentation
└── testdata/          # Test files
```

### Programmatic Generation Architecture (v2.0+)

opnDossier v2.0 introduces programmatic markdown generation, replacing the template-based approach with direct Go method calls. This architecture delivers significant performance improvements and enhanced developer experience.

#### Key Components

**MarkdownBuilder Interface**

```go
// ReportBuilder interface for programmatic generation
type ReportBuilder interface {
    BuildStandardReport(data *model.OpnSenseDocument) (string, error)
    BuildCustomReport(data *model.OpnSenseDocument, options BuildOptions) (string, error)

    // Section builders
    BuildSystemSection(data *model.OpnSenseDocument) string
    BuildNetworkSection(data *model.OpnSenseDocument) string
    BuildSecuritySection(data *model.OpnSenseDocument) string
    BuildServicesSection(data *model.OpnSenseDocument) string

    // Component builders
    BuildFirewallRulesTable(rules []model.Rule) *markdown.TableSet
    BuildInterfaceTable(interfaces model.Interfaces) *markdown.TableSet
}
```

**Performance-Optimized Methods**

- **Security Assessment**: `CalculateSecurityScore`, `AssessRiskLevel`, `AssessServiceRisk`
- **Data Transformation**: `FilterSystemTunables`, `GroupServicesByStatus`, `FormatSystemStats`
- **String Utilities**: `EscapeMarkdownSpecialChars`, `FormatTimestamp`, `TruncateDescription`

#### Development Guidelines for New Methods

1. **Method Naming**: Use descriptive names that indicate functionality

   ```go
   // Good
   func (b *MarkdownBuilder) FilterSystemTunables(tunables []model.SysctlItem, securityOnly bool) []model.SysctlItem

   // Avoid
   func (b *MarkdownBuilder) Filter(items []any, flag bool) []any
   ```

2. **Error Handling**: Return explicit errors with context

   ```go
   func (b *MarkdownBuilder) BuildSection(data *model.OpnSenseDocument) (string, error) {
       if data == nil {
           return "", fmt.Errorf("configuration data cannot be nil")
       }

       // Implementation...
       if err := someOperation(); err != nil {
           return "", fmt.Errorf("failed to build section: %w", err)
       }

       return result, nil
   }
   ```

3. **Performance Optimization**: Use pre-allocated slices and efficient string building

   ```go
   func (b *MarkdownBuilder) ProcessLargeDataset(items []model.Item) []ProcessedItem {
       // Pre-allocate with estimated capacity
       result := make([]ProcessedItem, 0, len(items))

       // Use strings.Builder for efficient string concatenation
       var builder strings.Builder
       builder.Grow(1024) // Pre-allocate capacity

       // Process items...
       return result
   }
   ```

4. **Type Safety**: Use specific types rather than `any` or `interface{}`

   ```go
   // Good
   func (b *MarkdownBuilder) FormatServices(services []model.Service) string

   // Avoid
   func (b *MarkdownBuilder) FormatItems(items any) string
   ```

#### Testing Programmatic Generation

**Unit Tests for Methods**

```go
func TestMarkdownBuilder_FilterSystemTunables(t *testing.T) {
    tests := []struct {
        name         string
        tunables     []model.SysctlItem
        securityOnly bool
        expected     int
    }{
        {
            name: "filter security tunables",
            tunables: []model.SysctlItem{
                {Tunable: "security.test", Value: "1"},
                {Tunable: "net.other", Value: "0"},
            },
            securityOnly: true,
            expected:     1,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            builder := converter.NewMarkdownBuilder()
            result := builder.FilterSystemTunables(tt.tunables, tt.securityOnly)
            assert.Len(t, result, tt.expected)
        })
    }
}
```

**Performance Benchmarks**

```go
func BenchmarkMarkdownBuilder_CalculateSecurityScore(b *testing.B) {
    builder := converter.NewMarkdownBuilder()
    config := loadTestConfig()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = builder.CalculateSecurityScore(config)
    }
}
```

**Integration Tests**

```go
func TestMarkdownBuilder_BuildStandardReport(t *testing.T) {
    // Load test configuration
    config := loadTestConfig("testdata/sample-config.xml")

    // Generate report
    builder := converter.NewMarkdownBuilder()
    report, err := builder.BuildStandardReport(config)

    // Validate results
    require.NoError(t, err)
    assert.Contains(t, report, "# OPNsense Configuration")
    assert.Contains(t, report, "## System Information")

    // Validate markdown syntax
    err = validateMarkdownSyntax(report)
    assert.NoError(t, err)
}
```

### Template to Programmatic Migration

When migrating template functions to Go methods:

1. **Analyze Template Function**: Understand input parameters and expected output
2. **Create Go Method**: Implement with proper types and error handling
3. **Add Unit Tests**: Test various input scenarios and edge cases
4. **Benchmark Performance**: Ensure performance meets expectations
5. **Update Documentation**: Add method to API documentation

**Example Migration:**

```go
// Template function (old)
{{ define "formatUptime" }}{{ div .Seconds 3600 }} hours{{ end }}

// Go method (new)
func (b *MarkdownBuilder) FormatUptime(seconds int) string {
    hours := seconds / 3600
    return fmt.Sprintf("%d hours", hours)
}
```

## Project Structure

```text
opndossier/
│ ├── display/ # Output formatting (Lipgloss)
│ ├── export/ # File export logic
│ └── log/ # Logging utilities
├── docs/ # Documentation
└── tests/ # Test files
```

## Development Workflow

### 1. Create a Feature Branch

```bash
# Create and switch to a new branch
git checkout -b feat/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### Security Scanning

opnDossier treats vulnerability management as a first-class workflow concern.

- **Run scans locally**:
  - `just scan` - run vulnerability scanning
  - `just sbom` - generate SBOM artifacts
- **CI requirements**:
  - CI runs Grype scans for both the repository filesystem and Go module dependencies (`go.mod`).
  - Severity thresholds are stricter on `main` (filesystem cutoff is $\\ge$ medium) than on feature branches (filesystem cutoff is $\\ge$ high).
- **Where results live**:
  - SARIF uploads appear in the GitHub Security tab (Code Scanning).
  - SBOM and vulnerability report artifacts are attached to workflow runs.

### 2. Development Commands

This project follows comprehensive development standards and uses modern Go tooling:

```bash
# Development workflow using Just
just test      # Run tests
just lint      # Run linters
just check     # Run all pre-commit checks
just ci-check  # Run comprehensive CI checks
just dev       # Run in development mode
just docs      # Serve documentation locally

# Build and test
just build     # Build the application
just install   # Install locally
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
git commit -m "feat(parser): add support for new XML schema"

# Bug fixes
git commit -m "fix(config): resolve environment variable precedence"

# Documentation
git commit -m "docs(readme): update configuration examples"

# Breaking changes
git commit -m "feat(api)!: change configuration file format"
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
// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
    // Standard library first
    "context"
    "fmt"

    // Third-party packages
    "github.com/spf13/cobra"

    // Local packages last
    "github.com/EvilBit-Labs/opnDossier/internal/config"
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
        return fmt.Errorf("failed to open file %s: %w", path, err)
    }
    defer file.Close()

    // Process file...
    if err := someOperation(); err != nil {
        return fmt.Errorf("failed to process file %s: %w", path, err)
    }

    return nil
}

// Bad: Don't use log.Fatal or panic in library code
func badExample() {
    log.Fatal("This terminates the program") // Never do this
}
```

### Logging Standards

Use structured logging with charmbracelet/log:

```go
// Good: Structured logging with context
logger := log.New()

logger.Info("Starting conversion", "input_file", inputPath)
logger.Debug("Processing section", "section", sectionName, "count", itemCount)

// With fields for additional context
ctxLogger := logger.With("operation", "convert")
ctxLogger.Error("Conversion failed", "error", err)
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
            name:       "default config",
            configFile: "",
            envVars:    nil,
            want:       &Config{LogLevel: "info"},
            wantErr:    false,
        },
        {
            name:       "env var override",
            configFile: "",
            envVars:    map[string]string{"OPNDOSSIER_VERBOSE": "true"},
            want:       &Config{Verbose: true},
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
                t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("LoadConfig() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

## Configuration Management

### Understanding the Stack

The configuration system uses **Viper** for layered configuration management:

1. **CLI flags** (highest priority) - Cobra integration
2. **Environment variables** (`OPNDOSSIER_*`) - Viper handling
3. **Configuration file** (`~/.opnDossier.yaml`) - Viper loading
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
    v.SetDefault("new_option", "default_value")
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
    if c.NewOption == "" {
        validationErrors = append(validationErrors, ValidationError{
            Field:   "new_option",
            Message: "new_option cannot be empty",
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
    Use:   "new [args]",
    Short: "Brief description",
    Long: `Detailed description with configuration info:

CONFIGURATION:
  This command respects the global configuration precedence:
  CLI flags > environment variables (OPNDOSSIER_*) > config file > defaults`,

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

```text
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
- [ ] Breaking change (fix or feature that would cause existing functionality to
      change)
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

## Developer Certificate of Origin (DCO)

This project requires all contributors to sign off on their commits, certifying that they have the right to submit the code under the project's license. This is enforced by the [DCO GitHub App](https://github.com/apps/dco).

To sign off, add `-s` to your commit command:

```bash
git commit -s -m "feat(parser): add new feature"
```

This adds a `Signed-off-by` line to your commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

By signing off, you agree to the [Developer Certificate of Origin](https://developercertificate.org/).

## Project Governance

### Decision-Making

opnDossier uses a **maintainer-driven** governance model. Decisions are made by the project maintainers through consensus on GitHub issues and pull requests. Community input is welcomed and encouraged on all significant changes.

### Roles

| Role                 | Responsibilities                                                                          | Current                                        |
| -------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Maintainer**       | Merge PRs, manage releases, set project direction, review security reports, triage issues | [@UncleSp1d3r](https://github.com/UncleSp1d3r) |
| **Security Contact** | Triage vulnerability reports, coordinate fixes, publish advisories                        | support@evilbitlabs.io                         |
| **Contributor**      | Submit issues, PRs, and participate in discussions                                        | Anyone following this guide                    |

### How Decisions Are Made

- **Bug fixes and minor changes**: Any maintainer can review and merge
- **New features**: Discussed in a GitHub issue before implementation; maintainer approval required
- **Architecture changes**: Require maintainer approval with rationale documented in the PR description
- **Breaking changes**: Discussed in a GitHub issue with community input; maintainer approval required
- **Releases**: Prepared by any maintainer following the [release process](#release-process); GoReleaser handles automation

### Becoming a Maintainer

As the project grows, active contributors who demonstrate sustained, high-quality contributions and alignment with project goals may be invited to become maintainers. Criteria include:

- Consistent, high-quality PRs over a sustained period
- Understanding of the project's architecture and security model
- Alignment with the project's core philosophy (operator-focused, offline-first, structured data)

### Continuity Plan

To ensure the project can continue operating if any key person becomes unavailable:

- The GitHub organization (EvilBit-Labs) has multiple administrators
- CI/CD pipelines (GoReleaser, GitHub Actions) are fully automated and documented
- All development standards, architecture decisions, and processes are documented in AGENTS.md, CONTRIBUTING.md, and docs/
- Security response procedures are documented in SECURITY.md with alternative contact methods
- Release signing uses Sigstore keyless signatures (no personal keys required)

---

Thank you for contributing to opnDossier! Your contributions help make network configuration management better for everyone.
