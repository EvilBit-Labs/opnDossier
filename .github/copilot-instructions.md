# CoPilot Instructions for opnDossier

## AI Assistant Guidelines

**CRITICAL**: When contributing to this project, always:

1. Follow the established patterns in existing code
2. Use `just` commands for all development tasks
3. Run `just ci-check` before reporting success
4. Reference `AGENTS.md` and `DEVELOPMENT_STANDARDS.md` for detailed standards
5. Maintain offline-first architecture (no external dependencies)

## Project Overview

opnDossier is a Go-based CLI tool for processing OPNsense firewall configurations. It converts XML config files to Markdown/JSON/YAML with audit capabilities. Built for operators with offline-first design.

## Code Organization Patterns

### Directory Structure

```text
cmd/                    # CLI entry points (convert, display, validate)
internal/
├── audit/             # Compliance checking and audit engine
├── config/            # Configuration management with env vars
├── converter/         # Multi-format conversion (MD/JSON/YAML)
├── display/           # Terminal output with themes
├── export/            # File export with overwrite protection
├── log/               # Structured logging
├── markdown/          # Markdown generation with templates
├── model/             # OPNsense data models
├── parser/            # XML parsing and validation
├── plugin/            # Plugin interfaces
├── plugins/           # Compliance plugins (stig, sans, firewall)
├── processor/         # Data processing and analysis
├── templates/         # Markdown templates
├── validator/         # Configuration validation
└── walker.go          # File system utilities
```

### Key Patterns to Follow

**Error Handling**: Always use `fmt.Errorf` with context

```go
return fmt.Errorf("failed to parse config: %w", err)
```

**Logging**: Use `charmbracelet/log` for structured logging

```go
logger := log.New(os.Stderr, "", log.LstdFlags)
logger.Info("processing config file", "filename", filename)
```

**Configuration**: Use `internal/config` for all settings

```go
cfg := config.GetConfig()
```

**Data Models**: Use `internal/model` structs for OPNsense data

```go
doc := &model.OpnSenseDocument{}
```

## Development Commands

**ALWAYS use these commands:**

```bash
just install      # Setup environment
just build        # Build application
just test         # Run tests
just format       # Format code
just lint         # Run linting
just ci-check     # Full validation
just coverage     # Run with coverage
just bench        # Run benchmarks
```

## CLI Command Patterns

### Convert Command Structure

```go
// Always follow this pattern for new commands
var convertCmd = &cobra.Command{
    Use:   "convert [file]",
    Short: "Convert OPNsense config to markdown",
    Long:  `Detailed description...`,
    Args:  cobra.ExactArgs(1),
    RunE:  runConvert,
}
```

### Flag Patterns

```go
// Output flags
convertCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
convertCmd.Flags().StringVarP(&format, "format", "f", "markdown", "Output format")

// Template flags
convertCmd.Flags().StringVar(&templateName, "template", "", "Template name")
convertCmd.Flags().StringSliceVar(&sections, "section", []string{}, "Sections to include")

// Audit flags
convertCmd.Flags().StringVar(&auditMode, "mode", "", "Audit mode")
convertCmd.Flags().StringSliceVar(&selectedPlugins, "plugins", []string{}, "Compliance plugins")
```

## Data Processing Patterns

### XML Parsing Flow

1. Use `internal/parser` for XML parsing
2. Convert to `internal/model` structs
3. Process with `internal/processor`
4. Convert to output format with `internal/converter`

### Template Usage

```go
// Use internal/templates for markdown generation
opts := markdown.Options{
    Template: templateName,
    Theme:    themeName,
    Wrap:     wrapWidth,
}
```

### Audit Integration

```go
// Use internal/audit for compliance checking
registry := audit.NewPluginRegistry()
report := registry.RunAudit(ctx, config, mode)
```

## Testing Patterns

**ALWAYS write tests for new functionality:**

```go
func TestParseXMLConfig(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *Config
        wantErr  bool
    }{
        {
            name:     "valid config",
            input:    `<config><system><hostname>test</hostname></system></config>`,
            expected: &Config{System: System{Hostname: "test"}},
            wantErr:  false,
        },
        {
            name:     "invalid XML",
            input:    `<config><unclosed>`,
            expected: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := parseXMLConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("parseXMLConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("parseXMLConfig() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

## Error Patterns

**Use these error types from internal packages:**

```go
import "github.com/EvilBit-Labs/opnDossier/internal/parser"
import "github.com/EvilBit-Labs/opnDossier/internal/plugin"

// Common error patterns
if err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

## Security Requirements

**NEVER do these:**

- Hardcode secrets or API keys
- Use external HTTP calls
- Store sensitive data in code
- Skip input validation

**ALWAYS do these:**

- Use environment variables with `OPNFOCUS_` prefix for config
- Validate and sanitize XML input files
- Use secure defaults
- Handle errors gracefully with context
- Include context in log messages (filename, operation, duration)
- Use appropriate log levels (debug, info, warn, error)

## Integration Points

### Component Communication

```text
parser → model → processor → converter → export
                ↓
            audit → plugins
                ↓
            templates → markdown
```

### Key Interfaces

- `internal/plugin.Plugin` for compliance plugins
- `internal/model.OpnSenseDocument` for data
- `internal/config.Config` for settings
- `charmbracelet/log.Logger` for logging

## Common Tasks

### Adding New Command

1. Create file in `cmd/`
2. Follow existing command patterns
3. Add to `root.go` init()
4. Write comprehensive tests
5. Update documentation

### Adding New Format

1. Add converter in `internal/converter/`
2. Add template in `internal/templates/`
3. Update command flags
4. Add tests
5. Update documentation

### Adding New Plugin

1. Implement `internal/plugin.Plugin` interface
2. Add to `internal/plugins/`
3. Register in `internal/audit/`
4. Add tests
5. Update documentation

## Quality Checklist

**Before submitting code:**

- [ ] Code follows Go formatting (`gofmt`)
- [ ] All linting issues resolved (`golangci-lint`)
- [ ] Tests pass (`go test ./...`)
- [ ] Test coverage >80%
- [ ] Error handling includes context with `fmt.Errorf`
- [ ] Logging uses `charmbracelet/log` with structured fields
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Documentation updated
- [ ] Dependencies managed (`go mod tidy`)

## Key Files to Reference

- `AGENTS.md` - Detailed development standards
- `DEVELOPMENT_STANDARDS.md` - Go-specific conventions
- `ARCHITECTURE.md` - System design
- `project_spec/requirements.md` - Complete requirements
- `project_spec/tasks.md` - Implementation tasks
- `internal/model/opnsense.go` - Core data models
- `cmd/convert.go` - Main command implementation
- `internal/parser/xml.go` - XML parsing logic

## AI-Specific Guidelines

**When making changes:**

1. **Survey first**: Review existing code for patterns
2. **Match style**: Follow established naming and structure
3. **Test thoroughly**: Write tests for all new functionality
4. **Document changes**: Update relevant documentation
5. **Validate**: Run `just ci-check` before reporting success

**When unsure:**

1. Check `AGENTS.md` for detailed standards
2. Review similar implementations in the codebase
3. Follow the established patterns exactly
4. Ask for clarification if patterns are unclear

---

**Remember**: This project prioritizes offline operation, structured data, and operator-focused workflows. Always maintain these principles in your contributions.
