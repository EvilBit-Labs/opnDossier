## applyTo: '.github/copilot\*'

# opnDossier AI Coding Agent Instructions

## Project Architecture & Data Flow

- **Monolithic Go CLI**: Converts OPNsense `config.xml` to Markdown, JSON, or YAML. No external network calls—offline-first.
- **Major Components**:
  - `cmd/`: CLI entrypoints (`convert`, `display`, `validate`). See `cmd/root.go` for command registration.
  - `internal/parser/`: XML parsing to Go structs (`OpnSenseDocument` in `internal/model/opnsense.go`).
  - `internal/model/`: Strict data models mirroring OPNsense config structure.
  - `internal/processor/`: Normalization, validation, analysis, and transformation pipeline.
  - `internal/converter/`, `internal/markdown/`: Multi-format export (Markdown, JSON, YAML) using templates and options.
  - `internal/audit/`, `internal/plugin/`, `internal/plugins/`: Compliance audit engine and plugin system (STIG, SANS, firewall).
  - `internal/display/`, `internal/log/`: Terminal output and structured logging.

**Data Flow**:
`parser` → `model` → `processor` → `converter`/`markdown` → `export`
Audit overlays: `processor` → `audit` → `plugins`

## Critical Workflows

- **All development tasks use `just`** (see `justfile`):
  - `just install` – install dependencies
  - `just build` – build binary
  - `just test` – run all tests
  - `just lint` – run golangci-lint
  - `just ci-check` – run full CI-equivalent checks (must pass before reporting success)
- **No external dependencies**: All code must run fully offline.
- **Never commit code without explicit user permission.**

## Project-Specific Conventions

- **Rule Precedence**: See [AGENTS.md](../AGENTS.md) for canonical rule precedence and always defer to the project root for authoritative standards.
- **Error Handling**: Always wrap errors with context using `fmt.Errorf("context: %w", err)`.
- **Logging**: Use `charmbracelet/log` for all logging; include context fields (e.g., filename, operation).
- **Config Management**: Use `internal/config` and `spf13/viper` for CLI/app config (not for OPNsense XML).
- **Data Models**: All OPNsense config data must use `internal/model` structs with strict XML/JSON/YAML tags.
- **Testing**: Table-driven tests, >80% coverage, use `testdata/` for fixtures.
- **Commit Messages**: Must follow Conventional Commits (`<type>(<scope>): <description>`, e.g., `fix(parser): handle comma-separated interfaces`).

## Integration & Plugin Patterns

- **Audit Plugins**: Implement `CompliancePlugin` interface (`internal/plugin/interfaces.go`). Register in `internal/audit/plugin_manager.go`.
- **Plugin Structure**: Place in `internal/plugins/{standard}/`. Use generic `Finding` struct—no compliance-specific fields.
- **Multi-Format Export**: Add new formats in `internal/converter/` and templates in `internal/templates/`.

## Key Files & References

- `AGENTS.md`, `DEVELOPMENT_STANDARDS.md`, `ARCHITECTURE.md`, `project_spec/requirements.md`
- `cmd/convert.go`, `internal/model/opnsense.go`, `internal/parser/xml.go`, `internal/processor/README.md`

## Example Patterns

**CLI Command**:

```go
var convertCmd = &cobra.Command{
    Use:   "convert [file]",
    Short: "Convert OPNsense config to multiple formats",
    RunE:  runConvert,
}
```

**Plugin Interface**:

```go
type CompliancePlugin interface {
    Name() string
    RunChecks(config *model.OpnSenseDocument) []Finding
    // ...
}
```

## AI Agent Checklist

- [ ] Use `just` for all dev tasks
- [ ] Run `just ci-check` before reporting success
- [ ] Follow established code/data patterns
- [ ] Never add external dependencies
- [ ] Reference and update documentation as needed

For details, see `AGENTS.md` and `DEVELOPMENT_STANDARDS.md`.
