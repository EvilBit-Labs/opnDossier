---
applyTo: '**'
---

# Project Structure Guidelines

## Core Project Files

### Security-Focused Build Configuration

To support secure and reproducible operator distribution, follow these build practices:

- **Reproducible Builds:** Use pinned dependencies (`go.mod`, `go.sum`) and deterministic build flags.
- **Go Build Hardening:**
  - Use `-trimpath` to remove local paths from binaries: `go build -trimpath ...`
  - Use `-buildmode=pie` for position-independent executables (where supported).
  - Set `GOVERSION` and `CGO_ENABLED=0` for static, portable builds: `CGO_ENABLED=0 go build ...`
  - Use `-ldflags="-s -w"` to strip debug info from release binaries.
- **Build Integrity:**
  - Use `go mod verify` to check dependency integrity.
  - Use checksums and signatures for release artifacts.
  - Integrate tools like `goreleaser` for automated, signed, and reproducible releases.

**Example secure build command:**

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o opnDossier ./main.go
```

**Recommended tools:**

- [goreleaser](https://goreleaser.com/) for reproducible, signed releases
- [cosign](https://github.com/sigstore/cosign) for artifact signing (optional, if supply chain security is required)

---

### Configuration and Build

```text
opnDossier/
├── go.mod                    # Go module definition and dependencies
├── go.sum                    # Dependency checksums
├── justfile                  # Task runner for development commands
└── main.go                   # Application entry point
```

### Documentation

```text
opnDossier/
├── README.md                 # Project overview and quick start
├── AGENTS.md                 # Development standards and AI agent protocols
├── ARCHITECTURE.md           # System architecture documentation
├── DEVELOPMENT_STANDARDS.md  # Coding standards and practices
└── docs/                     # Comprehensive documentation directory
```

### Project Specification

```text
opnDossier/
└── project_spec/
    ├── requirements.md       # Detailed requirements specification
    ├── tasks.md              # Implementation task checklist
    └── user_stories.md       # User stories and use cases
```

## Directory Structure

### Source Code Organization

```text
opndossier/
├── cmd/
│   ├── convert.go                         # Convert command entry point
│   ├── display.go                         # Display command entry point
│   ├── validate.go                        # Validate command entry point
│   └── root.go                            # Root command and main entry point
├── internal/                              # Private application logic and business rules
├── pkg/                                   # Public packages (if any)
├── testdata/                              # Test data and fixtures
└── docs/                                  # Documentation
```

### Internal Package Structure

```text
opnDossier/internal/
├── audit/                    # Audit engine and compliance checking
│   ├── plugin.go             # Plugin registry and compliance logic
│   └── plugin_manager.go     # Plugin lifecycle management
├── config/                   # Configuration management
├── converter/                # Data conversion utilities
├── display/                  # Terminal display and formatting
├── export/                   # File export functionality
├── log/                      # Logging utilities
├── markdown/                 # Markdown generation
├── model/                    # Data models and structures
├── parser/                   # XML parsing and validation
├── plugin/                   # Plugin interfaces and errors
├── plugins/                  # Compliance plugins
│   ├── firewall/             # Firewall compliance plugin
│   ├── sans/                 # SANS compliance plugin
│   └── stig/                 # STIG compliance plugin
├── processor/                # Data processing and analysis
├── templates/                # Template files for output generation
├── validator/                # Data validation
├── constants/                # Application constants
└── walker.go                 # File system walker utilities
```

## Development Workflow

### Task Management

- Use `just` commands for development tasks
- Follow the task checklist in `project_spec/tasks.md`
- Update task status as work progresses
- Reference requirements in `project_spec/requirements.md`

### Quality Assurance

- Run `just ci-check` before committing
- Ensure all tests pass with `just test`
- Maintain >80% test coverage
- Follow linting standards with `golangci-lint`

### Documentation Updates

- Update relevant documentation when making changes
- Keep `README.md` current with installation and usage
- Update `docs/` directory for new features
- Maintain consistency across all documentation files
