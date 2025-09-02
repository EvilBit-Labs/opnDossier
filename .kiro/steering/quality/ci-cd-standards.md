---
inclusion: always
---

# CI/CD Pipeline Standards for opnDossier

## Pipeline Quality Gates

### Pre-Merge Requirements

**MANDATORY**: All changes must pass complete CI/CD pipeline before merge.

```bash
# CI/CD validation sequence
just ci-check  # Comprehensive pipeline validation
```

**AI Assistant Rule**: Never report task completion without successful `just ci-check` execution.

## Build and Release Pipeline

### Automated Release Process

- **Build Tool**: GoReleaser v2 for cross-platform releases
- **Platforms**: macOS, Windows, Linux (amd64/arm64)
- **Distribution**: Single binary with no external runtime dependencies
- **Versioning**: Semantic versioning triggered by conventional commits

### Release Quality Gates

- All CI checks must pass before release
- Security scanning with zero critical vulnerabilities
- Cross-platform build verification
- Automated changelog generation

## GitHub Actions CI/CD Pipeline

### Pipeline Requirements

- **Trigger Events**: All PRs to main/develop branches and pushes to main
- **Go Version**: Use Go 1.21+ with actions/setup-go
- **Quality Gates**: Execute `just ci-check` for comprehensive validation
- **Parallel Jobs**: Run quality checks and security scanning concurrently

### MegaLinter Integration

- **Tool**: Use oxsecurity/megalinter/flavors/go for Go-focused analysis
- **Scope**: Validate only changed files in PRs, full codebase on main
- **Security**: Generate SARIF reports for GitHub Security tab integration
- **Auto-fixes**: Apply formatting fixes automatically where possible

### Essential Linters

- **Go**: golangci-lint with project-specific configuration
- **Markdown**: markdownlint for documentation consistency
- **YAML/JSON**: Syntax and formatting validation
- **Security**: Gitleaks for secrets, Trivy for vulnerabilities
- **Exclusions**: Ignore `.git/`, `testdata/*.xml`, and vendor directories

### Pipeline Failure Handling

- **Security Issues**: Build fails immediately on secrets or critical vulnerabilities
- **Quality Issues**: Auto-fixes applied where possible, manual review required otherwise
- **Test Failures**: Detailed reporting with coverage analysis
- **Build Failures**: Cross-platform build verification before release

### Performance Optimization

- **Incremental Analysis**: Only changed files analyzed in PRs
- **Parallel Execution**: Multiple quality checks run concurrently
- **Caching**: Dependencies and build artifacts cached between runs
- **Timeout**: 10-minute maximum execution with early failure detection
