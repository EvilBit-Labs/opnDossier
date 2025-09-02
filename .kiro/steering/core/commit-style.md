---
inclusion: always
---

# Commit Message Standards

## Format Requirements

All commits MUST follow [Conventional Commits](https://www.conventionalcommits.org) specification:

```text
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

## Commit Types

- `feat`: New features or functionality
- `fix`: Bug fixes and corrections
- `docs`: Documentation changes only
- `style`: Code style changes (formatting, whitespace)
- `refactor`: Code restructuring without behavior changes
- `perf`: Performance improvements
- `test`: Adding or modifying tests
- `build`: Build system or dependency changes
- `ci`: CI/CD configuration changes
- `chore`: Maintenance tasks and meta changes

## Scope Guidelines

Scopes are REQUIRED and must match project architecture:

- `parser`: XML parsing and configuration file handling
- `converter`: Data format conversion (XML/JSON/YAML/Markdown)
- `audit`: Compliance checking and audit engine
- `cli`: Command-line interface and user interaction
- `model`: Data structures and type definitions
- `plugin`: Plugin system and compliance frameworks
- `templates`: Output templates and formatting
- `display`: Terminal output and styling
- `config`: Configuration management
- `validator`: Data validation utilities

## Description Rules

- Use imperative mood ("add", not "added" or "adds")
- Start with lowercase letter
- No period at the end
- Maximum 72 characters
- Be specific and clear about the change

## Body Guidelines

- Start after blank line from description
- Explain WHAT and WHY, not HOW
- Use bullet points for multiple changes
- Reference requirements (F###) when applicable
- Include context for complex changes

## Footer Usage

- Start after blank line from body
- Use for issue references: `Closes #123`, `Fixes #456`
- Breaking changes: `BREAKING CHANGE: description`
- Co-authored commits: `Co-authored-by: Name <email>`

## Breaking Changes

Mark breaking changes using either:

- `!` after type/scope: `feat(api)!: redesign plugin interface`
- Footer: `BREAKING CHANGE: plugin interface now requires version field`

## Quality Requirements

- All commits MUST pass `just ci-check`
- Code MUST be formatted with `gofmt`
- Tests MUST pass before committing
- Linting issues MUST be resolved

## Examples

### Feature Addition

```text
feat(parser): add support for OPNsense 24.1 config format

- Parse new VLAN configuration structure
- Handle updated firewall rule format
- Add backward compatibility for 23.x versions

Closes #142
```

### Bug Fix

```text
fix(converter): handle empty VLAN configurations gracefully

Previously crashed when VLAN section was empty or missing.
Now returns empty array and logs warning message.

Fixes #156
```

### Documentation

```text
docs(cli): update installation instructions

Add Windows-specific installation steps and troubleshooting
section for common dependency issues.
```

### Breaking Change

```text
feat(model)!: redesign OpnSenseDocument structure

BREAKING CHANGE: OpnSenseDocument.Interfaces is now a map
instead of slice. Update code accessing interface data.

- Improves lookup performance for large configurations
- Enables interface validation by name
- Simplifies audit plugin implementation

Closes #178
```

### Refactoring

```text
refactor(audit): extract plugin registry to separate package

Move plugin management logic to internal/registry for better
separation of concerns and testability.
```

## Anti-Patterns

Avoid these commit message patterns:

- `fix: bug fix` (too vague)
- `feat: added new feature` (wrong tense)
- `update code` (missing scope and specificity)
- `WIP: work in progress` (incomplete work)
- `fix typo` (missing scope)
