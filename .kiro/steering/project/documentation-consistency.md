---
inclusion: fileMatch
fileMatchPattern:
  - '**/*.md'
  - docs/**/*
  - '**/*.mdc'
---

# Documentation Consistency Guidelines

## Writing Standards

- **Operator-Focused**: Write for security professionals and network operators
- **Technical Precision**: Use exact terminology for OPNsense, firewall, and security concepts
- **Actionable Content**: Provide clear, implementable guidance

## Terminology

- **OPNsense**: Always capitalize correctly (not "opnsense" or "OPNSense")
- **config.xml**: Use backticks for file references
- **CLI Tool**: Refer to opnDossier as a "CLI tool" not "application"
- **Offline-First**: Hyphenated when used as adjective
- **Airgapped**: Single word, not "air-gapped"

## Formatting Standards

- **Headers**: Use ATX-style (`#`, `##`, `###`)
- **Code Blocks**: Always specify language
- **Lists**: Use `-` for unordered, `1.` for ordered
- **Emphasis**: `**bold**` for important terms, `*italic*` for emphasis

## Quality Gates

```bash
just format              # Format all markdown
markdownlint **/*.md     # Validate syntax
markdown-link-check **/*.md  # Check links
just ci-check           # Comprehensive validation
```

## Common Patterns

### CLI Commands

```bash
opndossier convert config.xml --format markdown
```

### Requirements References

- Functional: F001 (XML parsing)
- Task: TASK-030 (CLI structure)
- User story: US-009 (CLI interface)

### Error Documentation

**Error**: `parse error at line 45`
**Solution**: Validate XML structure
