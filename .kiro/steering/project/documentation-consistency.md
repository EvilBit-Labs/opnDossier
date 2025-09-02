---
inclusion: fileMatch
fileMatchPattern:
  - '**/*.md'
  - 'docs/**/*'
  - '**/*.mdc'
---

# Documentation Consistency Guidelines for opnDossier

## Core Documentation Principles

### Writing Standards for AI Assistants

- **Operator-Focused Language**: Write for security professionals and network operators
- **Technical Precision**: Use exact terminology for OPNsense, firewall, and security concepts
- **Actionable Content**: Provide clear, implementable guidance and examples
- **Concise Clarity**: Balance technical depth with readability - avoid unnecessary verbosity

### opnDossier-Specific Terminology

- **OPNsense**: Always capitalize correctly (not "opnsense" or "OPNSense")
- **config.xml**: Use backticks for file references
- **CLI Tool**: Refer to opnDossier as a "CLI tool" not "application" or "program"
- **Offline-First**: Hyphenated when used as adjective
- **Airgapped**: Single word, not "air-gapped"
- **Markdown**: Capitalize when referring to the format

## Document Structure Standards

### Markdown Formatting Rules

- **Headers**: Use ATX-style headers (`#`, `##`, `###`) consistently
- **Code Blocks**: Always specify language for syntax highlighting
- **Lists**: Use `-` for unordered lists, `1.` for ordered lists
- **Emphasis**: Use `**bold**` for important terms, `*italic*` for emphasis
- **Links**: Use descriptive link text, avoid "click here" or bare URLs

### Project-Specific Formatting

```markdown
# Correct Examples

## CLI Commands
```bash
opndossier convert config.xml --format markdown
```

## File References

- Configuration file: `config.xml`
- Output file: `documentation.md`
- Template directory: `internal/templates/`

## Requirements References

- Functional requirement: F001 (XML parsing)
- Task reference: TASK-030 (CLI structure)
- User story: US-009 (CLI interface)

## Content Organization by Document Type

### Requirements Documentation (`project_spec/`)

- **Format**: Use EARS notation (Event-driven, State-driven, etc.)
- **Structure**: Functional requirements (F001-F026), technical specs, acceptance criteria
- **Style**: Concise single-line entries with key details in parentheses
- **Cross-References**: Link to related tasks and user stories

### Architecture Documentation

- **Focus**: System design, data flow, component relationships
- **Diagrams**: Use Mermaid for architecture diagrams when possible
- **Patterns**: Document architectural patterns and design decisions
- **Performance**: Include performance characteristics and constraints

### User Documentation

- **Audience**: Network operators, security professionals, DevOps engineers
- **Examples**: Provide realistic OPNsense configuration scenarios
- **Workflows**: Document complete end-to-end workflows
- **Troubleshooting**: Include common issues and solutions

## AI Assistant Guidelines

### When Updating Documentation

1. **Maintain Consistency**: Follow existing patterns and terminology
2. **Update Cross-References**: Ensure all internal links remain valid
3. **Validate Examples**: Test all code examples and CLI commands
4. **Check Metadata**: Update document version and modification dates
5. **Run Quality Checks**: Execute `just ci-check` before completion

### Documentation Quality Gates

- All code examples must be tested and functional
- Cross-references must point to existing content
- Markdown must pass linting (`markdownlint`)
- Formatting must be consistent (`mdformat`)
- Technical accuracy must be verified

### Common Patterns to Follow

```markdown
# Task Documentation Pattern
- [x] **TASK-###**: Task Title
  - **Context**: Why this task is needed
  - **Requirement**: F### (specific requirement)
  - **Action**: What needs to be implemented
  - **Acceptance**: Clear success criteria

# CLI Command Documentation Pattern
```bash
# Basic usage
opndossier convert config.xml

# With options
opndossier convert config.xml --format json --output report.json
```

# Error Handling Documentation Pattern

**Error**: `parse error at line 45: invalid XML syntax`
**Cause**: Malformed XML in configuration file
**Solution**: Validate XML structure using standard tools

## Validation and Quality Assurance

### Required Checks Before Committing

```bash
# Format all markdown files
just format

# Validate markdown syntax and style
markdownlint **/*.md

# Check for broken internal links
markdown-link-check **/*.md

# Run comprehensive quality checks
just ci-check
```

### Document Metadata Requirements

All major documentation files must include:

- Document version
- Last modified date
- Author information
- Change summary for updates

### Cross-Reference Validation

- Verify all `#[[file:...]]` references exist
- Check all requirement references (F###, TASK-###, US-###)
- Validate all internal markdown links
- Ensure code examples are current and functional

## Key Documentation Files

### Core Project Documentation

- **README.md** - Project overview, installation, quick start
- **AGENTS.md** - AI assistant development guidelines
- **ARCHITECTURE.md** - System design and component architecture
- **DEVELOPMENT_STANDARDS.md** - Go coding standards and practices

### Project Specification

- **project_spec/requirements.md** - Complete functional and technical requirements
- **project_spec/tasks.md** - Implementation task checklist with progress tracking
- **project_spec/user_stories.md** - User-centric requirements and scenarios

### Specialized Documentation

- **docs/** - User guides, API documentation, examples
- **CONTRIBUTING.md** - Contribution guidelines and development workflow
- **SECURITY.md** - Security policy and vulnerability reporting
