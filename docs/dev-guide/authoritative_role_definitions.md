# Authoritative Role Definitions

This document captures the single-sentence "official" purpose of each library used in the opnDossier project, compiled from `tasks.md` and `AGENTS.md`.

## Library Role Definitions

### Cobra

**Purpose**: Command structure & argument parsing **Introduced in**: TASK-001 (Update Go dependencies to match requirements) **Context**: Use `cobra` for CLI command organization with consistent verb patterns (`create`, `list`, `get`, `update`, `delete`)

### Fang (charmbracelet/fang)

**Purpose**: Enhanced UX layer on top of Cobra (styled help, version, completion) **Introduced in**: TASK-003a (Implement CLI enhancement with fang) **Context**: Add fang for enhanced CLI experience with styled help, errors, and automatic features including styled help/usage pages, styled error messages, automatic `--version` flag, hidden `man` command for manpage generation, `completion` command for shell completions, and themeable appearance

### Viper (spf13/viper)

**Purpose**: Layered configuration (files, env, flags) **Introduced in**: TASK-003 (Set up configuration management with viper) **Context**: Implement YAML config files, environment variables, CLI overrides using viper with standard precedence (CLI flags > env vars > config file > defaults)

### charmbracelet/log

**Purpose**: Structured, leveled logging **Introduced in**: TASK-002 (Implement structured logging with `charmbracelet/log`) **Context**: Replace current `log` usage with structured logging throughout application using charmbracelet/log with proper levels (Debug, Info, Warn, Error)

## Supporting Libraries

### charmbracelet/lipgloss

**Purpose**: Styled terminal output formatting **Introduced in**: TASK-014 (Implement terminal display with lipgloss) **Context**: Create styled terminal output with colored, syntax-highlighted markdown

### charmbracelet/glamour

**Purpose**: Markdown rendering in terminal **Introduced in**: TASK-016 (Implement markdown rendering with glamour) **Context**: Integrate glamour for markdown rendering in terminal with syntax highlighting

## Task Reference Summary

- **TASK-001**: Dependency management and technology stack setup
- **TASK-002**: Structured logging implementation
- **TASK-003**: Configuration management with viper
- **TASK-003a**: CLI enhancement with fang

## Configuration Precedence

As established in TASK-003 and TASK-028, the configuration system follows standard precedence:

1. CLI flags (highest precedence)
2. Environment variables
3. Configuration file
4. Defaults (lowest precedence)

## CLI Architecture Pattern

The project implements a layered CLI architecture:

- **Cobra**: Foundation for command structure and argument parsing
- **Fang**: Enhancement layer providing styled UX, automatic features, and improved user experience
- **Viper**: Configuration layer managing settings from multiple sources
- **charmbracelet/log**: Logging layer providing structured, contextual logging throughout the application
