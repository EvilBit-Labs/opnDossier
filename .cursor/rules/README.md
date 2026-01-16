# Cursor Rules Organization

This directory contains Cursor AI development rules organized into logical subfolders for better maintainability and clarity.

## 📁 Folder Structure

### 🎯 Core (`core/`)

#### Foundation rules that always apply - fundamental project principles

- **`core-concepts.mdc`** - Core philosophy, EvilBit Labs brand principles, technology stack, and fundamental development patterns
- **`commit-style.mdc`** - Conventional commit message standards with project-specific scopes

*These rules have `alwaysApply: true` and form the foundation for all development work.*

### 🤖 AI Assistant (`ai-assistant/`)

#### AI agent behavior, workflows, and mandatory practices

- **`ai-assistant-guidelines.mdc`** - AI behavior rules, development rules of engagement, mandatory practices, and common workflows
- **`development-workflow.mdc`** - Development process, quality assurance steps, and code review checklist

*Essential for AI agents working on the project.*

### 🐹 Go Language (`go/`)

#### Go-specific coding standards and best practices

- **`go-standards.mdc`** - Go development standards, coding conventions, and language-specific guidelines
- **`go-testing.mdc`** - Go testing best practices, benchmarking, and test organization
- **`go-documentation.mdc`** - Go documentation standards and commenting conventions
- **`go-organization.mdc`** - Go package organization and file structure

*Applied when working with Go source files (`**/*.go`).*

### 📋 Project (`project/`)

#### Project structure, documentation, and requirements management

- **`project-structure.mdc`** - Directory layout, file organization, and project hierarchy
- **`requirements-management.mdc`** - Requirements tracking and specification management
- **`documentation-consistency.mdc`** - Documentation standards and consistency rules

*Guides overall project organization and documentation.*

### 🏗️ Architecture (`architecture/`)

#### System design, architectural patterns, and component relationships

- **`audit-engine.mdc`** - Audit system guidelines, plugin architecture, and compliance checking
- **`plugin-architecture.mdc`** - Plugin development standards, interfaces, and testing requirements

*Applied when working with architectural components and plugins.*

### ✅ Quality (`quality/`)

#### CI/CD, testing, and quality assurance standards

- **`ci-cd-standards.mdc`** - CI/CD integration, quality gates, and deployment standards
- **`compliance-standards.mdc`** - Compliance and security standards for the project

*Ensures code quality and deployment reliability.*

## 🎛️ Rule Precedence

**CRITICAL - Rules are applied in the following order of precedence:**

1. **Project-specific rules** (from project root instruction files like AGENTS.md or .cursor/rules/)
2. **General development standards** (outlined in these rules)
3. **Language-specific style guides** (Go conventions, etc.)

When rules conflict, always follow the rule with higher precedence.

## 🔄 Rule Application

### Always Applied Rules

- `core/core-concepts.mdc` (`alwaysApply: true`)
- `core/commit-style.mdc` (`alwaysApply: true`)
- `ai-assistant/ai-assistant-guidelines.mdc` (`alwaysApply: true`)
- `quality/ci-cd-standards.mdc` (`alwaysApply: true`)

### Context-Specific Rules

- `go/` rules apply to `**/*.go` files
- `ai-assistant/development-workflow.mdc` applies to `**/*.md,**/*.go,**/justfile`
- Other rules apply based on their specific glob patterns

## 📚 Related Documentation

For comprehensive project information, also refer to:

- **[AGENTS.md](../../AGENTS.md)** - Complete AI agent development guidelines
- **[.github/copilot-instructions.md](../../.github/copilot-instructions.md)** - GitHub Copilot specific instructions
- **[DEVELOPMENT_STANDARDS.md](../../docs/development/standards.md)** - Go-specific coding standards
- **[ARCHITECTURE.md](../../docs/development/architecture.md)** - System architecture documentation

## 🔧 Maintenance

When updating cursor rules:

1. **Maintain consistency** with AGENTS.md and GitHub Copilot instructions
2. **Update related files** when making changes that affect multiple rule categories
3. **Test rule application** to ensure no conflicts between rules
4. **Document changes** in the appropriate category README if needed

## 🎯 Benefits of This Organization

- **Logical Separation**: Related rules grouped together for easier maintenance
- **Reduced Cognitive Load**: Easier to find and update specific types of rules
- **Clear Ownership**: Each category has a specific purpose and scope
- **Maintainability**: Changes can be made to specific areas without affecting others
- **Consistency**: Aligned with project documentation and other AI tool instructions
