## applyTo: project_spec/*.md,docs/spec/*.md,\*\*/\*.mdc

# Project Specification Management Guidelines

## Overview

This document provides comprehensive guidelines for managing requirements, tasks, and user stories in the opnDossier project. It ensures consistency across all specification documents and maintains proper alignment between requirements and implementation.

## Project Specification Files

### Core Specification Documents

The `project_spec/` directory contains three essential documents that work together to define the complete project scope:

- **requirements.md** - **Complete requirements specification**

  - Contains all functional requirements (F001-F025) and technical requirements
  - Defines system capabilities, constraints, and implementation details
  - Serves as the authoritative source for what the system must do
  - Includes document metadata for version control and change tracking

- **tasks.md** - **Implementation task checklist**

  - Breaks down requirements into actionable development tasks
  - Provides implementation context, acceptance criteria, and dependencies
  - Tracks progress through task lifecycle (not started, in progress, completed)
  - Links tasks to specific requirements and user stories

- **user_stories.md** - **User stories and use cases**

  - Defines user-centric requirements and scenarios
  - Provides context for why features are needed
  - Helps prioritize development based on user value
  - Supports acceptance criteria and testing scenarios

### Document Relationships

- **Requirements** define WHAT the system must do
- **Tasks** define HOW to implement the requirements
- **User Stories** define WHY the requirements matter to users
- All three documents should remain synchronized and cross-referenced

## Requirements Document Standards

### Document Structure

- **Functional Requirements (F001-F025)**: Core system capabilities and features
- **Technical Requirements**: Implementation details and technical constraints
- **User Stories**: User-centric requirements and use cases
- **System Architecture**: High-level design and component relationships

### Style Consistency

- **Concise Format**: Requirements should be concise, single-line entries with key details in parentheses
- **Reference Pattern**: Use format `F### (key details)` for functional requirements
- **Cross-References**: Include relevant requirement numbers in parentheses when referencing other requirements
- **Balance**: Strike balance between conciseness and comprehensiveness - avoid verbose multi-bullet requirements

### Maintenance Guidelines

- **Version Control**: Update document version and last modified date when making changes
- **Change Tracking**: Document specific changes in metadata section
- **Consistency**: Ensure all requirements follow the same style and format
- **Redundancy**: Avoid duplicating information already covered in architecture or other sections

## Task Documentation Standards

### Task Structure

Each task should follow this consistent structure:

```markdown
- [ ] **TASK-###**: Task Title

  - **Context**: Clear explanation of why this task is needed
  - **Requirement**: List all relevant requirement numbers (F###)
  - **User Story**: Reference applicable user stories (US-###)
  - **Action**: Specific implementation steps and approach
  - **Acceptance**: Clear acceptance criteria for completion
```

### Task Lifecycle Management

#### Task States

- **[ ]**: Not started
- **[~]**: In progress
- **[x]**: Completed
- **[!]**: Blocked or needs attention

#### Update Process

- **Status Updates**: Update task status as work progresses
- **Requirement Changes**: Update task requirements when requirements change
- **Dependency Tracking**: Note dependencies between tasks
- **Progress Tracking**: Document progress and blockers

### Task Categories

#### Phase 1: Core Infrastructure

- **TASK-001** to **TASK-010**: Basic setup, dependencies, and core functionality

#### Phase 2: Data Processing

- **TASK-011** to **TASK-020**: XML parsing, model creation, and data conversion

#### Phase 3: Output Generation

- **TASK-021** to **TASK-030**: Markdown generation, display, and export functionality

#### Phase 4: Audit Engine

- **TASK-031** to **TASK-040**: Audit functionality, plugins, and compliance checking

#### Phase 5: Integration and Testing

- **TASK-041** to **TASK-050**: Integration testing, documentation, and final validation

## Alignment Standards

### Requirement References

- **Explicit References**: Always include requirement numbers (F###) in task descriptions
- **User Story References**: Include relevant user story numbers (US-###) when applicable
- **Cross-Validation**: Ensure tasks align with current requirement descriptions
- **Update Frequency**: Review and update task requirements when requirements change
- **Completeness**: Ensure all requirements have corresponding tasks

### User Story Integration

- **Story References**: Include relevant user story numbers when applicable
- **User-Centric**: Frame tasks in terms of user value and outcomes
- **Acceptance Criteria**: Define clear, testable acceptance criteria
- **Priority Alignment**: Align task priority with user story priority

## Quality Assurance

### Review Process

- **Style Consistency**: Verify all requirements follow the same format
- **Completeness**: Ensure all requirements are properly documented
- **Alignment**: Check that tasks reference current requirement descriptions
- **Metadata**: Update document metadata when making changes
- **Clarity**: Verify task descriptions are clear and actionable
- **Dependencies**: Check for missing dependencies or blockers

### Validation Commands

```bash
# Check markdown formatting
just format

# Run comprehensive checks
just ci-check


# Validate requirements and task cross-references (robust, future-proof, offline-first)
go run scripts/lint_requirements.go

# The linter script should:
# - Parse all requirement IDs (e.g., F001, F100, F123, etc.) from project_spec/requirements.md
# - Parse all requirement references from project_spec/tasks.md
# - Assert every requirement is referenced by at least one task
# - Assert every requirement reference in tasks.md exists in requirements.md
# - Report any missing or orphaned links

# Example Go linter (scripts/lint_requirements.go):
# (Place this script in scripts/lint_requirements.go and make it runnable with `go run`)
#
# package main
# import (...)
# func main() {
#   // Parse requirements.md and tasks.md, check bidirectional links, print errors if any
# }
```

## Key Documents

- **requirements.md** - Complete requirements specification
- **tasks.md** - Implementation task checklist
- **user_stories.md** - User stories and use cases
- **ARCHITECTURE.md** - System architecture documentation
