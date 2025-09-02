---
inclusion: fileMatch
fileMatchPattern:
  - project_spec/*.md
  - '**/*requirements*.md'
  - '**/*tasks*.md'
  - '**/*user_stories*.md'
---

# Requirements Management for opnDossier

## Critical AI Assistant Guidelines

### Before Modifying Requirements

- **ALWAYS** run `just ci-check` after any specification changes
- **NEVER** modify requirements without updating corresponding tasks
- **ALWAYS** maintain traceability between F### requirements and TASK-### implementations
- **MUST** use RFC 2119 keywords (SHALL, MUST, SHOULD, MAY) consistently

### opnDossier Context

- **Mission**: OPNsense configuration auditing for cybersecurity professionals
- **Architecture**: Offline-first CLI tool with plugin-based compliance checking
- **Users**: Blue team (defensive), red team (offensive), operations teams
- **Core Flow**: XML → Parser → Model → Audit Engine → Report Generator → Output

## Requirements Documentation Standards

### Functional Requirements Format

```markdown
F### (Brief description with key constraints)
- **Context**: Why this requirement exists
- **Acceptance**: Clear, testable success criteria
- **Priority**: Critical/High/Medium/Low
- **Dependencies**: Related requirements (F###)
```

### EARS Notation Requirements

- **Event-driven**: "When [trigger], then system SHALL [action]"
- **State-driven**: "While in [state], system SHALL [behavior]"
- **Unwanted**: "If [error condition], then system SHALL [recovery]"
- **Ubiquitous**: "System SHALL always [fundamental property]"
- **Optional**: "Where [condition exists], system MAY [optional behavior]"

### opnDossier-Specific Requirements

- **XML Processing**: Use `encoding/xml` standard library only
- **Offline Operation**: No external network dependencies
- **Plugin Architecture**: Extensible compliance checking (STIG, SANS, CIS)
- **Multi-Format Output**: Markdown (primary), JSON, YAML export
- **Security Focus**: Input validation, secure defaults, no telemetry

## Task Management Standards

### Task Structure (MANDATORY)

```markdown
- [ ] **TASK-###**: Descriptive Title

  - **Context**: Implementation rationale and project relationship
  - **Requirement**: F### (specific functional requirement)
  - **User Story**: US-### (user-centric justification)
  - **Action**: Specific implementation steps
  - **Acceptance**: Clear, testable completion criteria
  - **Dependencies**: Prerequisites and blockers
```

### Task Lifecycle

- **[ ]**: Not started
- **[x]**: Completed (with `just ci-check` passing)
- **[!]**: Blocked or needs attention

### Implementation Phases

1. **Core Infrastructure** (TASK-001-010): Dependencies, logging, configuration
2. **XML Processing** (TASK-011-020): Parsing, validation, data models
3. **Output Generation** (TASK-021-030): Markdown, display, file export
4. **Audit Engine** (TASK-031-040): Plugin system, compliance checking
5. **Quality & Testing** (TASK-041-050): Testing, documentation, validation

## Compliance and Security Requirements

### Security-First Principles

- **Offline-First**: No external dependencies or network calls
- **Input Validation**: Comprehensive validation for all user inputs
- **Secure Defaults**: Security-first default configurations
- **No Telemetry**: Zero external data transmission
- **Plugin Security**: Sandboxed compliance plugin execution

### Compliance Framework Integration

- **STIG**: Security Technical Implementation Guides
- **SANS**: Critical Security Controls
- **CIS**: Center for Internet Security benchmarks
- **Plugin Architecture**: Extensible framework for custom compliance rules

## Quality Gates (MANDATORY)

### Before Completing Any Task

```bash
# REQUIRED validation sequence
just format    # Format all code and documentation
just lint      # Static analysis and linting
just test      # Run comprehensive test suite
just ci-check  # Full quality validation (MANDATORY)
```

### Requirements Validation

```bash
# Check requirement consistency
grep -E "F0[0-9]{2}" project_spec/requirements.md | wc -l

# Validate task-requirement alignment
grep -E "TASK-[0-9]{3}" project_spec/tasks.md | grep -E "F0[0-9]{2}"

# Check for missing acceptance criteria
grep -c "Acceptance:" project_spec/tasks.md
```

## AI Assistant Implementation Rules

### When Creating Requirements

1. **Use EARS notation** for all new requirements
2. **Include acceptance criteria** that are testable and specific
3. **Reference related requirements** using F### notation
4. **Assign appropriate priority** based on user value and technical risk
5. **Update corresponding tasks** to maintain traceability

### When Implementing Tasks

1. **Reference specific requirements** (F###) in task description
2. **Include user story context** (US-###) when applicable
3. **Define clear acceptance criteria** for completion validation
4. **Identify dependencies** and prerequisites
5. **Run quality gates** before marking tasks complete

### When Modifying Specifications

1. **Update document metadata** (version, last modified date)
2. **Maintain cross-references** between requirements, tasks, and user stories
3. **Validate impact** on existing implementations
4. **Run comprehensive checks** (`just ci-check`)
5. **Document rationale** for changes in commit messages

## Document Relationships

### Core Specification Files

- **requirements.md**: Authoritative source for WHAT system must do
- **tasks.md**: Implementation plan for HOW to build requirements
- **user_stories.md**: User context for WHY requirements matter
- **ARCHITECTURE.md**: System design and technical approach

### Traceability Matrix

```text
Requirements (F###) → Tasks (TASK-###) → User Stories (US-###) → Code Implementation
```

### Cross-Reference Validation

- Every F### requirement MUST have corresponding TASK-### implementation
- Every TASK-### MUST reference specific F### requirement
- Every US-### SHOULD influence multiple F### requirements
- All references MUST be validated and current

## Key Reference Documents

- **#[[file:project_spec/requirements.md]]** - Complete functional requirements
- **#[[file:project_spec/tasks.md]]** - Implementation task checklist
- **#[[file:project_spec/user_stories.md]]** - User-centric scenarios
- **#[[file:ARCHITECTURE.md]]** - System architecture and design
