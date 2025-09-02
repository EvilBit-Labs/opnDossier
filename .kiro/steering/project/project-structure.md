---
inclusion: always
---

# AI File Organization Decision Guide

## Pre-Implementation Checklist

### Before Creating ANY New File

1. **Scan existing structure** - Use `listDirectory` to review current organization
2. **Check for existing utilities** - Search for similar functionality before duplicating
3. **Validate package placement** - Ensure new files belong in the intended package
4. **Review naming patterns** - Match established conventions in the target directory

### File Placement Decision Tree

```text
New functionality needed?
├── CLI command? → cmd/{command}.go
├── Data structure? → internal/model/{domain}.go
├── XML parsing? → internal/parser/{feature}.go
├── Compliance rule? → internal/plugins/{framework}/{rule}.go
├── Output formatting? → internal/display/{format}.go
├── File conversion? → internal/converter/{format}.go
├── Validation logic? → internal/validator/{type}.go
└── Utility function? → Check existing packages first!
```

## Package Boundary Enforcement

### Strict Separation Rules

- **cmd/**: ONLY Cobra commands and CLI interaction - NO business logic
- **internal/model/**: ONLY data structures with tags - NO processing logic
- **internal/parser/**: ONLY XML parsing with `encoding/xml` - NO other formats
- **internal/audit/**: ONLY plugin orchestration - NO specific compliance rules
- **internal/plugins/**: ONLY framework-specific implementations - NO generic logic

### Common AI Mistakes to Avoid

```text
❌ WRONG: Adding business logic to cmd/ files
✅ CORRECT: CLI calls internal packages for business logic

❌ WRONG: Creating new packages for single functions
✅ CORRECT: Add to existing appropriate package

❌ WRONG: Mixing XML parsing with JSON/YAML in parser/
✅ CORRECT: XML in parser/, other formats in converter/

❌ WRONG: Hardcoding compliance rules in audit/
✅ CORRECT: Generic plugin management in audit/, rules in plugins/
```

## File Naming Intelligence

### Context-Aware Naming

When creating files, consider the **functional context**:

```text
internal/model/
├── opnsense.go      # Root document structure
├── firewall.go      # Firewall-specific types
├── interfaces.go    # Network interface types
├── findings.go      # Audit result types
└── validation.go    # Validation methods

internal/plugins/stig/
├── stig.go          # Main plugin implementation
├── controls.go      # STIG control definitions
├── network.go       # Network-related STIG rules
└── access.go        # Access control STIG rules
```

### Avoid These Naming Patterns

- Generic names: `utils.go`, `helpers.go`, `common.go`
- Vague names: `data.go`, `types.go`, `functions.go`
- Redundant names: `parser_parser.go`, `model_types.go`

## Integration Points

### When Adding New Features

1. **Check requirements** - Reference `project_spec/requirements.md` for context
2. **Identify integration points** - Where does this connect to existing code?
3. **Plan data flow** - How does this fit the XML → Parser → Model → Audit → Output pipeline?
4. **Consider plugin architecture** - Should this be extensible via plugins?

### Cross-Package Dependencies

```go
// CORRECT: Clear dependency direction
cmd/convert.go → internal/converter → internal/model
                                  → internal/parser

// WRONG: Circular dependencies
internal/model ↔ internal/parser  // Avoid this!
```

## AI-Specific Guidance

### When Implementing Requirements

1. **Map requirement to package** - F001-F005 (convert) → cmd/convert.go + internal/converter/
2. **Identify data structures needed** - Add to internal/model/ with proper XML tags
3. **Plan testing strategy** - Create corresponding \*\_test.go files
4. **Consider error handling** - Add to appropriate errors.go file

### Quality Validation Commands

```bash
# Before creating files - understand current structure
find . -name "*.go" -type f | head -20

# After creating files - validate organization
just format && just lint && just test && just ci-check
```

## Reference Integration

This document focuses on **file organization decisions**. For comprehensive details, see:

- **Project structure**: `.kiro/steering/structure.md`
- **Go organization**: `.kiro/steering/go/go-organization.md`
- **Core concepts**: `.kiro/steering/core/core-concepts.md`
- **Requirements**: `project_spec/requirements.md`
