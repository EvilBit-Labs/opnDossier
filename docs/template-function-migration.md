# Template Function Migration Guide

## Overview

This document provides a comprehensive mapping of existing template functions to their planned Go method replacements as part of the transition from template-based to programmatic markdown generation.

## Migration Strategy

The migration follows a phased approach to minimize disruption:

1. **Phase 1**: Core utility functions (formatting, escaping)
2. **Phase 2**: Data transformation functions
3. **Phase 3**: Complex aggregation and analysis functions
4. **Phase 4**: Sprig function replacements

## Target Architecture

All template functions will be replaced with methods on a `MarkdownBuilder` type:

```go
type MarkdownBuilder struct {
    config *model.OpnSenseDocument
    opts   Options
    logger *log.Logger
}
```

## Function Mappings

### Phase 1: Core Utility Functions

| Template Function        | Go Method                                                       | Status       | Notes                           |
| ------------------------ | --------------------------------------------------------------- | ------------ | ------------------------------- |
| `escapeTableContent`     | `EscapeTableContent(content any) string`                        | Pending      | Critical for table generation   |
| `isLast`                 | `IsLastInSlice(index int, slice any) bool`                      | Pending      | Used in template loops          |
| `formatBoolean`          | `FormatBoolean(value any) string`                               | **Migrated** | Already exists in formatters.go |
| `formatBooleanWithUnset` | `FormatBooleanWithUnset(value any) string`                      | **Migrated** | Already exists in formatters.go |
| `formatUnixTimestamp`    | `FormatUnixTimestamp(timestamp string) string`                  | **Migrated** | Already exists in formatters.go |
| `isTruthy`               | `IsTruthy(value any) bool`                                      | **Migrated** | Already exists in formatters.go |
| `truncateDescription`    | `TruncateDescription(description string, maxLength int) string` | Pending      | Word boundary handling required |

### Phase 2: Data Transformation Functions

| Template Function         | Go Method                                                                            | Status       | Notes                           |
| ------------------------- | ------------------------------------------------------------------------------------ | ------------ | ------------------------------- |
| `formatInterfacesAsLinks` | `FormatInterfaceLinks(interfaces model.InterfaceList) string`                        | Pending      | Generates markdown anchor links |
| `filterTunables`          | `FilterSystemTunables(tunables []model.SysctlItem, include bool) []model.SysctlItem` | Pending      | Security-focused filtering      |
| `getPowerModeDescription` | `GetPowerModeDescription(mode string) string`                                        | **Migrated** | Already exists in formatters.go |
| `getPortDescription`      | `GetPortDescription(port string) string`                                             | Pending      | Simple string formatting        |
| `getProtocolDescription`  | `GetProtocolDescription(protocol string) string`                                     | Pending      | Simple string formatting        |

### Phase 3: Security and Compliance Functions

| Template Function       | Go Method                                            | Status  | Notes                                  |
| ----------------------- | ---------------------------------------------------- | ------- | -------------------------------------- |
| `getRiskLevel`          | `AssessRiskLevel(severity string) string`            | Pending | Returns emoji + risk text              |
| `getSecurityZone`       | `DetermineSecurityZone(interfaceName string) string` | Pending | Zone classification logic              |
| `getSTIGDescription`    | `GetSTIGControlDescription(controlID string) string` | Pending | **Placeholder** - needs STIG database  |
| `getSANSDescription`    | `GetSANSControlDescription(controlID string) string` | Pending | **Placeholder** - needs SANS database  |
| `getRuleCompliance`     | `AssessFirewallRuleCompliance(rule any) string`      | Pending | **Placeholder** - complex analysis     |
| `getNATRiskLevel`       | `AssessNATRuleRisk(rule any) string`                 | Pending | **Placeholder** - security assessment  |
| `getNATRecommendation`  | `GenerateNATRecommendation(rule any) string`         | Pending | **Placeholder** - remediation advice   |
| `getCertSecurityStatus` | `AssessCertificateSecurityStatus(cert any) string`   | Pending | **Placeholder** - certificate analysis |
| `getDHCPSecurity`       | `AssessDHCPSecurity(dhcp any) string`                | Pending | **Placeholder** - DHCP security check  |
| `getRouteSecurityZone`  | `DetermineRouteSecurityZone(route any) string`       | Pending | **Placeholder** - route analysis       |

### Phase 4: Sprig Function Replacements (High Priority)

| Sprig Function | Go Method                                            | Status  | Notes                     |
| -------------- | ---------------------------------------------------- | ------- | ------------------------- |
| `upper`        | `ToUpper(s string) string`                           | Pending | String case conversion    |
| `lower`        | `ToLower(s string) string`                           | Pending | String case conversion    |
| `title`        | `ToTitle(s string) string`                           | Pending | Title case conversion     |
| `trim`         | `TrimSpace(s string) string`                         | Pending | Whitespace removal        |
| `trimPrefix`   | `TrimPrefix(s, prefix string) string`                | Pending | Prefix removal            |
| `trimSuffix`   | `TrimSuffix(s, suffix string) string`                | Pending | Suffix removal            |
| `replace`      | `ReplaceString(s, old, new string) string`           | Pending | String replacement        |
| `split`        | `SplitString(s, sep string) []string`                | Pending | String splitting          |
| `join`         | `JoinStrings(elems []string, sep string) string`     | Pending | String joining            |
| `contains`     | `ContainsString(s, substr string) bool`              | Pending | Substring check           |
| `hasPrefix`    | `HasPrefix(s, prefix string) bool`                   | Pending | Prefix check              |
| `hasSuffix`    | `HasSuffix(s, suffix string) bool`                   | Pending | Suffix check              |
| `default`      | `DefaultValue(value, defaultVal any) any`            | Pending | Default value handling    |
| `empty`        | `IsEmpty(value any) bool`                            | Pending | Empty value check         |
| `coalesce`     | `Coalesce(values ...any) any`                        | Pending | First non-empty value     |
| `ternary`      | `Ternary(condition bool, trueVal, falseVal any) any` | Pending | Conditional selection     |
| `toJson`       | `ToJSON(obj any) (string, error)`                    | Pending | JSON serialization        |
| `toPrettyJson` | `ToPrettyJSON(obj any) (string, error)`              | Pending | Pretty JSON serialization |
| `toYaml`       | `ToYAML(obj any) (string, error)`                    | Pending | YAML serialization        |

### Phase 4: Sprig Function Replacements (Medium Priority)

| Sprig Function | Go Method                           | Status  | Notes                 |
| -------------- | ----------------------------------- | ------- | --------------------- |
| `add`          | `Add(a, b int) int`                 | Pending | Arithmetic operations |
| `sub`          | `Subtract(a, b int) int`            | Pending | Arithmetic operations |
| `mul`          | `Multiply(a, b int) int`            | Pending | Arithmetic operations |
| `div`          | `Divide(a, b int) int`              | Pending | Arithmetic operations |
| `mod`          | `Modulo(a, b int) int`              | Pending | Arithmetic operations |
| `max`          | `Max(a, b int) int`                 | Pending | Maximum value         |
| `min`          | `Min(a, b int) int`                 | Pending | Minimum value         |
| `len`          | `Length(obj any) int`               | Pending | Length calculation    |
| `reverse`      | `ReverseSlice(slice any) any`       | Pending | Slice reversal        |
| `first`        | `FirstElement(slice any) any`       | Pending | First element         |
| `last`         | `LastElement(slice any) any`        | Pending | Last element          |
| `rest`         | `RestElements(slice any) any`       | Pending | All but first         |
| `initial`      | `InitialElements(slice any) any`    | Pending | All but last          |
| `uniq`         | `UniqueElements(slice any) any`     | Pending | Remove duplicates     |
| `sortAlpha`    | `SortAlphabetically(slice any) any` | Pending | Alphabetical sort     |

### Phase 4: Sprig Function Replacements (Low Priority)

| Sprig Function | Go Method                                            | Status  | Notes             |
| -------------- | ---------------------------------------------------- | ------- | ----------------- |
| `date`         | `FormatDate(format string, date time.Time) string`   | Pending | Date formatting   |
| `now`          | `CurrentTime() time.Time`                            | Pending | Current timestamp |
| `toDate`       | `ParseDate(layout, value string) (time.Time, error)` | Pending | Date parsing      |
| `ago`          | `TimeAgo(t time.Time) string`                        | Pending | Relative time     |
| `htmlEscape`   | `HTMLEscape(s string) string`                        | Pending | HTML escaping     |
| `htmlUnescape` | `HTMLUnescape(s string) string`                      | Pending | HTML unescaping   |
| `urlEscape`    | `URLEscape(s string) string`                         | Pending | URL escaping      |
| `urlUnescape`  | `URLUnescape(s string) (string, error)`              | Pending | URL unescaping    |

## Implementation Priority

### Priority 1: Critical Functions (Must implement first)

1. `EscapeTableContent` - Essential for table generation
2. `IsLastInSlice` - Required for template loop logic
3. `TruncateDescription` - Used extensively in reports
4. `ToUpper`, `ToLower` - Basic string operations
5. `TrimSpace` - Data cleanup

### Priority 2: Core Data Functions

1. `FormatInterfaceLinks` - Important for navigation
2. `FilterSystemTunables` - Security-focused filtering
3. `AssessRiskLevel` - Security assessment display
4. `DetermineSecurityZone` - Network categorization
5. String manipulation functions (`ReplaceString`, `SplitString`, `JoinStrings`)

### Priority 3: Advanced Functions

1. Placeholder security functions (when data sources available)
2. JSON/YAML serialization functions
3. Mathematical operations
4. Collection manipulation functions

### Priority 4: Nice-to-Have Functions

1. Date/time formatting beyond timestamp conversion
2. HTML/URL escaping (may not be needed for markdown)
3. Advanced collection operations

## Breaking Changes

### Template Syntax Changes

- **Template calls**: `{{ getRiskLevel .Severity }}` → **Method calls**: `builder.AssessRiskLevel(item.Severity)`
- **Sprig functions**: `{{ .Value | upper }}` → **Method calls**: `builder.ToUpper(item.Value)`
- **Pipeline operators**: No longer available, must use nested method calls

### Parameter Changes

- **Type safety**: Template functions accept `any`, Go methods use specific types
- **Error handling**: Go methods can return errors, templates silently fail
- **Context**: Template functions operate on current context, methods need explicit parameters

### Return Value Changes

- **Consistency**: All methods return consistent types
- **Error propagation**: Errors bubble up instead of silent failures
- **Type safety**: Compile-time type checking

## Migration Complexity Assessment

### Low Complexity (1-2 days each)

- Simple string operations (`ToUpper`, `ToLower`, `TrimSpace`)
- Basic formatting functions (`GetPortDescription`, `GetProtocolDescription`)
- Already implemented functions (just need integration)

### Medium Complexity (3-5 days each)

- Collection operations (`FilterSystemTunables`, `IsLastInSlice`)
- Link generation (`FormatInterfaceLinks`)
- Complex string operations (`TruncateDescription`)
- Risk assessment (`AssessRiskLevel`, `DetermineSecurityZone`)

### High Complexity (1-2 weeks each)

- Security analysis placeholders (requires external data sources)
- JSON/YAML serialization with proper error handling
- Complex collection manipulations
- Template escape sequence handling

### Very High Complexity (2-4 weeks each)

- Complete Sprig replacement (100+ functions)
- Template-to-Go code generation tooling
- Backwards compatibility layer
- Performance optimization for large configurations

## Testing Strategy

### Unit Tests

- Test each method with various input types
- Verify error handling for invalid inputs
- Compare output with current template function results

### Integration Tests

- Test method combinations in realistic scenarios
- Verify markdown output matches template-generated output
- Performance benchmarks vs template rendering

### Migration Tests

- Side-by-side comparison during migration
- Regression tests to ensure no functionality loss
- User acceptance tests for output quality

## Recommendations

1. **Start with Priority 1 functions** to establish patterns and infrastructure
2. **Create comprehensive unit tests** before migration to ensure functional equivalence
3. **Implement gradual migration** with feature flags to enable/disable programmatic generation
4. **Consider keeping some Sprig functions** for complex operations where Go replacements add little value
5. **Profile performance** to ensure Go methods are faster than template functions
6. **Document migration patterns** for future template function additions

## Notes

- **Placeholder functions** marked above need external data sources (STIG/SANS databases, compliance rules)
- **Type safety** improvements will catch errors at compile time vs runtime template failures
- **Performance** should improve significantly by eliminating template parsing overhead
- **Maintainability** will improve with explicit interfaces and dependency injection
- **Testing** becomes much easier with direct method calls vs template execution
