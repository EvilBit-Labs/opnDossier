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

| Template Function        | Go Method                                                       | Status       | Notes                                      |
| ------------------------ | --------------------------------------------------------------- | ------------ | ------------------------------------------ |
| `escapeTableContent`     | `EscapeTableContent(content any) string`                        | **Migrated** | Implemented in `markdown_utils.go` line 13 |
| `isLast`                 | `IsLastInSlice(index int, slice any) bool`                      | **Migrated** | Implemented in `markdown_utils.go` line 79 |
| `formatBoolean`          | `FormatBoolean(value any) string`                               | **Migrated** | Already exists in formatters.go            |
| `formatBooleanWithUnset` | `FormatBooleanWithUnset(value any) string`                      | **Migrated** | Already exists in formatters.go            |
| `formatUnixTimestamp`    | `FormatUnixTimestamp(timestamp string) string`                  | **Migrated** | Already exists in formatters.go            |
| `isTruthy`               | `IsTruthy(value any) bool`                                      | **Migrated** | Already exists in formatters.go            |
| `truncateDescription`    | `TruncateDescription(description string, maxLength int) string` | **Migrated** | Implemented in `markdown_utils.go` line 57 |

### Phase 2: Data Transformation Functions

| Template Function         | Go Method                                                                            | Status       | Notes                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------ | ------------ | ------------------------------------------------------------------------------------- |
| `formatInterfacesAsLinks` | `FormatInterfaceLinks(interfaces model.InterfaceList) string`                        | Pending      | Generates markdown anchor links                                                       |
| `filterTunables`          | `FilterSystemTunables(tunables []model.SysctlItem, include bool) []model.SysctlItem` | **Migrated** | Implemented in `markdown_transformers.go` line 26, includes security prefix filtering |
| `getPowerModeDescription` | `GetPowerModeDescription(mode string) string`                                        | **Migrated** | Already exists in formatters.go                                                       |
| `getPortDescription`      | `GetPortDescription(port string) string`                                             | Pending      | Simple string formatting                                                              |
| `getProtocolDescription`  | `GetProtocolDescription(protocol string) string`                                     | Pending      | Simple string formatting                                                              |

### Phase 3: Security and Compliance Functions

| Template Function        | Go Method                                                  | Status       | Notes                                         |
| ------------------------ | ---------------------------------------------------------- | ------------ | --------------------------------------------- |
| `getRiskLevel`           | `AssessRiskLevel(severity string) string`                  | **Migrated** | Implemented in `markdown_security.go` line 20 |
| `calculateSecurityScore` | `CalculateSecurityScore(data *model.OpnSenseDocument) int` | **Migrated** | Implemented in `markdown_security.go` line 42 |
| `assessServiceRisk`      | `AssessServiceRisk(service model.Service) string`          | **Migrated** | Implemented in `markdown_security.go` line 91 |
| `getSecurityZone`        | `DetermineSecurityZone(interfaceName string) string`       | Pending      | Zone classification logic                     |
| `getSTIGDescription`     | `GetSTIGControlDescription(controlID string) string`       | Pending      | **Placeholder** - needs STIG database         |
| `getSANSDescription`     | `GetSANSControlDescription(controlID string) string`       | Pending      | **Placeholder** - needs SANS database         |
| `getRuleCompliance`      | `AssessFirewallRuleCompliance(rule any) string`            | Pending      | **Placeholder** - complex analysis            |
| `getNATRiskLevel`        | `AssessNATRuleRisk(rule any) string`                       | Pending      | **Placeholder** - security assessment         |
| `getNATRecommendation`   | `GenerateNATRecommendation(rule any) string`               | Pending      | **Placeholder** - remediation advice          |
| `getCertSecurityStatus`  | `AssessCertificateSecurityStatus(cert any) string`         | Pending      | **Placeholder** - certificate analysis        |
| `getDHCPSecurity`        | `AssessDHCPSecurity(dhcp any) string`                      | Pending      | **Placeholder** - DHCP security check         |
| `getRouteSecurityZone`   | `DetermineRouteSecurityZone(route any) string`             | Pending      | **Placeholder** - route analysis              |

### Phase 4: Sprig Function Replacements (High Priority)

| Sprig Function | Go Method                                            | Status       | Notes                                       |
| -------------- | ---------------------------------------------------- | ------------ | ------------------------------------------- |
| `upper`        | `ToUpper(s string) string`                           | **Migrated** | Implemented in `markdown_utils.go` line 130 |
| `lower`        | `ToLower(s string) string`                           | **Migrated** | Implemented in `markdown_utils.go` line 135 |
| `title`        | `ToTitle(s string) string`                           | Pending      | Title case conversion                       |
| `trim`         | `TrimSpace(s string) string`                         | **Migrated** | Implemented in `markdown_utils.go` line 140 |
| `trimPrefix`   | `TrimPrefix(s, prefix string) string`                | Pending      | Prefix removal                              |
| `trimSuffix`   | `TrimSuffix(s, suffix string) string`                | Pending      | Suffix removal                              |
| `replace`      | `ReplaceString(s, old, new string) string`           | Pending      | String replacement                          |
| `split`        | `SplitString(s, sep string) []string`                | Pending      | String splitting                            |
| `join`         | `JoinStrings(elems []string, sep string) string`     | Pending      | String joining                              |
| `contains`     | `ContainsString(s, substr string) bool`              | Pending      | Substring check                             |
| `hasPrefix`    | `HasPrefix(s, prefix string) bool`                   | Pending      | Prefix check                                |
| `hasSuffix`    | `HasSuffix(s, suffix string) bool`                   | Pending      | Suffix check                                |
| `default`      | `DefaultValue(value, defaultVal any) any`            | **Migrated** | Implemented in `markdown_utils.go` line 93  |
| `empty`        | `IsEmpty(value any) bool`                            | **Migrated** | Implemented in `markdown_utils.go` line 101 |
| `coalesce`     | `Coalesce(values ...any) any`                        | Pending      | First non-empty value                       |
| `ternary`      | `Ternary(condition bool, trueVal, falseVal any) any` | Pending      | Conditional selection                       |
| `toJson`       | `ToJSON(obj any) (string, error)`                    | Pending      | JSON serialization                          |
| `toPrettyJson` | `ToPrettyJSON(obj any) (string, error)`              | Pending      | Pretty JSON serialization                   |
| `toYaml`       | `ToYAML(obj any) (string, error)`                    | Pending      | YAML serialization                          |

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

### Phase 5: Advanced Data Operations

| Template Function       | Go Method                                                                    | Status       | Notes                                              |
| ----------------------- | ---------------------------------------------------------------------------- | ------------ | -------------------------------------------------- |
| `groupServicesByStatus` | `GroupServicesByStatus(services []model.Service) map[string][]model.Service` | **Migrated** | Implemented in `markdown_transformers.go` line 77  |
| `aggregatePackageStats` | `AggregatePackageStats(packages []model.Package) map[string]int`             | **Migrated** | Implemented in `markdown_transformers.go` line 120 |
| `filterRulesByType`     | `FilterRulesByType(rules []model.Rule, ruleType string) []model.Rule`        | **Migrated** | Implemented in `markdown_transformers.go` line 164 |
| `extractUniqueValues`   | `ExtractUniqueValues(items []string) []string`                               | **Migrated** | Implemented in `markdown_transformers.go` line 203 |

### Phase 6: Report Building Methods

| Template Function          | Go Method                                                                | Status       | Notes                                 |
| -------------------------- | ------------------------------------------------------------------------ | ------------ | ------------------------------------- |
| `buildSystemSection`       | `BuildSystemSection(data *model.OpnSenseDocument) string`                | **Migrated** | Implemented in `markdown.go` line 222 |
| `buildNetworkSection`      | `BuildNetworkSection(data *model.OpnSenseDocument) string`               | **Migrated** | Implemented in `markdown.go` line 369 |
| `buildSecuritySection`     | `BuildSecuritySection(data *model.OpnSenseDocument) string`              | **Migrated** | Implemented in `markdown.go` line 436 |
| `buildServicesSection`     | `BuildServicesSection(data *model.OpnSenseDocument) string`              | **Migrated** | Implemented in `markdown.go` line 481 |
| `buildStandardReport`      | `BuildStandardReport(data *model.OpnSenseDocument) (string, error)`      | **Migrated** | Implemented in `markdown.go` line 695 |
| `buildComprehensiveReport` | `BuildComprehensiveReport(data *model.OpnSenseDocument) (string, error)` | **Migrated** | Implemented in `markdown.go` line 751 |

## Implementation Priority

### Completed Functions

The following functions have been successfully migrated and are available for use:

**Phase 1: Core Utility Functions**

- ✅ `EscapeTableContent` - Essential for table generation
- ✅ `IsLastInSlice` - Required for template loop logic
- ✅ `TruncateDescription` - Used extensively in reports
- ✅ `ToUpper`, `ToLower` - Basic string operations
- ✅ `TrimSpace` - Data cleanup
- ✅ `DefaultValue` - Default value handling
- ✅ `IsEmpty` - Empty value check

**Phase 2: Data Transformation Functions**

- ✅ `FilterSystemTunables` - Security-focused filtering

**Phase 3: Security and Compliance Functions**

- ✅ `AssessRiskLevel` - Security assessment display
- ✅ `CalculateSecurityScore` - Overall security scoring
- ✅ `AssessServiceRisk` - Service risk assessment

**Phase 5: Advanced Data Operations**

- ✅ `GroupServicesByStatus` - Service grouping
- ✅ `AggregatePackageStats` - Package statistics
- ✅ `FilterRulesByType` - Rule filtering
- ✅ `ExtractUniqueValues` - Unique value extraction

**Phase 6: Report Building Methods**

- ✅ `BuildSystemSection` - System section generation
- ✅ `BuildNetworkSection` - Network section generation
- ✅ `BuildSecuritySection` - Security section generation
- ✅ `BuildServicesSection` - Services section generation
- ✅ `BuildStandardReport` - Standard report generation
- ✅ `BuildComprehensiveReport` - Comprehensive report generation

**Total**: 30+ methods now available for programmatic generation.

### Priority 2: Core Data Functions (Remaining)

1. `FormatInterfaceLinks` - Important for navigation
2. `DetermineSecurityZone` - Network categorization
3. String manipulation functions (`ReplaceString`, `SplitString`, `JoinStrings`)

### Priority 3: Advanced Functions (Remaining)

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

### Completed (30+ Functions)

The following functions have been successfully migrated and are production-ready:

**Low Complexity (Completed)**

- ✅ Simple string operations (`ToUpper`, `ToLower`, `TrimSpace`)
- ✅ Basic utility functions (`EscapeTableContent`, `IsLastInSlice`, `TruncateDescription`)
- ✅ Default value handling (`DefaultValue`, `IsEmpty`)

**Medium Complexity (Completed)**

- ✅ Collection operations (`FilterSystemTunables`, `GroupServicesByStatus`)
- ✅ Complex string operations (`TruncateDescription`)
- ✅ Risk assessment (`AssessRiskLevel`, `CalculateSecurityScore`, `AssessServiceRisk`)
- ✅ Data aggregation (`AggregatePackageStats`, `FilterRulesByType`, `ExtractUniqueValues`)

**High Complexity (Completed)**

- ✅ Report building methods (`BuildSystemSection`, `BuildNetworkSection`, `BuildSecuritySection`, `BuildServicesSection`)
- ✅ Complete report generation (`BuildStandardReport`, `BuildComprehensiveReport`)

### Remaining Work

**Low Complexity (1-2 days each)**

- Basic formatting functions (`GetPortDescription`, `GetProtocolDescription`)
- Additional string operations (`TrimPrefix`, `TrimSuffix`)

**Medium Complexity (3-5 days each)**

- Link generation (`FormatInterfaceLinks`)
- Network categorization (`DetermineSecurityZone`)
- String manipulation (`ReplaceString`, `SplitString`, `JoinStrings`)

**High Complexity (1-2 weeks each)**

- Security analysis placeholders (requires external data sources)
- JSON/YAML serialization with proper error handling
- Complex collection manipulations

**Very High Complexity (2-4 weeks each)**

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
