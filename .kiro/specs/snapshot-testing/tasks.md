# Implementation Plan

## Phase 1: Core Infrastructure Setup

- [ ] 1. Add go-snaps dependency and basic integration

  - Add `github.com/gkampitakis/go-snaps` to go.mod
  - Create basic snapshot test helper utilities in `internal/testing/`
  - Set up snapshot file organization structure in `testdata/snapshots/`
  - _Requirements: 1.1, 1.2, 5.1, 5.3_

- [ ] 2. Implement command output capture mechanism

  - Create `CommandOutput` struct to capture stdout, stderr, exit code, and duration
  - Implement `CaptureCommandOutput` function for CLI command execution
  - Add support for input redirection and environment variable control
  - _Requirements: 1.1, 1.4_

- [ ] 3. Create cross-platform output normalization utilities

  - Implement path separator normalization (Windows \\ to Unix /)
  - Add line ending normalization (\\r\\n to \\n)
  - Create timestamp normalization for time-dependent output
  - Implement `NormalizeOutput` function with configurable options
  - _Requirements: 4.1, 4.2, 4.3_

## Phase 2: CLI Command Snapshot Testing

- [ ] 4. Replace convert command string-based tests with snapshots

  - Convert existing tests in `cmd/convert_test.go` from string parsing to snapshot validation
  - Create snapshots for markdown, JSON, and YAML output formats
  - Add test cases for different configuration scenarios using existing testdata files
  - Implement table-driven snapshot tests with parallel execution
  - _Requirements: 1.1, 1.2, 1.3, 6.1, 6.2_

- [ ] 5. Replace display command string-based tests with snapshots

  - Convert display command tests to use snapshot validation
  - Create snapshots for terminal output with different themes and styling
  - Add test cases for various display options and formatting
  - Validate consistent styling and formatting across different scenarios
  - _Requirements: 1.1, 1.2, 6.1, 6.2_

- [ ] 6. Replace validate command string-based tests with snapshots

  - Create snapshots for validation success and error cases
  - Replace existing error message string comparisons with snapshot validation
  - Add comprehensive validation scenario coverage using testdata configurations
  - Ensure consistent error reporting format across different validation failures
  - _Requirements: 1.1, 1.2, 6.1, 6.2_

## Phase 3: Report Generation Snapshot Testing

- [ ] 7. Implement markdown report snapshot validation

  - Replace template-based string tests with comprehensive snapshot validation
  - Create snapshots for standard, blue team, and red team report formats
  - Add test cases for different audit modes and comprehensive reporting options
  - Validate report structure, content consistency, and formatting
  - _Requirements: 2.1, 2.2, 2.4_

- [ ] 8. Create JSON/YAML export snapshot tests

  - Implement snapshots for structured data exports (JSON and YAML formats)
  - Replace existing JSON parsing and validation tests with snapshot comparison
  - Add comprehensive export format coverage for all configuration sections
  - Ensure data integrity and consistency across format conversions
  - _Requirements: 2.1, 2.4_

- [ ] 9. Add template rendering consistency validation

  - Create snapshots for template rendering with different data inputs
  - Test template inheritance and composition through snapshot validation
  - Validate custom template function registration and usage
  - Ensure consistent template output across different configuration scenarios
  - _Requirements: 2.2, 2.4_

## Phase 4: Plugin Output Validation

- [ ] 10. Implement compliance plugin snapshot testing

  - Create snapshots for STIG, SANS, and Firewall plugin outputs
  - Replace existing finding validation string tests with snapshot comparison
  - Add comprehensive plugin scenario coverage using different configuration inputs
  - Validate finding structure, content consistency, and severity mappings
  - _Requirements: 3.1, 3.2, 3.4_

- [ ] 11. Add audit result integration snapshot tests

  - Create snapshots for combined audit results from multiple plugins
  - Test plugin interaction and finding aggregation through snapshot validation
  - Validate audit report generation with plugin findings integration
  - Ensure consistent audit output formatting and finding prioritization
  - _Requirements: 3.1, 3.5_

- [ ] 12. Implement plugin configuration validation snapshots

  - Create snapshots for plugin configuration validation and error handling
  - Test plugin metadata and registration through snapshot comparison
  - Validate plugin lifecycle management and error recovery
  - Ensure consistent plugin behavior across different configuration scenarios
  - _Requirements: 3.3, 3.4_

## Phase 5: Integration and Migration

- [ ] 13. Migrate integration tests to snapshot-based validation

  - Convert `integration_test.go` string-based assertions to snapshot tests
  - Replace `assert.Contains` and `strings.Contains` patterns with snapshot validation
  - Add comprehensive end-to-end workflow coverage through snapshots
  - Maintain existing test behavior while improving reliability
  - _Requirements: 6.1, 6.2, 6.3, 7.1, 7.2_

- [ ] 14. Implement snapshot test organization and management

  - Create clear directory structure for snapshot files matching test organization
  - Implement snapshot metadata tracking with version and creation information
  - Add documentation explaining test coverage and expected behavior
  - Create utilities for snapshot cleanup and maintenance
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 15. Add error handling and debugging support for snapshot tests

  - Implement detailed diff output for snapshot comparison failures
  - Create clear error messages with actionable instructions for snapshot updates
  - Add verbose output modes for detailed comparison information
  - Implement validation for snapshot content integrity and format
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

## Phase 6: Performance and Quality Assurance

- [ ] 16. Optimize snapshot test performance

  - Ensure individual snapshot tests complete in less than 100ms
  - Implement efficient storage and comparison mechanisms for large outputs
  - Add parallel test execution where safe (using `t.Parallel()`)
  - Create performance benchmarks for snapshot comparison operations
  - _Requirements: 8.1, 8.2_

- [ ] 17. Integrate snapshot tests with existing CI/CD pipeline

  - Ensure snapshot tests run as part of `just test` and `just ci-check`
  - Add snapshot test validation to GitHub Actions workflow
  - Include snapshot tests in coverage reporting and quality gates
  - Provide consistent error reporting format with other test types
  - _Requirements: 7.2, 7.3, 7.4, 7.5_

- [ ] 18. Create snapshot test maintenance tooling and documentation

  - Implement tooling for updating snapshots when output legitimately changes
  - Create clear guidance on when and how to update snapshots
  - Add documentation for snapshot test maintenance and best practices
  - Ensure snapshot files are readable and reviewable in version control
  - _Requirements: 8.3, 8.4, 8.5_

## Phase 7: Final Validation and Cleanup

- [ ] 19. Remove obsolete string-based tests and cleanup

  - Remove original string-based tests after snapshot validation is complete
  - Clean up unused test utilities and helper functions
  - Update test documentation and examples to reflect snapshot testing approach
  - Ensure no regression in test coverage after migration
  - _Requirements: 6.3, 6.4_

- [ ] 20. Comprehensive snapshot test coverage validation

  - Verify all CLI commands have comprehensive snapshot test coverage
  - Ensure all report generation paths are covered by snapshot tests
  - Validate all plugin outputs have appropriate snapshot validation
  - Add missing test cases identified during implementation
  - Run complete test suite validation with `just ci-check`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
