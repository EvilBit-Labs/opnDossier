# Requirements Document

## Introduction

This specification defines the requirements for implementing snapshot testing capabilities in opnDossier using the go-snaps library. Snapshot testing will replace existing tests that rely on string parsing and provide automated regression testing for CLI output and generated reports, ensuring consistent output formatting and content across code changes. This enhancement will improve the testing strategy by capturing and validating complete output structures instead of fragile string-based assertions.

## Requirements

### Requirement 1: CLI Command Output Snapshot Testing

**User Story:** As a developer, I want to capture and validate CLI command output using snapshot tests, so that I can detect unintended changes in command behavior and output formatting.

#### Acceptance Criteria

1. WHEN CLI commands are executed in tests THEN the system SHALL capture complete output using go-snaps for comparison
2. WHEN snapshot tests run THEN the system SHALL validate command output against stored snapshots with automatic diff reporting
3. WHEN CLI output changes THEN the system SHALL provide clear diff visualization showing exactly what changed
4. WHEN new CLI features are added THEN the system SHALL support creating new snapshots with `go test -update` flag
5. WHEN snapshot tests fail THEN the system SHALL provide actionable error messages with instructions for updating snapshots

### Requirement 2: Generated Report Content Validation

**User Story:** As a developer, I want to validate generated markdown, JSON, and YAML reports using snapshot testing, so that I can ensure report content consistency and catch formatting regressions.

#### Acceptance Criteria

1. WHEN reports are generated THEN the system SHALL capture complete report content for snapshot comparison
2. WHEN report templates change THEN the system SHALL detect content differences through snapshot validation
3. WHEN audit findings are generated THEN the system SHALL validate finding structure and content through snapshots
4. WHEN different output formats are used THEN the system SHALL maintain separate snapshots for markdown, JSON, and YAML outputs
5. WHEN report generation logic changes THEN the system SHALL provide detailed diffs showing content modifications

### Requirement 3: Plugin Output Validation

**User Story:** As a developer, I want to validate compliance plugin outputs using snapshot tests, so that I can ensure plugin findings remain consistent and detect changes in compliance rule logic.

#### Acceptance Criteria

1. WHEN compliance plugins execute THEN the system SHALL capture plugin findings and recommendations for snapshot comparison
2. WHEN plugin logic changes THEN the system SHALL detect differences in finding generation through snapshot validation
3. WHEN new compliance rules are added THEN the system SHALL support creating snapshots for new finding types
4. WHEN plugin configurations change THEN the system SHALL validate that findings remain consistent through snapshot testing
5. WHEN multiple plugins run THEN the system SHALL capture combined audit results for comprehensive validation

### Requirement 4: Cross-Platform Output Consistency

**User Story:** As a developer, I want to ensure CLI output consistency across different platforms, so that users have the same experience regardless of their operating system.

#### Acceptance Criteria

1. WHEN tests run on different platforms THEN the system SHALL normalize platform-specific differences (path separators, line endings)
2. WHEN file paths are included in output THEN the system SHALL use consistent path representation in snapshots
3. WHEN timestamps are included THEN the system SHALL provide mechanisms to normalize or mock time-dependent output
4. WHEN platform-specific features are tested THEN the system SHALL support conditional snapshot validation
5. WHEN cross-platform tests run THEN the system SHALL maintain separate snapshots only when platform differences are expected

### Requirement 5: Test Data Management and Organization

**User Story:** As a developer, I want well-organized snapshot files and test data, so that I can easily maintain and understand snapshot test coverage.

#### Acceptance Criteria

1. WHEN snapshot files are created THEN the system SHALL organize them in a clear directory structure matching test organization
2. WHEN test data is needed THEN the system SHALL use consistent sample OPNsense configurations from testdata/ directory
3. WHEN snapshots are updated THEN the system SHALL provide clear naming conventions that indicate test purpose and scope
4. WHEN snapshot tests are added THEN the system SHALL include documentation explaining the test coverage and expected behavior
5. WHEN snapshot files grow large THEN the system SHALL provide mechanisms to split or organize complex snapshots

### Requirement 6: Migration from String-Based Testing

**User Story:** As a developer, I want to replace existing string parsing tests with snapshot tests, so that I can eliminate fragile string-based assertions and improve test reliability.

#### Acceptance Criteria

1. WHEN existing tests use string parsing THEN the system SHALL identify and replace them with snapshot-based validation
2. WHEN string assertions are found THEN the system SHALL convert them to comprehensive snapshot comparisons
3. WHEN output validation is needed THEN the system SHALL use snapshot testing instead of substring matching or regex patterns
4. WHEN test maintenance is required THEN the system SHALL provide more reliable snapshot-based tests than brittle string parsing
5. WHEN test failures occur THEN the system SHALL provide clearer failure information through snapshot diffs than string comparison errors

### Requirement 7: Integration with Existing Test Suite

**User Story:** As a developer, I want snapshot tests to integrate seamlessly with the existing test suite, so that they run as part of the standard testing workflow without disrupting current practices.

#### Acceptance Criteria

1. WHEN snapshot tests are added THEN the system SHALL integrate with existing table-driven test patterns
2. WHEN `just test` is executed THEN the system SHALL run snapshot tests alongside existing unit and integration tests
3. WHEN CI/CD pipeline runs THEN the system SHALL include snapshot test validation in the quality gates
4. WHEN test coverage is calculated THEN the system SHALL include snapshot tests in coverage reporting
5. WHEN tests fail THEN the system SHALL provide consistent error reporting format with other test types

### Requirement 8: Performance and Maintainability

**User Story:** As a developer, I want snapshot tests to be fast and maintainable, so that they don't slow down the development workflow or become a maintenance burden.

#### Acceptance Criteria

1. WHEN snapshot tests execute THEN the system SHALL complete individual tests in less than 100ms to maintain fast feedback
2. WHEN large outputs are captured THEN the system SHALL provide efficient storage and comparison mechanisms
3. WHEN snapshots become outdated THEN the system SHALL provide clear guidance on when and how to update them
4. WHEN snapshot files are committed THEN the system SHALL ensure they are readable and reviewable in version control
5. WHEN snapshot tests are maintained THEN the system SHALL provide tooling to clean up unused or obsolete snapshots

### Requirement 9: Error Handling and Debugging Support

**User Story:** As a developer, I want clear error messages and debugging support for snapshot tests, so that I can quickly identify and resolve test failures.

#### Acceptance Criteria

1. WHEN snapshot comparisons fail THEN the system SHALL provide detailed diff output showing exactly what changed
2. WHEN snapshot files are missing THEN the system SHALL provide clear instructions for creating initial snapshots
3. WHEN snapshot tests fail in CI THEN the system SHALL provide actionable error messages for remote debugging
4. WHEN debugging snapshot issues THEN the system SHALL support verbose output modes for detailed comparison information
5. WHEN snapshot content is invalid THEN the system SHALL provide validation errors with specific line and character information
