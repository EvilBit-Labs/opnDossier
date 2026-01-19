# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### 🧹 Cleanup

- Remove stubbed audit mode CLI code and documentation (deferred to v2.1; see [#174](https://github.com/EvilBit-Labs/opnDossier/issues/174))

## [1.0.0] - 2025-08-04

### 🚀 Features

- *(security)* Add security policy documentation

  - Introduced a new SECURITY.md file outlining the security policy, supported versions, vulnerability reporting process, responsible disclosure guidelines, and security best practices for opnFocus.
  - Documented security features and provided contact information for security-related inquiries.

- *(templates)* Add issue and pull request templates

  - Introduced a new issue template for bug reports, feature requests, documentation issues, and general issues, providing a structured format for users to report problems and suggestions.
  - Added a pull request template to guide contributors in providing clear descriptions, change types, related issues, testing procedures, and documentation updates.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(config)* Add new sample configuration files for OPNsense

  - Introduced `sample.config.6.xml` and `sample.config.7.xml` files containing comprehensive configurations for OPNsense, including system settings, interface configurations, and firewall rules.
  - The new configurations enhance the setup process and provide examples for various network setups.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add support for including system tunables in report generation

  - Introduced a new CLI flag `--include-tunables` to allow users to include system tunables in the output report.
  - Implemented a filtering function to conditionally include or exclude tunables based on their values.
  - Updated report templates to display tunables correctly when the flag is set.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add initial configuration for CodeRabbit integration

  - Introduced a new configuration file `.coderabbit.yaml` to set up CodeRabbit features and settings.
  - Configured various options including auto review, chat integrations, and code generation settings.
  - Enabled multiple linting tools and pre-merge checks to enhance code quality and review processes.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Implement embedded template functionality and testing

  - Added support for embedding templates in the binary using Go's embed package, allowing the application to access templates even when filesystem templates are missing.
  - Created tests to validate the embedded templates functionality, ensuring templates are accessible and correctly loaded.
  - Updated the markdown package to utilize embedded templates, enhancing the template management system.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Enhance build tests for embedded templates

  - Introduced a new test suite for validating the functionality of the binary with embedded templates, ensuring proper execution and accessibility.
  - Updated existing tests to utilize the new suite structure, improving organization and maintainability.
  - Disabled specific linters in the configuration to address compatibility issues with cobra commands.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add opnsense configuration DTD and update XSD schema

  - Introduced a new DTD file for opnsense configuration, defining the structure and elements for XML configuration files.
  - Updated the XSD schema to reflect changes in the configuration structure, including the addition of new elements and attributes.
  - Removed deprecated elements and adjusted sequences to improve validation accuracy.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Enhance display options and add new utility functions

  - Updated `buildDisplayOptions` to handle special template formats (json, yaml) by setting the format instead of the template name.
  - Introduced new utility functions in `markdown/formatters.go` for boolean formatting and power mode descriptions.
  - Updated template function map in `markdown/generator.go` to include new formatting functions.
  - Adjusted various model fields to use integer types for better consistency and validation.
  - Updated templates to utilize new formatting functions for improved output consistency.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add GitHub Actions workflow testing commands for Unix and Windows

  - Introduced `act-workflow` commands in the `justfile` for testing GitHub Actions workflows on both Unix and Windows platforms.
  - Added error handling to check for the presence of the `act` command and provide installation instructions if not found.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add utility functions for boolean evaluation and formatting

  - Introduced `IsTruthy`, `FormatBoolean`, and `FormatBooleanWithUnset` functions to evaluate truthy values and format boolean representations.
  - Added comprehensive unit tests for each function to ensure correct behavior across various input cases.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Refactor command flags and shared functionality for convert and display commands

  - Consolidated shared flags for template, sections, theme, and wrap width into a new `shared_flags.go` file to reduce duplication.
  - Updated the `convert` and `display` commands to utilize shared flags, improving maintainability.
  - Disabled audit mode functionality temporarily, with appropriate comments and error handling in place.
  - Enhanced test coverage for flag validation and command behavior.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Enhance release process and documentation

  - Updated .gitignore to include GoReleaser and packaging artifacts for improved project cleanliness.
  - Enhanced .goreleaser.yaml to automate generation of shell completions and man pages, and added support for new package formats.
  - Introduced RELEASING.md to document the release process, including prerequisites, validation steps, and version tagging.
  - Added completion and man commands to the CLI for generating shell completions and man pages.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### 🐛 Bug Fixes

- *(display)* Remove validation from display command by default

  - Change display command to use Parse() instead of ParseAndValidate() by default
  - Display command now only ensures XML can be unmarshalled into data model
  - Full configuration quality validation remains in validate command only
  - Update help text and flag descriptions to reflect new behavior
  - Fixes issue #29 where display command incorrectly ran validation

  This change allows display command to work with production configurations
  that may have inconsistencies but are still valid for operating firewalls.

- *(migration)* Update module path instructions in migration.md

  - Changed the command for updating the `go.mod` file's module path from a sed command to Go's official `go mod edit` command for improved safety.
  - Ensured clarity in the migration instructions for updating import paths in Go files.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Update issue template and installation guide

  - Modified the issue template to escape the Just version comment for clarity.
  - Added a ConfigMap example and a Job example in the installation guide for Kubernetes, enhancing documentation for users.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(templates)* Update formatting for system notes in OPNsense report template

  - Changed code block syntax for system notes to use `text` for better clarity.
  - Updated fallback message for no system notes to maintain consistent formatting.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Simplify markdown test assertions by removing ANSI stripping

  - Removed the ANSI stripping function and adjusted assertions to work directly with markdown output, leveraging the `TERM=dumb` environment variable for consistent test results.
  - Updated test cases to check for formatted output with bold labels for better clarity.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Enhance config test assertions and output path handling

  - Updated the temporary config file creation in `TestLoadConfigPrecedence` to use a valid output path.
  - Adjusted assertions to verify the correct output file path based on the new configuration.
  - Improved error message validation in `TestFileExporter` tests to account for platform-specific behavior.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(validate)* Display all validation errors instead of just the first one

  - Update AggregatedValidationError.Error() to show all validation errors with numbered list
  - Modify validate command to properly display all validation issues for each file
  - Update tests to match new error message format
  - Fixes issue #32 where only first validation error was shown

- Standardize MTU field naming in VPN model and templates

  - Changed the MTU field in the WireGuardServerItem struct from lowercase to uppercase for consistency.
  - Updated the corresponding template to reflect the new field naming convention.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Standardize PSK field naming in VPN model and templates

  - Changed the PSK field in the WireGuardClientItem struct from lowercase to uppercase for consistency.
  - Updated the corresponding template to reflect the new field naming convention.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Improve number parsing in IsTruthy function

  - Refactored the number parsing logic in the IsTruthy function to simplify the handling of both integer and float values.
  - Updated comments for clarity regarding truthy evaluation of numbers.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update directory permissions and timestamp formatting

  - Changed the output directory permissions from 0o750 to 0o755 for broader access.
  - Updated timestamp conversion in `FormatUnixTimestamp` to use `float64(time.Second)` for improved clarity.
  - Enhanced the template to conditionally display revision fields, ensuring proper handling of empty values.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update logging methods and documentation

  - Deprecated `GetLogLevel` and `GetLogFormat` methods in the config package, replacing them with logic based on verbose and quiet flags.
  - Updated the `man.go` file to include a comment regarding the required permissions for man pages.
  - Removed outdated examples from the troubleshooting documentation and updated commands to reflect new logging practices.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(release)* Remove GO_VERSION dependency and add mdformat to changelog generation

### 🚜 Refactor

- Remove JSON and YAML template files and update related functionality

  - Deleted unused `json_output.tmpl` and `yaml_output.tmpl` files to streamline template management.
  - Updated the `generateJSON` and `generateYAML` methods to use direct marshaling instead of templates, simplifying the output generation process.
  - Adjusted tests to reflect the removal of templates and updated expected values accordingly.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Simplify opnsense-config XSD schema by removing deprecated elements

  - Removed multiple deprecated optional elements from the opnsense-config XSD schema to streamline the configuration structure.
  - Introduced a new `xs:any` element to allow for additional interface names, enhancing flexibility for DHCP configuration.
  - Updated the schema to reflect standard/reserved interface names while maintaining support for custom naming.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### 📚 Documentation

- Fix changelog format for v1.0.0 release
- Finalize changelog for v1.0.0 release
- Format changelog for v1.0.0 release

### ⚙️ Miscellaneous Tasks

- *(ci)* Refactor CI configuration and enhance testing workflow

  - Renamed CI workflow from `ci-check` to `CI` for clarity and consistency.
  - Consolidated testing steps into a single job with a matrix strategy for Go versions and OS platforms.
  - Added a new `test-coverage` command in the Justfile to run tests with coverage reporting.
  - Removed obsolete `ci.yml` file to streamline CI configuration.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(ci)* Add golangci-lint setup to CI workflow

  - Integrated golangci-lint into the CI workflow for improved code quality checks.
  - Configured the action to use the latest version for consistency.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(justfile)* Add full-checks command to streamline CI process

  - Introduced a new `full-checks` command to run all checks, tests, and release validation in a single step.
  - Updated the Justfile to include a call to `ci-check` and `check-goreleaser` for comprehensive validation.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(workflow)* Remove summary workflow for issue summarization

  - Deleted the `.github/workflows/summary.yml` file, which contained a GitHub Actions workflow for summarizing new issues.
  - This change cleans up the repository by removing an unused workflow.

  No tests were affected by this change.

- *(ci)* Simplify Go version matrix in CI workflow

  - Removed the specific Go version `1.24` from the CI workflow matrix, retaining only `stable` for testing.
  - This change streamlines the CI configuration and focuses on the latest stable Go version.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(workflow)* Remove summary workflow for issue summarization

  - Deleted the `.github/workflows/summary.yml` file, which contained a GitHub Actions workflow for summarizing new issues.
  - This change cleans up the repository by removing an unused workflow.

  No tests were affected by this change.

- *(ci)* Simplify Go version matrix in CI workflow

  - Removed the specific Go version `1.24` from the CI workflow matrix, retaining only `stable` for testing.
  - This change streamlines the CI configuration and focuses on the latest stable Go version.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add MIGRATION IN-PROGRESS notice to README.md
  Temporarily freeze development during repository migration

- Update compliance and project documentation for opnDossier

  - Added comprehensive compliance standards documentation, including guidelines for compliance framework, audit engine architecture, and testing requirements.
  - Updated project structure and naming conventions to reflect the transition from opnFocus to opnDossier.
  - Revised documentation to ensure consistency across all project files and improve clarity.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Rename project from opnFocus to opnDossier and update documentation

  - Updated project name and references from opnFocus to opnDossier across documentation and configuration files.
  - Enhanced CoPilot instructions to reflect new project structure and guidelines.
  - Adjusted CI workflow for new build outputs and Go version matrix.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update documentation to reflect project name change to opnDossier

  - Renamed all instances of opnFocus to opnDossier in requirements, tasks, and user stories documentation.
  - Ensured consistency across all project documentation to align with the new project name.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update project references and configurations for opnDossier

  - Renamed all instances of opnFocus to opnDossier across various configuration files, documentation, and codebase.
  - Updated .gitignore, .golangci.yml, .goreleaser.yaml, and other relevant files to reflect the new project name and structure.
  - Added new XML schema for OPNsense configurations in testdata.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update documentation and configuration for opnDossier

  - Replaced all instances of `OPNFOCUS` with `OPNDOSSIER` in various documentation files, including CONTRIBUTING.md, DEVELOPMENT_STANDARDS.md, and README.md.
  - Updated environment variable references and configuration management details to reflect the new naming convention.
  - Ensured consistency across all project documentation and examples.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update report templates to reflect project name change to opnDossier

  - Replaced instances of opnFocus with opnDossier in opnsense_report_comprehensive.md.tmpl and opnsense_report.md.tmpl.
  - Ensured consistency in the generated output across both report templates.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Rename project references from opnFocus to opnDossier

  - Updated all instances of `opnFocus` to `opnDossier` across the codebase, including module names, test files, and comments.
  - Ensured consistency in naming conventions throughout the project to reflect the new branding.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add CI and CodeQL badges to README.md

  - Included CI and CodeQL badges in the README.md to enhance visibility of the project's continuous integration and code quality checks.
  - This update improves the documentation by providing immediate feedback on the project's build status and security analysis.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add CodeRabbit Pull Request Reviews badge to README.md

  - Included a new badge for CodeRabbit Pull Request Reviews in the README.md to enhance visibility of code review processes.
  - This update improves the documentation by providing additional context for contributors regarding code review practices.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update .gitignore and justfile for improved coverage reporting

  - Enhanced .gitignore to include additional Go build artifacts, coverage files, and system-specific files for better project cleanliness.
  - Updated justfile to streamline coverage testing commands and ensure consistent usage of coverage.txt.
  - Modified CI workflow to use the latest version of the Codecov action and updated coverage report handling.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update CI workflow and justfile for testing improvements

  - Removed coverage testing command from `justfile` and replaced it with a standard test command.
  - Added a new job in the CI workflow to run tests and collect coverage, including setup steps for Go and Codecov integration.
  - Deleted the obsolete `lint_report.json` file to clean up the repository.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update CI workflow to run tests across all packages

  - Modified the CI workflow to run tests for all Go packages by changing the test command to `go test -coverprofile=coverage.txt ./...`.
  - This change enhances test coverage reporting and ensures all packages are tested during the CI process.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update release workflow to include main branch

  - Added the main branch to the release workflow triggers, ensuring that releases are initiated on pushes to the main branch as well as version tags.
  - This change enhances the flexibility of the release process.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update .coderabbit.yaml configuration

  - Modified tone instructions to emphasize Go best practices, security for CLI tools, and offline-first capabilities.
  - Updated auto title instructions to enforce conventional commit format.
  - Disabled several linting tools to streamline the review process, including ruff, markdownlint, and various others.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update CI configuration and enable GitHub checks

  - Enabled GitHub checks in .coderabbit.yaml to enhance review process.
  - Simplified Go version specification in ci-check.yml by setting it to stable, removing the matrix strategy for Go versions.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

## [1.0.0-rc1] - 2025-08-01

### 🚀 Features

- Enhance XMLParser with security features and input size limit

  - Added MaxInputSize field to XMLParser to limit XML input size and prevent XML bombs.
  - Implemented security measures in the Parse method to disable external entity loading and DTD processing, mitigating XXE attacks.
  - Updated NewXMLParser to initialize MaxInputSize with a default value.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Implement basic xml parsing functionality for opnsense configuration files

- *(core)* Migrate to fang config and structured logging

- *(logging)* Enhance logger initialization with error handling and validation

  - Updated logger creation to return errors for invalid configurations, improving robustness.
  - Added validation for log levels and formats, ensuring only valid options are accepted.
  - Revised tests to cover new error handling scenarios and validate logger behavior.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(config)* Enhance configuration management and error handling

  - Updated `initConfig` function to return errors for failed config file reads, improving error handling.
  - Added logging for successful config loading and handling of missing config files.
  - Revised documentation to reflect changes in configuration command flags and examples.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(validation)* Introduce comprehensive validation feature for configuration integrity

  - Added a new validation feature that enhances configuration integrity by validating against rules and constraints.
  - The feature is automatically applied during parsing or can be explicitly initiated via CLI, with detailed output examples available in the README.
  - Updated the `justfile` to include new benchmark commands for performance testing.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(validation)* Implement comprehensive validation system for configuration integrity

  - Introduced a structured validation system with core components including `ValidationError` and `AggregatedValidationReport`.
  - Added field-specific and cross-field validation patterns to ensure configuration integrity.
  - Enhanced CLI commands to support validation during configuration processing.
  - Updated documentation to reflect new validation features and usage examples.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(config)* Add sample configuration files for OPNsense

  - Introduced three new sample configuration files: `sample.config.1.xml`, `sample.config.2.xml`, and `sample.config.3.xml`.
  - Each file contains various system settings, network interfaces, and firewall rules to demonstrate OPNsense configuration capabilities.
  - The configurations include detailed descriptions for sysctl tunables, user and group settings, and load balancer monitor types.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(converter)* Add JSON conversion support and enhance output handling

  - Implemented a new JSONConverter for converting OPNsense configurations to JSON format.
  - Updated the convert command to handle multiple output formats (markdown, JSON) based on user input.
  - Enhanced error handling and logging during the conversion process.
  - Removed the deprecated sample-report.md file.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(templates)* Add comprehensive OPNsense report templates

  - Introduced two new markdown templates: `opnsense_report_analysis.md` for analyzing template fields and their mappings to model properties, and `opnsense_report_comprehensive.md.tmpl` for generating a detailed configuration summary.
  - The analysis template includes sections for various components such as interfaces, firewall rules, NAT rules, and missing properties, while the comprehensive template provides a structured overview of system configurations, interfaces, firewall rules, and more.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(todos)* Add TODO comments for addressing minor gaps in OPNsense analysis

  - Introduced a new `TODO_MINOR_GAPS.md` file documenting enhancements needed for rule comparison, destination analysis, service integration, and compliance checks.
  - Added specific TODO comments in `internal/processor/analyze.go`, `internal/model/opnsense.go`, and `internal/processor/example.go` to guide future development efforts.
  - The changes aim to improve accuracy in rule detection, enhance firewall analysis, and ensure compliance with enterprise requirements.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tasks)* Mark XML parser and validation tasks as complete

  - Updated the status of multiple tasks related to XML processing, including the XML parser interface, OPNsense schema validation, streaming XML processing, and configuration processor interface, to indicate completion.
  - Refactored the OPNsense struct for better organization, ensuring improved hierarchy preservation for configuration data models.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tasks)* Update markdown generator tasks with enhanced context

  - Refactored the context for TASK-011 to clarify that a markdown generator is already implemented and requires updates to align with the enhanced model and configuration representation.
  - Updated TASK-013 context to specify the use of templates from `internal/templates` for improved markdown formatting and styling.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Enhance AGENTS.md and DEVELOPMENT_STANDARDS.md with new features and structure

  - Updated AGENTS.md to include multi-format export capabilities and detailed validation features, enhancing documentation clarity.
  - Revised DEVELOPMENT_STANDARDS.md to improve organization, including a new section on development environment setup and updated commit message conventions.
  - Added comprehensive markdown generation and output requirements to project_spec/requirements.md, ensuring alignment with new features.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Implement comprehensive markdown generation for opnsense configurations
  This commit implements a complete markdown generation system for OPNsense
  configurations with the following key features:

  Core Features:

  - Full markdown generation from OPNsense XML configurations
  - Comprehensive coverage of System, Network, Security, and Service configs
  - Structured output with proper markdown formatting and tables
  - Enhanced terminal display with theme support and syntax highlighting

- *(markdown)* Introduce new markdown generation and formatting capabilities

  - Added a new `internal/markdown` package for comprehensive markdown generation from OPNsense configurations.
  - Implemented a modular generator architecture with reusable formatting helpers and enhanced template support.
  - Updated existing markdown generation functions to utilize the new generator, ensuring backward compatibility.
  - Enhanced tests for markdown generation, including integration tests for various configuration scenarios.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(testdata)* Replace config.xml with opnfocus-config.xsd and add sample configurations

  - Deleted the outdated `config.xml` file and replaced it with `opnfocus-config.xsd`, which defines the schema for OPNsense configurations.
  - Added multiple sample configuration files (`sample.config.1.xml`, `sample.config.4.xml`, `sample.config.5.xml`) to demonstrate various settings and features.
  - Introduced a README.md file to document the purpose and usage of the test data files.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(opnsense)* Update dependencies and enhance model completeness checks

  - Updated `go.mod` and `go.sum` to reflect new versions of dependencies, including `bubbletea`, `color`, `mimetype`, and `olekukonko` packages.
  - Added a new `completeness-check` target in the `justfile` to validate the completeness of the OPNsense model against XML configurations.
  - Introduced `completeness_test.go` and `completeness.go` to ensure all XML elements are represented in the Go model.
  - Created `common.go` for shared data structures and utilities across the model.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Refactor OPNsense model and enhance documentation

  - Renamed `Opnsense` to `OpnSenseDocument` across the codebase for consistency and clarity.
  - Updated related tests and validation functions to reflect the new model name.
  - Added a note in `AGENTS.md` emphasizing the preference for well-maintained third-party libraries over custom solutions.
  - Introduced new model structures for certificates, high availability, and interfaces to improve completeness.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Refactor WebGUI and related structures for consistency

  - Updated the `Webgui` field to `WebGUI` across the codebase for uniformity.
  - Refactored related structures in the `System` model to use inline struct definitions for `WebGUI` and `SSH`.
  - Adjusted tests and validation functions to reflect the new structure and naming conventions.
  - Enhanced the handling of `Bogons` and other related configurations for improved clarity.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(documentation)* Add comprehensive model completeness tasks for OPNsense

  - Introduced a new `MODEL_COMPLETENESS_TASKS.md` file outlining prioritized tasks to address 1,145 missing fields identified in the OPNsense Go model.
  - Documented implementation strategy, success metrics, and guidelines for code quality and testing requirements.
  - Structured the document to focus on core system functionality, security, network, and advanced features.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Extend SysctlItem and APIKey structures with additional fields

  - Added `Key` and `Secret` fields to the `SysctlItem` struct for enhanced configuration options.
  - Introduced new fields in the `APIKey` struct, including `Privileges`, `Priv`, `Scope`, `UID`, `GID`, and timestamps for creation and modification.
  - Updated the `Firmware` struct to include `Type`, `Subscription`, and `Reboot` fields for improved model completeness.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Add debug model paths test for completeness validation

  - Introduced `TestDebugModelPaths` in `completeness_test.go` to log and validate expected model paths against the actual paths retrieved from the Go model.
  - Updated `GetModelCompletenessDetails` in `completeness.go` to strip the "opnsense." prefix from XML paths for accurate comparison with model paths.
  - Enhanced `getModelPaths` to handle slices and arrays in addition to structs and pointers.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(github)* Add Dependabot configuration and CodeQL analysis workflow

  - Introduced a Dependabot configuration file to automate dependency updates for Go modules and GitHub Actions on a weekly and daily schedule.
  - Added a CodeQL analysis workflow to perform security scanning on the main branch and pull requests, scheduled to run weekly.
  - Created a release workflow to automate the release process using GoReleaser upon tagging.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Enhance completeness checks and extend model structures

  - Updated `CheckModelCompleteness` to strip the "opnsense." prefix from XML paths for accurate comparison with model paths.
  - Enhanced `getModelPaths` to include version and UUID attributes for top-level elements and nested struct fields.
  - Introduced new `Widgets` struct for dashboard configuration in the `System` model.
  - Updated `Options` struct to make fields optional and improved documentation for `WireGuardServerItem` and `WireGuardClientItem`.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Remove MODEL_COMPLETENESS_TASKS.md and update model structures

  - Deleted the `MODEL_COMPLETENESS_TASKS.md` file as it is no longer needed.
  - Updated `completeness.go` to handle complex XML tags and improve path generation.
  - Introduced `BridgesConfig` struct in `interfaces.go` for better bridges configuration representation.
  - Modified `OPNsense` struct in `opnsense.go` to use `BridgesConfig` and added new fields for DHCP and Netflow configurations.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(dependencies)* Update Go module dependencies and improve markdown generator

  - Added several indirect dependencies in `go.mod` including `mergo`, `goutils`, `semver`, `sprig`, `uuid`, `xstrings`, `copystructure`, `reflectwalk`, and `decimal`.
  - Updated `go.sum` to reflect the new dependencies and their checksums.
  - Refactored the markdown generator to utilize functions from the `sprig` library, enhancing template functionality.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Implement document enrichment and enhance markdown generation

  - Added `EnrichDocument` function to enrich `OpnSenseDocument` with calculated fields, statistics, and analysis data.
  - Updated `markdownGenerator` to utilize the enriched model for generating output in JSON and YAML formats.
  - Introduced new `EnrichedOpnSenseDocument` struct to hold additional data for reporting.
  - Added comprehensive tests for the enrichment functionality to ensure correctness.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(cleanup)* Remove unused markdown.py and opnsense.py files, update .editorconfig

  - Deleted the `markdown.py` and `opnsense.py` files as they are no longer needed in the project.
  - Updated `.editorconfig` to maintain consistent whitespace handling by ensuring trailing whitespace is not trimmed.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(refactor)* Update types to use `any` and enhance markdown generation

  - Changed function signatures and struct fields across multiple files to use `any` instead of `interface{}` for improved type handling.
  - Added new `modernize` and `modernize-check` commands in the `justfile` for code modernization checks.
  - Updated markdown templates to include additional fields for better reporting.
  - Refactored benchmark tests to utilize `b.Loop()` for improved performance measurement.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(model)* Enhance System and User structs with additional fields

  - Added `Notes` field to the `System` struct for additional configuration information.
  - Introduced `Disabled` field to the `User` struct to indicate user status.
  - Updated markdown report template to reflect changes in user status and system notes.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Add tests for display functionality and progress handling

  - Introduced multiple tests for the `TerminalDisplay` including scenarios for displaying raw markdown with and without colors, and handling progress events.
  - Added a sentinel error `ErrRawMarkdown` to indicate when raw markdown should be displayed.
  - Enhanced the `DisplayWithProgress` method to properly handle goroutine synchronization and prevent leaks.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tasks)* Mark TASK-014 as completed for terminal display implementation

  - Updated the status of **TASK-014** in the tasks documentation to indicate completion of the terminal display implementation using glamour.
  - Context and requirements for the task remain unchanged.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(display)* Add theme support for terminal display

  - Introduced a new `displayTheme` variable to allow users to specify a theme (light, dark, auto, none) for the terminal display.
  - Updated the `generateMarkdown` function to return raw markdown, delegating theme handling to the display package.
  - Enhanced the terminal display creation to support explicit theme selection or auto-detection.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(display)* Enhance display command with customizable options

  - Added new flags for `displayTemplate`, `displaySections`, and `displayWrapWidth` to the display command for improved customization.
  - Updated the `buildDisplayOptions` function to handle new options and prioritize command-line flags over configuration settings.
  - Modified markdown generation to support customizable templates and section filtering.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(user_stories)* Add new user stories for recon report and audits

  - Introduced user stories US-046, US-047, and US-048 for generating recon reports and defensive audits from OPNsense config.xml files.
  - Defined specific requirements and expected outcomes for red team, blue team, and neutral summary modes.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(display)* Enhance terminal display tests and functionality

  - Updated `TestDisplayWithANSIWhenColorsEnabled` to improve content verification, allowing for both ANSI codes and rendered content.
  - Added new tests for theme detection, theme properties, and terminal capability detection to ensure proper handling of light and dark themes.
  - Introduced `DetermineGlamourStyle` and `IsTerminalColorCapable` functions to streamline theme and color capability checks.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(user_stories)* Expand acceptance criteria for analyze command modes

  - Added acceptance criteria for the `analyze` command with modes: `red`, `blue`, and `summary`, detailing expected outputs and validation requirements.
  - Ensured consistent output format across all modes and included error handling for invalid mode flags.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(config)* Add template validation in configuration

  - Implemented validation for the `Template` field in the configuration, ensuring that the specified template can be loaded successfully. If loading fails, an appropriate validation error is appended.
  - This enhancement improves the robustness of configuration handling by preventing invalid templates from being used.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(enrichment)* Add dynamic interface counting and analysis tests

  - Introduced `TestDynamicInterfaceCounting` and `TestDynamicInterfaceAnalysis` to validate the counting and analysis of network interfaces in the configuration.
  - Enhanced the `generateStatistics` function to dynamically generate interface statistics, improving accuracy and maintainability.
  - Refactored related functions for better modularity and clarity in statistics generation.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(reports)* Add markdown templates for blue, red, and standard audit reports

  - Introduced `blue.md.tmpl`, `red.md.tmpl`, and `standard.md.tmpl` for generating audit reports in different modes.
  - Each template includes structured sections for findings, recommendations, and configuration details tailored to the respective report type.
  - Enhanced the project to support multi-mode report generation as specified in requirements F016, F018, and F019.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Add comprehensive markdown export validation tests

  - Introduced multiple tests for validating markdown export functionality, including checks for valid markdown content, absence of terminal control characters, and actual exported file validation against acceptance criteria for TASK-017.
  - Enhanced the `TestFileExporter_Export` function and added new tests: `TestFileExporter_MarkdownValidation`, `TestFileExporter_NoTerminalControlCharacters`, and `TestFileExporter_ActualExportedFile`.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Add JSON export validation tests

  - Introduced new tests for validating JSON export functionality, including checks for valid JSON content, absence of terminal control characters, and actual exported JSON file validation against acceptance criteria for TASK-018.
  - Added `TestFileExporter_JSONValidation`, `TestFileExporter_NoTerminalControlCharactersJSON`, and `TestFileExporter_ActualExportedJSONFile` to ensure compliance with export requirements.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Add YAML export validation tests

  - Introduced new tests for validating YAML export functionality, including checks for valid YAML content, absence of terminal control characters, and actual exported YAML file validation against acceptance criteria for TASK-019.
  - Added `TestFileExporter_YAMLValidation`, `TestFileExporter_NoTerminalControlCharactersYAML`, and `TestFileExporter_ActualExportedYAMLFile` to ensure compliance with export requirements.
  - Refactored existing tests to utilize a helper function for locating the test configuration file.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(markdown)* Implement JSON and YAML template-based export functionality

  - Refactored `generateJSON` and `generateYAML` methods to utilize templates for output generation, enhancing flexibility and maintainability.
  - Updated JSON and YAML templates to include additional fields and structured data for better representation of the opnSense model.
  - Marked TASK-019 as complete in project tasks documentation.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(output)* Implement output file naming and overwrite protection

  - Added `determineOutputPath` function to handle output file naming with smart defaults and overwrite protection.
  - Introduced tests for `determineOutputPath` to validate various scenarios, including handling existing files and ensuring no automatic directory creation.
  - Updated the `convert` command to utilize the new output path determination logic and added a `--force` flag for overwriting files without prompt.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(export)* Enhance file export functionality with comprehensive validation and error handling

  - Added new error handling for empty content and path validation, including checks for path traversal attacks and directory existence.
  - Implemented atomic file writing to ensure safe file operations.
  - Introduced multiple tests to validate error handling and path validation scenarios, ensuring compliance with TASK-021 requirements.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Implement comprehensive validation tests for exported files

  - Added tests to validate exported files for markdown, JSON, and YAML formats, ensuring they are parseable by standard tools and libraries.
  - Implemented `TestFileExporter_StandardToolValidation`, `TestFileExporter_LibraryValidation`, and `TestFileExporter_CrossPlatformValidation` to cover various validation scenarios.
  - Marked TASK-021a as complete in project tasks documentation.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(markdown)* Implement escapeTableContent function for markdown templates

  - Added `escapeTableContent` function to sanitize table cell content in markdown templates, preventing formatting issues with special characters.
  - Updated markdown templates to utilize the new function for escaping pipe and newline characters in descriptions.
  - Enhanced user input handling in `determineOutputPath` to improve overwrite confirmation prompts.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(compliance)* Implement plugin-based architecture for compliance standards

  - Removed the deprecated mcp.json file and added new compliance documentation files, including audit-engine.mdc, compliance-standards.mdc, go-standards.mdc, plugin-architecture.mdc, project-structure.mdc, and others to define compliance standards and guidelines.
  - Established a plugin-based architecture for compliance checks, allowing for dynamic registration and management of compliance plugins.
  - Enhanced documentation for plugin development and compliance standards integration, ensuring clarity and usability for developers.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Enhance compliance and core concepts documentation

  - Added multi-format export and validation guidelines in `compliance-standards.mdc`, detailing support for markdown, JSON, and YAML formats.
  - Introduced core philosophy principles in `core-concepts.mdc`, emphasizing operator-focused design and offline-first capabilities.
  - Updated Go version requirements in `go-standards.mdc` and added data processing standards for multi-format export and validation.
  - Enhanced project structure documentation in `project-structure.mdc` to clarify source code organization.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Update requirements and tasks for audit report generation

  - Revised requirements in `requirements.md` to enhance clarity and consistency for audit report generation modes (standard, blue, red) and their respective features.
  - Updated `tasks.md` to reflect changes in acceptance criteria for markdown generation, terminal display, and file export tasks, ensuring alignment with new requirements.
  - Added error handling, validation features, and smart file naming for export tasks, improving robustness.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Update AI agent guidelines and add development workflow documentation

  - Modified `ai-agent-guidelines.mdc` to separate linting and formatting commands for clarity.
  - Introduced new `development-workflow.mdc` to outline comprehensive development processes, including pre-development checklists, implementation steps, and quality assurance practices.
  - Added `documentation-consistency.mdc` and `requirements-management.mdc` to establish guidelines for maintaining documentation consistency and managing project specifications.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(convert)* Enhance conversion command with audit report generation capabilities

  - Added new flags for audit mode, including `--mode`, `--blackhat-mode`, `--comprehensive`, and `--plugins` to support various report types.
  - Implemented `handleAuditMode` function to generate reports based on selected audit modes (standard, blue, red).
  - Updated command documentation to reflect new features and usage examples for audit report generation.
  - Refactored markdown generator initialization to accept a logger for improved logging capabilities.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(audit)* Enhance audit report generation and validation logging

  - Updated `handleAuditMode` to include a plugin registry for improved report generation.
  - Enhanced markdown options validation to log warnings on invalid inputs instead of silently ignoring them.
  - Modified markdown templates to use the correct firmware version and last revision time fields.
  - Added tests for validation logging to ensure proper handling of invalid options.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Expand tasks for opnFocus CLI tool implementation

  - Added a comprehensive release roadmap for the opnFocus CLI tool, detailing tasks and features for versions 1.0, 1.1, and 1.2.
  - Included critical tasks for the v1.0 release, such as refactoring CLI command structure, implementing a help system, and ensuring test coverage.
  - Outlined major features for future versions, focusing on audit reports and performance enhancements.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Mark TASK-030 as complete for CLI command structure refactor

  - Updated tasks.md to reflect the completion of TASK-030, which involved refactoring the CLI command structure to use proper Cobra patterns.
  - Added a note confirming that the CLI structure is fully implemented with an intuitive command organization and a comprehensive help system.
  - Ensured all related commands (convert, display, validate) are functioning correctly.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(cli)* Enhance command flag organization and documentation

  - Refactored command flag setup in `convert.go` and `display.go` for improved clarity and usability, including better descriptions and annotations for each flag.
  - Added comprehensive help text and examples for the `convert` and `display` commands, enhancing user guidance on available options and workflows.
  - Implemented mutual exclusivity for certain flags to prevent conflicting configurations, improving command reliability.
  - Updated tests to ensure proper flag validation and command behavior.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Mark TASK-032 as complete for verbose/quiet output modes

  - Updated tasks.md to reflect the completion of TASK-032, which involved adding verbose and quiet output modes to the CLI tool.
  - Enhanced documentation to clarify the context and requirements for output level control.
  - Ensured all related command functionalities are working as intended.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Mark TASK-035 as complete for YAML configuration file support

  - Updated tasks.md to reflect the completion of TASK-035, which involved implementing YAML configuration file support.
  - Added a note detailing the integration with Viper, precedence handling, validation, and documentation.
  - Ensured all quality checks pass successfully.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Add changelog and git-cliff configuration

  - Introduced CHANGELOG.md to document all notable changes to the project.
  - Added cliff.toml for git-cliff configuration to automate changelog generation.
  - Updated justfile to include installation and usage instructions for git-cliff.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Mark TASK-035 as complete for YAML configuration file support

  - Updated tasks.md to reflect the completion of TASK-035, confirming the implementation of YAML configuration file support.
  - Ensured all related documentation is accurate and up-to-date.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Add comprehensive environment variable tests for configuration loading

  - Introduced multiple test cases in `config_test.go` to validate loading of configuration from environment variables, covering all fields including boolean, integer, and slice types.
  - Ensured proper handling of various representations for boolean values and tested empty slice scenarios.
  - Updated tasks.md to mark TASK-036 as complete, confirming full implementation of environment variable support with extensive test coverage.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Mark TASK-037 as complete for CLI flag override system

  - Updated tasks.md to reflect the completion of TASK-037, confirming the implementation of the CLI flag override system.
  - Added a note detailing the comprehensive precedence handling and extensive test coverage for the new feature.
  - Ensured all quality checks pass successfully.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Enhance audit mode tests and add plugin registry functionality

  - Added comprehensive tests for converting audit modes to report modes and creating mode configurations in `convert_test.go`.
  - Implemented mock compliance plugin for testing plugin registry functionalities in `mode_controller_test.go`.
  - Enhanced report generation methods in `mode_controller.go` to include detailed metadata analysis.
  - Updated `plugin.go` to prevent duplicate plugin registration.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(ci)* Add CI workflow for comprehensive checks and testing

  - Introduced a new CI workflow (`ci-check.yml`) to automate checks on push and pull request events, including dependency installation, running tests, and uploading coverage reports.
  - Updated existing CI workflow (`ci.yml`) to enhance testing and quality checks, including pre-commit checks, security scans, and modernize checks.
  - Ensured compatibility with Go version 1.24 and added support for multiple operating systems.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Update README and add comprehensive documentation examples

  - Enhanced the README.md to include a v1.0 release section, detailing features and installation instructions.
  - Added multiple documentation examples covering advanced configurations, audit and compliance workflows, automation, and troubleshooting.
  - Created new example files for basic documentation, advanced configurations, audit compliance, and automation scripting.
  - Updated existing documentation to improve clarity and usability, ensuring all examples are practical and immediately usable.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(goreleaser)* Enhance multi-platform build configuration and add Docker support

  - Updated `.goreleaser.yaml` to include FreeBSD as a target OS and refined ldflags for versioning and commit information.
  - Introduced Dockerfile for building the opnFocus image and added Docker support in GoReleaser configuration.
  - Enhanced `justfile` with new commands for building and releasing snapshots and full releases.
  - Updated `.gitignore` to exclude the `dist/` directory and marked TASK-060 as complete in `tasks.md`, confirming comprehensive GoReleaser configuration.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(release)* Enable automated release process on tag pushes

  - Updated `.github/workflows/release.yml` to trigger the release workflow on git tag pushes matching 'v\*'.
  - Marked TASK-063 as complete in `tasks.md`, confirming the implementation of the automated release process with GoReleaser.
  - Added detailed notes on the release management features, including multi-platform builds and Docker support.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### 🐛 Bug Fixes

- Format markdown files to pass pre-commit checks

- *(logging)* Update logging output and enhance Kubernetes configuration documentation

  - Changed logging output from `enhancedLogger.Info(md)` to `fmt.Print(md)` for direct stdout output.
  - Added clarification in the Kubernetes section of the installation guide regarding configuration file mounting and usage of the `--config` flag.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(requirements)* Update gofmt reference to golangci-lint

  - Changed the reference from `gofmt` to `golangci-lint` in the requirements document to reflect the correct tool for formatting and linting.
  - Updated the acceptance criteria for the markdown generator task to specify that it converts all XML files in the `testdata/` directory.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Correct formatting and content in AGENTS.md, DEVELOPMENT_STANDARDS.md, and README.md

  - Adjusted formatting in AGENTS.md for consistency in the Data Model section.
  - Improved table structure and clarity in DEVELOPMENT_STANDARDS.md.
  - Removed an unnecessary blank line in README.md to enhance readability.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Align indentation in completeness_test.go for consistency

  - Adjusted the indentation of the loop iterating over XML files in `completeness_test.go` to maintain consistent formatting.
  - Ensured readability and adherence to project style guidelines.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Update display tests to use context for improved handling

  - Modified display test cases to pass `context.Background()` instead of `nil` to the `Display` and `DisplayWithProgress` methods, enhancing context management.
  - Ensured goroutine synchronization and proper error handling in tests.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Update plugin architecture and firewall reference documentation

  - Corrected the directory path for built-in plugin implementations in `plugin-architecture.mdc`.
  - Updated the DNS rebind check control from "Disable" to "Enable" in `cis-like-firewall-reference.md` to reflect accurate configuration.
  - Added import statement for `fmt` in the static plugin example within `plugin-development.md`.
  - Enhanced error messages in `errors.go` for clarity and added comments for better understanding.
  - Introduced comprehensive tests for the STIG plugin in `stig_test.go`, covering various compliance checks and logging configurations.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Resolve remaining testifylint issues

  - Replace assert.ErrorIs/ErrorAs with require.ErrorIs/ErrorAs for error assertions that must stop test execution
  - Replace assert.Equal with assert.InDelta for float comparison in display_test.go
  - Remove useless assert.True(t, true, ...) in analyze_test.go and replace with proper documentation log
  - Ensure all error assertions use require when test must stop on error

- *(cli)* Update command flag requirements and task status

  - Removed mutual exclusivity between "mode" and "template" flags in `convert.go`, allowing them to be used together.
  - Marked TASK-053 as complete in `tasks.md`, confirming verification of offline operation with no external dependencies.
  - Added a note on the successful verification of complete offline operation through comprehensive testing.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### 🚜 Refactor

- Update struct field names in opnsense model for consistency

  - Renamed struct fields in `opnsense.go` to follow Go naming conventions, improving clarity and consistency across the codebase.
  - Updated corresponding test assertions in `xml_test.go` to reflect the new field names.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(display)* Streamline command definitions and enhance terminal display handling

  - Consolidated variable declarations for `noValidation` and command definitions for `displayCmd` and `validateCmd`.
  - Introduced a constant for `DefaultWordWrapWidth` to improve maintainability in terminal display settings.
  - Enhanced error handling in `NewTerminalDisplay` to ensure a fallback renderer is created if the primary fails.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update docstrings for clarity and consistency across multiple files

  - Enhanced documentation comments in `cmd/display.go`, `internal/display/display.go`, `internal/model/completeness.go`, `internal/model/enrichment.go`, `internal/processor/example_usage.go`, `internal/processor/report.go`, and `internal/validator/opnsense.go` to improve clarity and maintainability.
  - Removed redundant comments and ensured consistency in formatting.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(display)* Update terminal display initialization to use options

  - Modified the terminal display initialization in `cmd/display.go` to utilize a new options structure for theme configuration, enhancing flexibility and maintainability.
  - Replaced direct theme assignment with the use of `DefaultOptions()` to set the theme.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Simplify command retrieval in convert tests

  - Updated `findCommand` function to remove the name parameter, hardcoding the "convert" command lookup for consistency across tests.
  - Adjusted all related test cases to reflect this change, ensuring they still validate command initialization and flags correctly.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Replace inline structs with configuration types in OPNsense tests

  - Updated `WebGUI` and `SSH` fields in `System` struct to use `WebGUIConfig` and `SSHConfig` types for improved clarity and maintainability.
  - This change simplifies the test setup and enhances the readability of the test cases.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(display)* Replace theme string literals with constants in display package

  - Updated theme-related string literals in `display.go`, `display_test.go`, and `theme.go` to use constants for improved maintainability and consistency.
  - Enhanced context handling in `Display` and `DisplayWithProgress` methods to check for cancellation before processing.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(markdown)* Optimize configuration content detection in formatters

  - Removed inline regex patterns from `isConfigContent` function and replaced them with pre-compiled regex variables for improved performance and readability.
  - This change enhances the clarity of the configuration content detection logic.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(processor)* Enhance CoreProcessor initialization and improve MDNode documentation

  - Updated `NewCoreProcessor` to return an error if the markdown generator cannot be created, improving error handling.
  - Modified tests to handle the new error return from `NewCoreProcessor`, ensuring robust test cases.
  - Enhanced documentation for `MDNode` struct to clarify its purpose and fields.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### 📚 Documentation

- Add project configuration files and documentation for OPNsense CLI tool

  - Introduced .cursorrules for development standards and guidelines.
  - Added .editorconfig, .gitattributes, and .golangci.yml for project configuration.
  - Created .goreleaser.yaml for release management.
  - Included .markdownlint-cli2.jsonc and .mdformat.toml for markdown formatting.
  - Established .pre-commit-config.yaml for pre-commit hooks.
  - Updated README.md with project overview and installation instructions.
  - Added documentation files for project structure and usage.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update project documentation and configuration files for opnFocus

  - Removed .cursorrules file as it was no longer needed.
  - Added node_modules/ to .gitignore to prevent tracking of dependencies.
  - Updated .markdownlint-cli2.jsonc for improved markdown linting rules.
  - Modified .mdformat.toml to exclude additional markdown files.
  - Enhanced .pre-commit-config.yaml with new hooks for commit linting and markdown formatting.
  - Created new documentation files including architecture and requirements for better project clarity.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Enhance project documentation for opnFocus

  - Added related documentation section in AGENTS.md, linking to requirements, architecture, and development standards.
  - Updated requirements.md to remove checkboxes and improve readability.
  - Included additional resources in AGENTS.md for comprehensive project understanding.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update project documentation and structure for opnFocus

  - Updated AGENTS.md to reflect the new path for the requirements document and improved project structure clarity.
  - Added project_spec/requirements.md to serve as the comprehensive requirements document for the opnFocus CLI tool.
  - Enhanced DEVELOPMENT_STANDARDS.md to reference the new requirements document location.
  - Created project_spec/tasks.md and project_spec/user_stories.md to outline implementation tasks and user stories.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update documentation and formatting for opnFocus

  - Improved formatting in AGENTS.md and DEVELOPMENT_STANDARDS.md for better readability.
  - Updated README.md with correct documentation links and installation instructions.
  - Added a new README.md in internal/parser/testdata/ for parser test data organization.
  - Enhanced project_spec/requirements.md and tasks.md with clearer structure and context.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Standardize configuration formatting and update documentation

  - Removed quotes from configuration values in README and user guide for consistency.
  - Updated table formatting in documentation for better readability.
  - Revised examples to reflect the new configuration style across multiple documents.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tasks)* Mark TASK-004 and TASK-005 as completed (#4)

- *(CONTRIBUTING)* Add comprehensive contributing guide

  - Introduced a new `CONTRIBUTING.md` file detailing prerequisites, development setup, architecture overview, coding standards, and the pull request process.
  - The guide aims to streamline contributions and ensure adherence to project standards.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add comprehensive Copilot instructions for opnFocus project

- *(validator)* Clean up comment formatting in `demo.go`

  - Removed unnecessary whitespace in comments for improved readability.
  - Updated the comment above `DemoValidation` to maintain consistency with project documentation style.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(CONTRIBUTING)* Standardize commit message formatting in guidelines

  - Updated commit message examples in `CONTRIBUTING.md` to use consistent double quotes instead of escaped quotes.
  - Adjusted import statements to follow standard formatting conventions.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(validator)* Add package-level comments to `opnsense.go`

  - Introduced comprehensive comments to the `opnsense.go` file, detailing the validation functionality for OPNsense configuration files.
  - The comments cover validation of system settings, network interfaces, DHCP server configuration, firewall rules, NAT rules, user and group settings, and sysctl tunables.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update requirements and user stories documents to include Table of Contents

  - Added a Table of Contents section to both `requirements.md` and `user_stories.md` for improved navigation.
  - Replaced the previous manual list in `requirements.md` with a simplified `[TOC]` placeholder.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(requirements)* Clarify report generation modes and template usage

  - Updated the requirements documentation to specify the location of report templates for the blue, red, and standard modes.
  - Added references to `internal/templates/reports/` for better guidance on template-driven Markdown output.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update mapping table with issue #26 for Phase 4.3 tasks (TASK-023-TASK-029)

- Update AGENTS.md and add migration.md for project transition

  - Expanded AGENTS.md with new sections on data processing, data model, and report presentation standards.
  - Introduced migration.md detailing steps for transitioning the repository to a new path and updating project metadata.
  - Removed tasks_vs_issues.md as part of project cleanup.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(migration)* Enhance migration.md with detailed steps for repository transition

  - Added steps for freezing development, updating Go module path, renaming the binary, and updating project metadata.
  - Included instructions for updating repository URLs and configuration files to reflect the new branding.
  - Ensured clarity and completeness of the migration process for transitioning to the new repository.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(configuration)* Improve JSON formatting in configuration.md for clarity

  - Reformatted JSON examples in configuration.md to enhance readability and maintainability.
  - Ensured consistent indentation and structure for better understanding of log aggregation formats.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(migration)* Expand migration.md with detailed commands for repository transition

  - Added specific commands for updating the Go module path, repository URLs, and binary name in the migration process.
  - Included verification steps to ensure all changes were applied correctly across relevant files.
  - Enhanced clarity and completeness of the migration instructions for transitioning to the new repository.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tasks)* Reorganize input validation task in project_spec/tasks.md

  - Moved the comprehensive input validation task (TASK-022) to the correct section under audit report generation for better clarity and organization.
  - Ensured all relevant details regarding input validation requirements and acceptance criteria are retained.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tasks)* Mark TASK-024 as complete for multi-mode report controller

  - Updated the status of TASK-024 in `project_spec/tasks.md` to indicate completion of the multi-mode report controller implementation.
  - Ensured the context and requirements for the task remain clear and intact.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### 🧪 Testing

- *(tests)* Remove module_files_test.go due to redundancy

  - Deleted the `module_files_test.go` file as it was deemed redundant.
  - No tests were affected as the file was not referenced elsewhere.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(tests)* Remove markdown_spec_test.go due to redundancy

  - Deleted the `markdown_spec_test.go` file as it was deemed redundant.
  - No tests were affected as the file was not referenced elsewhere.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(errors)* Add unit tests for AggregatedValidationError functionality

  - Introduced tests for error message formatting, type matching, and error presence in `AggregatedValidationError`.
  - Enhanced the `Is` method for better error matching logic in `ParseError`, `ValidationError`, and `AggregatedValidationError`.
  - Updated the benchmark comment in `xml_test.go` for accuracy.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

### ⚙️ Miscellaneous Tasks

- Update golangci-lint configuration and justfile for opnFocus

  - Enhanced .golangci.yml with additional linters, settings, and configurations for improved code quality checks.
  - Modified justfile to update project name, streamline development commands, and improve formatting and linting processes.
  - Added new format and format-check targets to ensure consistent code formatting.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update golangci-lint settings and enhance justfile for opnFocus

  - Added module path and extra rules to the golangci-lint configuration in .golangci.yml for improved linting.
  - Removed the check-ast hook from .pre-commit-config.yaml to streamline pre-commit checks.
  - Refactored justfile to improve environment setup for both Windows and Unix, added new commands for installation, cleaning, and building.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update dependencies and refactor opnFocus CLI structure

  - Upgraded Go version to 1.24.0 and updated toolchain to 1.24.5.
  - Replaced several dependencies with newer versions, including charmbracelet libraries for improved functionality.
  - Introduced a new `convert` command for processing OPNsense configuration files into Markdown format.
  - Refactored `main.go` to utilize the new command structure and improved error handling.
  - Removed the outdated `opnsense.go` file and added configuration management and parsing functionalities.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update module path in go.mod for opnFocus

  - Changed module path from `opnFocus` to `github.com/unclesp1d3r/opnFocus` for consistency with repository structure.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update import paths to use the new module structure

  - Changed import paths from `opnFocus` to `github.com/unclesp1d3r/opnFocus` across multiple files for consistency with the updated module path.
  - Added additional test cases in `markdown_test.go` to handle nil input and empty struct scenarios.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update .gitignore and refactor justfile for environment setup

  - Added 'site/' to .gitignore to exclude site-related files from version control.
  - Refactored justfile to streamline virtual environment setup and command execution for both Windows and Unix systems.
  - Updated commands to use dynamic paths for Python and MkDocs based on the operating system.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add @commitlint/config-conventional dependency for commit message linting

  - Updated package.json and package-lock.json to include @commitlint/config-conventional as a devDependency.
  - This addition enhances commit message validation by using conventional commit standards.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update dependencies and .gitignore for improved project structure

  - Added 'vendor/' to .gitignore to exclude vendor directory from version control.
  - Updated dependencies in go.mod to newer versions for improved functionality and security.
  - Removed redundant go mod tidy command from justfile to streamline dependency management.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add CI workflow for golangci-lint

  - Introduced a new GitHub Actions workflow to run golangci-lint on push and pull request events.
  - Configured the workflow to run on multiple operating systems: Ubuntu, macOS, and Windows.

  Tested with `just ci-check`, all checks passed successfully.

- Remove wsl_v5 linter from golangci configuration

  - Removed the 'wsl_v5' linter from the golangci-lint configuration to streamline the linting process.
  - This change helps in reducing unnecessary checks that may not be relevant to the current project setup.

  Tested with `just ci-check`, all checks passed successfully.

- Update golangci-lint version in CI workflow

  - Updated golangci-lint version from v2.1 to v2.3 in the CI workflow configuration to leverage the latest features and improvements.

  Tested with `just ci-check`, all checks passed successfully.

- Update configuration management documentation and code

  - Revised configuration management details in multiple documents to clarify the standard precedence order for configuration sources.
  - Updated code comments and tests to reflect the new configuration handling using `spf13/viper`.
  - Removed redundant vendor command from the justfile to streamline dependency management.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Streamline environment setup in justfile

  - Removed the redundant `just use-venv` command from the setup-env section of the justfile to simplify the virtual environment setup process.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update configuration management and CLI enhancement documentation

  - Revised documentation to reflect the transition from `charmbracelet/fang` to `spf13/viper` for configuration management.
  - Added details about `charmbracelet/fang` for enhanced CLI experience in multiple files.
  - Updated `.gitignore` to include `opnFocus`.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Update dependabot configuration and release workflow

  - Changed the package-ecosystem format in `.github/dependabot.yml` to use quotes for consistency and updated the schedule interval from daily to weekly.
  - Modified the release workflow in `.github/workflows/release.yml` to use the `goreleaser/goreleaser-action@v5.0.0` for better integration and added arguments for a clean release.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Remove outdated OPNsense model update documentation

  - Deleted the `opnsense_model_update.md` file, which contained design details for updating OPNsense configuration models.
  - This document is no longer relevant to the current project scope and has been removed to maintain clarity in the documentation.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- Add initial project configuration files for Go development

  - Created `.idea/golinter.xml` to configure Go linter settings with a custom config file.
  - Added `.idea/modules.xml` to manage project modules, linking to the `opnFocus.iml` module file.
  - Introduced `.idea/opnFocus.iml` for module configuration, enabling Go support and defining content roots.
  - Established `.idea/vcs.xml` for version control settings, mapping the project directory to Git.

  These files set up the development environment for Go projects within the IDE.

- Remove opnsense report analysis template

  - Deleted the `opnsense_report_analysis.md` template file, which contained detailed mappings and analysis of template fields to model properties.
  - This removal is part of a cleanup effort to streamline the documentation and focus on relevant templates.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(rules)* Remove deprecated container-use rules documentation

  - Deleted the `container-use.mdc` file, which contained outdated guidelines for containerized development operations.
  - This change helps streamline the documentation by removing unnecessary content.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(docs)* Remove AI agent guidelines and update core concepts and workflow documentation

  - Deleted `ai-agent-guidelines.mdc` to streamline documentation and remove outdated content.
  - Enhanced `core-concepts.mdc` with updated rule precedence and added sections on data processing patterns and technology stack.
  - Expanded `development-workflow.mdc` to include AI agent mandatory practices and a code review checklist for improved clarity and compliance.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(lint)* Update golangci-lint configuration and remove gap analysis documentation

  - Added new linters and updated settings in `.golangci.yml` for improved code quality checks.
  - Removed `gap_analysis_table.md` as it contained outdated content and was no longer relevant to the project.
  - Adjusted exclusions and formatter settings to enhance linting performance.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(lint)* Update golangci-lint configuration for improved code quality

  - Removed `gochecknoinits` and adjusted settings for `cyclop`, `funlen`, and `gocognit` to enhance linting effectiveness.
  - Disabled `gocyclo` in favor of `cyclop` and temporarily disabled `shadow` checks to prioritize other issues.
  - Updated `allow-no-explanation` formatting for consistency.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(cleanup)* Remove obsolete configuration and documentation files

  - Deleted `.mdformat.toml` exclusions for markdown formatting, simplifying the configuration.
  - Removed `config.xml.sample` and `TODO_IMPLEMENTATION_ISSUES.md` files as they are no longer relevant to the project.
  - Updated CI workflow by removing the quality checks job to streamline the build process.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(cleanup)* Remove obsolete GoReleaser configuration and test file list

  - Deleted unused `nfpms` configuration from `.goreleaser.yaml` to streamline the release process.
  - Removed `files.txt` as it contained outdated test file references.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

- *(changelog)* Update to version 1.0.0-rc1 and document notable changes

  - Updated CHANGELOG.md to reflect the release of version 1.0.0-rc1, detailing new features, enhancements, and fixes.
  - Documented improvements in XMLParser security, logger initialization, configuration management, and validation features.
  - Added comprehensive markdown generation capabilities and updated documentation for better clarity and usability.

  Tested with `just test` and `just ci-check`, all checks passed successfully.

<!-- generated by git-cliff -->
