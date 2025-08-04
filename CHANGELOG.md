# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

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

<!-- generated by git-cliff -->
