# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

### Breaking Changes

- *(plugin)* `compliance.Plugin.RunChecks` signature changed — internal API change (semver stays v1.x)

  **Before (v1.x):**

  ```go
  import "github.com/EvilBit-Labs/opnDossier/internal/model"

  func (p *MyPlugin) RunChecks(config *model.OpnSenseDocument) []compliance.Finding { ... }
  ```

  **After:**

  ```go
  import "github.com/EvilBit-Labs/opnDossier/internal/model/common"

  func (p *MyPlugin) RunChecks(device *common.CommonDevice) []compliance.Finding { ... }
  ```

  All three built-in plugins (STIG, SANS, Firewall) have been updated.
  External plugins must update their `RunChecks` implementation and import path accordingly.

### Features

- *(model)* Introduce multi-device model layer with `CommonDevice` domain abstraction
    - `internal/model/common/` provides a platform-agnostic `CommonDevice` struct
    - `internal/model/opnsense/` provides the OPNsense-specific parser and converter
    - `ParserFactory` auto-detects device type from the XML root element; `--device-type` flag bypasses detection
    - All consumers (processor, report generators, audit, diff, compliance plugins) now operate on `CommonDevice`
    - JSON/YAML outputs include a top-level `device_type` field

- Enhance CI workflows and documentation for compliance
    - Added FOSSA status badges to README for license and security compliance visibility.
    - Updated CI workflow to include permissions for security events in vulnerability scans.
    - Refined release workflow to generate and upload checksums for artifacts.
    - Enhanced documentation on Go tooling, including race detection and airgap build strategies.
    - Improved compliance documentation with detailed verification steps and requirements.

    This update strengthens compliance with the Pipeline v2 specification and improves overall project visibility.

- *(compliance)* Complete Pipeline v2 standards implementation
    Add missing components identified from detailed Pipeline v2 standards analysis:

    Release Automation:
    - Add Release Please workflow for automated versioning and changelog
    - Update release workflow to trigger on release events (not manual tags)
    - Implement proper single source of truth for versioning

    Workflow Standards:
    - Rename ci-check.yml to ci.yml per Pipeline v2 naming convention
    - Fix SLSA provenance generation workflow structure
    - Improve release artifact handling and verification

    Local Development Parity:
    - Add all required Pipeline v2 standard just commands:
      • setup (install dev dependencies)
      • fmt (code formatting)
      • cover (generate coverage artifacts)
      • sbom (generate SBOM)
      • release-dry (GoReleaser dry run)
      • site (serve documentation locally)
    - Ensure complete local/CI parity per standards

    This achieves 100% compliance with the detailed Pipeline v2 Standards
    document requirements for automated versioning, workflow naming,
    and local development command interface.

- Enhance CI workflows and documentation for compliance
    - Added FOSSA status badges to README for license and security compliance visibility.
    - Updated CI workflow to include permissions for security events in vulnerability scans.
    - Refined release workflow to generate and upload checksums for artifacts.
    - Enhanced documentation on Go tooling, including race detection and airgap build strategies.
    - Improved compliance documentation with detailed verification steps and requirements.

    This update strengthens compliance with the Pipeline v2 specification and improves overall project visibility.

- Integrate local Snyk and FOSSA scanning into the justfile
    - Added `snyk-scan` target to run local Snyk vulnerability scans and monitor for issues.
    - Updated `fossa-scan` target to include warnings for missing API keys.
    - Modified `security-scan` target to include calls to both Snyk and FOSSA scans.
    - Removed the FOSSA GitHub Actions workflow file and updated documentation to reflect CLI usage.

    All tests passed successfully; no tests were affected by these changes.

- Enhance release process with security features and tooling
    - Updated `.goreleaser.yaml` to include Cosign signing configuration and SLSA provenance generation.
    - Enhanced `justfile` with installation targets for Grype, Syft, and Cosign for improved security scanning and artifact signing.
    - Revised `RELEASING.md` to reflect new security features and installation instructions.
    - Updated GitHub Actions workflow to upload Cosign bundle and SLSA provenance files during release.

    All tests passed successfully; no tests were affected by these changes.

- Enhance CI workflows and documentation for compliance
    - Added FOSSA status badges to README for license and security compliance visibility.
    - Updated CI workflow to include permissions for security events in vulnerability scans.
    - Refined release workflow to generate and upload checksums for artifacts.
    - Enhanced documentation on Go tooling, including race detection and airgap build strategies.
    - Improved compliance documentation with detailed verification steps and requirements.

    This update strengthens compliance with the Pipeline v2 specification and improves overall project visibility.

- Enhance CI workflows and documentation for compliance
    - Added FOSSA status badges to README for license and security compliance visibility.
    - Updated CI workflow to include permissions for security events in vulnerability scans.
    - Refined release workflow to generate and upload checksums for artifacts.
    - Enhanced documentation on Go tooling, including race detection and airgap build strategies.
    - Improved compliance documentation with detailed verification steps and requirements.

    This update strengthens compliance with the Pipeline v2 specification and improves overall project visibility.

- Add release-please configuration and clean up CI workflows
    - Introduced `.release-please-config.json` for streamlined release management.
    - Removed outdated FOSSA and Snyk CI workflows to reduce redundancy.
    - Updated `release-please.yml` to simplify configuration by removing unnecessary comments.

    All tests passed successfully; no tests were affected by these changes.

- Update GoReleaser and CI workflows for enhanced artifact signing
    - Modified `.goreleaser.yaml` to include separate Cosign signing configurations for artifacts and checksums.
    - Added a new `.github/CODEOWNERS` file to define code ownership for PR reviews.
    - Cleaned up the CI workflow by removing outdated Cosign installation and signing steps, streamlining the release process.

    All tests passed successfully; no tests were affected by these changes.

- *(NAT)* Prominently display NAT mode and forwarding rules with enhanced security information
- *(NAT)* Prominently display NAT mode and forwarding rules with enhanced security information
- *(NAT)* Add inbound rules to NAT summary and enhance report templates
    - Included InboundRules in NATSummary struct for comprehensive NAT configuration.
    - Updated report templates to reflect changes in NAT configuration, including inbound rules.
    - Enhanced security notes and formatting in the NAT configuration sections across various report templates.

    All tests passed successfully; no tests were affected by these changes.

- *(NAT)* Update inbound rules representation in NAT struct and report templates
    - Modified the NAT struct to change the Inbound field's XML representation for better clarity.
    - Updated report templates to accurately reflect the count of configured inbound rules.
    - Ensured consistency across comprehensive and standard report templates.

    All tests passed successfully; no tests were affected by these changes.

- *(NAT)* Refactor NATSummary method for safety and clarity
    - Updated the NATSummary method to initialize with safe defaults and added nil checks for NAT fields to prevent panics.
    - Removed the generateNATSummary function as its functionality is now integrated into NATSummary.
    - Added unit tests for NATSummary to ensure safe behavior with minimal and partial NAT configurations.

    All tests passed successfully; no tests were affected by these changes.

- *(ci)* Implement Windows smoke-only testing strategy
    - Add ci-check-smoke target for minimal Windows validation
    - Update CI workflow to use conditional testing based on platform
    - Windows runners now run build + core functionality tests only
    - Linux/macOS continue with full test suite including linting
    - Reduces Windows CI time and costs while maintaining compatibility verification

- *(ci)* Enhance smoke test commands and CI workflow conditions
    - Updated `ci-check-smoke` to use `-trimpath` and improved build flags for better performance and versioning.
    - Modified CI workflow conditions to use `runner.os` for Windows checks, ensuring compatibility across platforms.
    - All tests passed successfully; no tests were affected by these changes.

- *(ci)* Add Copilot setup steps workflow for automated environment configuration
    - Introduced a new GitHub Actions workflow to automate setup steps for Copilot, including installation of Go, Just, pre-commit, and various development tools.
    - Added verification steps to ensure successful installation and configuration of the development environment.
    - Included commands for running project validation and generating documentation as part of the setup process.

    All tests passed successfully; no tests were affected by these changes.

- *(ci)* Enhance Copilot setup workflow with additional tools and validation steps
    - Added input option for installing extra development tools (git-cliff, grype, syft) in the Copilot setup workflow.
    - Updated Go and Node.js setup steps for improved caching and version management.
    - Enhanced installation steps for development tools with version-specific downloads and verification.
    - Included conditional checks for running validation steps based on the presence of a Justfile.

    All tests passed successfully; no tests were affected by these changes.

- *(ci)* Simplify Copilot setup workflow by removing options and adding bash  check
    - Removed the input option for installing additional development tools in the Copilot setup workflow.
    - Added a step to ensure bash is installed before proceeding with the setup.
    - Streamlined the verification of extra tools installation by removing conditional checks.

    All tests passed successfully; no tests were affected by these changes.

- *(ci)* Update pre-commit configuration and enhance Copilot setup workflow
    - Changed the commitlint entry in the pre-commit configuration to use pnpm instead of npx.
    - Added installation steps for pnpm and improved caching in the Copilot setup workflow.
    - Introduced new commands for testing GitHub Actions workflows locally and verifying tool installations.

    All tests passed successfully; no tests were affected by these changes.

- *(markdown)* Enhance interface link formatting in markdown reports
    - Added a new function `formatInterfacesAsLinks` to format interface names as markdown links in the report templates.
    - Updated the markdown generation logic to include formatted interface links in firewall rules tables.
    - Modified comprehensive and standard report templates to utilize the new link formatting function for better readability.

    All tests passed successfully; no tests were affected by these changes.

- *(markdown)* Improve inline link formatting for interfaces in markdown
    - Enhanced the `formatInterfacesAsLinks` function to return inline markdown links that are automatically converted to reference-style links by the nao1215/markdown package.
    - Updated comments for clarity on how links are generated and utilized in table cells.

    All tests passed successfully; no tests were affected by these changes.

- *(constants)* Add gateway complexity weights and report template paths
    - Introduced new constants for Gateway and Gateway Group complexity weights.
    - Added template file paths for various report types used in auditing functions.

    All tests passed successfully; no tests were affected by these changes.

- *(reports)* Implement gateway groups in reports for GitHub Issue 65
    - Add Gateway Groups section to both standard and comprehensive report templates
    - Include gateway groups in statistics and complexity calculations
    - Add comprehensive test coverage for gateway groups functionality
    - Create test configuration file with realistic gateway group data
    - Add template path constants to prevent future confusion
    - Ensure comprehensive reports remain strict superset of standard reports

- *(metrics)* Add configuration metrics calculations and tests
    - Introduced `CalculateTotalConfigItems` function to compute total configuration items across various components.
    - Updated `generateStatistics` and `generatePerformanceMetrics` to utilize the new metrics calculation.
    - Added comprehensive tests for the new metrics functionality, including various configuration scenarios.
    - Refactored existing tests to load configuration from external XML files for better maintainability.

    All tests passed successfully; no tests were affected by these changes.

- *(tests)* Add comprehensive tests for MarkdownBuilder functionality
    - Introduced a new test file `markdown_builder_test.go` to cover various aspects of the `MarkdownBuilder` implementation.
    - Added tests for building system, network, security, services sections, and generating standard and comprehensive reports.
    - Included tests for formatting functions to ensure accurate markdown representation.
    - Verified that all tests pass successfully, ensuring the integrity of the new functionality.

- *(markdown)* Implement hybrid markdown generator for flexible output
    - Introduced `HybridGenerator` to support both programmatic and template-based markdown generation, allowing for gradual migration.
    - Added `generateWithHybridGenerator` function to streamline output generation based on user-defined options.
    - Updated command flags to enhance custom template functionality.
    - Created comprehensive tests to validate output consistency between programmatic and template generation modes.

    All tests passed successfully; no tests were affected by these changes.

- *(template)* Implement caching for template loading and enhance test coverage
    - Introduced a caching mechanism for template loading to optimize IO/CPU operations, reducing redundant template parsing.
    - Added comprehensive tests for `getCachedTemplate` to validate caching behavior and error handling for various scenarios.
    - Enhanced command flags to support filename completion for custom templates, improving user experience.
    - Updated existing tests to ensure compatibility with the new caching functionality.

    All tests passed successfully; no tests were affected by these changes.

- *(template)* Integrate LRU caching for template management and enhance test coverage
    - Implemented an LRU caching mechanism for template instances to optimize loading and reduce redundant I/O operations.
    - Refactored existing template handling to utilize the new cache, improving performance and memory management.
    - Expanded test coverage for template caching functionality, including concurrent access and cache size verification.
    - Updated command flags to allow configuration of the template cache size for better user control.

    All tests passed successfully; no tests were affected by these changes.

- *(converter)* Implement utility functions for template migration Phase 3.2
- *(converter)* Implement data transformation functions for markdown generation
- *(converter)* Implement Phase 3.4 security assessment functions
    - Add AssessRiskLevel() with emoji + text risk labels
    - Add CalculateSecurityScore() wrapper for security scoring
    - Add AssessServiceRisk() for service risk mapping
    - Update template getRiskLevel for consistency
    - Add comprehensive unit tests
    - Add security scoring methodology documentation

- *(test)* Complete comprehensive test suite for ported methods
- *(test)* Add performance baseline validation and fix TERM environment issues
    - Add comprehensive performance baseline tests validating response time requirements
    - Fix TERM environment handling in tests to prevent ANSI code interference
    - Update performance metrics in README_TESTS.md with accurate benchmark results
    - Add specific performance thresholds for all major operations:
      * Standard report generation: <1ms (✅ achieved: ~656μs)
      * System section generation: <200μs (✅ achieved: ~133μs)
      * Network section generation: <50μs (✅ achieved: ~24μs)
      * Security section generation: <300μs (✅ achieved: ~249μs)
      * Services section generation: <100μs (✅ achieved: ~59μs)
      * Large dataset processing: <50ms (✅ achieved: ~31ms)
    - Resolve all linting issues with proper nolint annotations
    - Maintain 8.7x performance improvement over template-based generation

- *(benchmarks)* Add comprehensive performance benchmarking suite
    - Add markdown_bench_test.go comparing original vs programmatic approaches
    - Include small/medium/large dataset testing with memory profiling
    - Implement individual method benchmarks and concurrent testing
    - Document 71-74% performance improvements exceeding 30-50% target
    - Add justfile entries for CI integration and regression testing

- *(cli)* Implement programmatic mode by default with engine selection
- *(cli)* Add comprehensive tests, config support, and migration guide
- *(docs)* Update agent practices and migration guide with critical task completion note
    - Added a critical note to ensure tasks are not considered complete until `just ci-check` passes.
    - Updated formatting and consistency in various documentation files.
    - Ensured all changes were validated and tests passed successfully.

- *(docs)* Refine requirements management guidelines
    - Updated the overview to remove project-specific naming for broader applicability.
    - Added detailed EARS notation guidelines for writing requirements.
    - Included acceptance criteria and RFC compliance requirements for clarity and standardization.
    - Ensured all changes were validated and tests passed successfully.

- *(docs)* Enhance requirements management documentation
    - Updated the tasks.md section to provide a more detailed implementation plan, including clear task descriptions and expected outcomes.
    - Added new guidelines for requirement prioritization, including priority levels, business value, and risk assessment.
    - Introduced a requirement traceability section to ensure alignment between requirements, tasks, user stories, and tests.
    - All changes have been validated, and tests passed successfully.

- *(docs)* Add comprehensive migration guide for custom template users
- Add settings.local.json for permission configuration
    Introduced a new settings.local.json file to define permissions for Bash commands, allowing specific build and test operations. This enhances the configuration management for the project.

- Enhance command validation and error handling
    - Added validation for flag combinations in the `convert` and `display` commands to ensure correct usage and improve user experience.
    - Updated error messages for better clarity, including specific cases for file access issues and template parsing errors.
    - Introduced a new `validateGlobalFlags` function to enforce consistency across global command flags.
    - Enhanced the `settings.local.json` to include additional permissions for Bash commands.
    - Updated documentation to reflect changes in command behavior and migration guidance.

- *(docs)* Add release and development standards documentation
    - Introduced a comprehensive release process document for opnDossier.
    - Added development standards outlining coding practices and workflows.
    - Updated index and migration guide to reflect new documentation.
    - Removed obsolete vale.ini file.

- Implement template mode deprecation framework for v2.0 (#151)
    * ci: update .coderabbit.yaml with schema and formatting fixes

    Added yaml-language-server schema reference for improved validation. Updated string quoting for placeholders and instructions to ensure consistency and compatibility.

    * feat: add settings.local.json for permission configuration

    Introduced a new settings.local.json file to define permissions for Bash commands, allowing specific build and test operations. This enhances the configuration management for the project.

- *(ci)* Enhance Grype vulnerability scanning in CI pipeline (#156)
    * feat(ci): enhance Grype vulnerability scanning in CI pipeline

    - Implement daily scheduled security scans and manual triggers.
    - Add SBOM generation and upload for SPDX and CycloneDX formats.
    - Introduce branch-specific severity thresholds for vulnerability scans.
    - Document security scanning processes and local execution commands.

- *(display)* Implement proper text wrapping support for --wrap flag (#158)
    * feat(coderabbit): update path instructions and enable walkthrough collapse

    - Enabled the collapse_walkthrough feature for improved UI experience.
    - Added detailed path instructions for various Go code directories, enhancing code review clarity and focus.
    - Updated path filters to include additional file types for better documentation and testing guidance.

- *(parser)* Implement proper ISO-8859-1 and Windows-1252 encoding support (#169)
    Add comprehensive support for ISO-8859-1 (Latin1) and Windows-1252 character
    encodings in XML parsing using golang.org/x/text/encoding. This resolves
    issues with parsing OPNsense config files that declare non-UTF-8 encodings.

- Add --no-wrap flag as explicit alias for --wrap 0 (#170)
    * feat: add --no-wrap flag as explicit alias for --wrap 0

    This commit implements the --no-wrap flag for both display and convert
    commands as a more intuitive alternative to --wrap 0. The flag is mutually
    exclusive with --wrap to prevent conflicting configuration.

- *(devcontainer)* Add Go development container configuration
    - Introduced a new devcontainer.json file for Go development.
    - Configured essential features and VSCode extensions for a better development experience.

- *(compliance)* Add extended checks for password policy and audit logging (#181)
    * feat(compliance): add extended checks for password policy and audit logging

- *(display)* Improve NAT rule directionality presentation in markdown reports (#182)
    ## Summary

    - Add `BuildOutboundNATTable` and `BuildInboundNATTable` methods to
    MarkdownBuilder for clear visual separation of NAT rule types
    - Update `BuildSecuritySection` to use new NAT table builders with
    direction indicators (⬆️ Outbound / ⬇️ Inbound)
    - Add inbound rules count to NAT summary and security warning for port
    forwarding exposure
    - Update all templates (opnsense_report.md.tmpl,
    opnsense_report_comprehensive.md.tmpl, reports/standard.md.tmpl) to
    properly iterate over inbound NAT rules

    ## Test plan

    - [x] Verified with `just ci-check` - all tests pass
    - [x] Added unit tests for `BuildOutboundNATTable` (with rules, empty
    rules, special characters)
    - [x] Added unit tests for `BuildInboundNATTable` (with rules, empty
    rules, special characters)
    - [x] Added unit tests for `BuildSecuritySection` with both NAT types
    and security warnings

- Complete template system migration and removal for v2.0 (#184)
    ## Summary

- *(cmd)* Implement CommandContext pattern for dependency injection (#188)
    ## Summary

    - Introduces `CommandContext` struct to encapsulate `Config` and
    `Logger` dependencies
    - Replaces deprecated `GetLogger()` and `GetConfig()` with explicit
    dependency injection via `GetCommandContext()`
    - Migrates all subcommands (convert, display, validate) to use the new
    pattern
    - Adds comprehensive tests for context accessor functions

    ## Changes

    | File | Change |
    |------|--------|
    | `cmd/context.go` | New CommandContext infrastructure with typed
    context key |
    | `cmd/context_test.go` | Comprehensive tests for Get/Set/MustGet
    functions |
    | `cmd/root.go` | Sets CommandContext in PersistentPreRunE, removes
    deprecated accessors |
    | `cmd/convert.go` | Uses CommandContext for logger/config access |
    | `cmd/display.go` | Uses CommandContext for logger/config access |
    | `cmd/validate.go` | Uses CommandContext for logger/config access |
    | `AGENTS.md` | Documents CommandContext pattern (5.7) and context key
    types (5.8) |

    ## Test plan

    - [x] `just ci-check` passes
    - [x] `go test -race ./cmd/...` passes
    - [x] All existing cmd tests pass with updated assertions

- *(converter)* Add streaming generation for large configurations (#189)
    ## Summary

    - Implement Tier 1 streaming optimization for memory-efficient output
    generation
    - Add code quality improvements from Go code review
    - Addresses issue #143

    ## Changes

    ### Streaming Generation (issue #143)
    - Add `SectionWriter` interface for `io.Writer`-based report generation
    - Add `StreamingGenerator` interface extending `Generator` with
    `GenerateToWriter`
    - Implement `WriteStandardReport` and `WriteComprehensiveReport` methods
    - Preserve string-based API for future HTML conversion workflows

    ### Code Quality Improvements
    - Replace `init()` with `sync.Once` pattern for global registry
    - Add context cancellation support to XML parser
    - Use `errors.Join()` for proper error accumulation
    - Use `slices.Sorted(maps.Keys())` for deterministic map iteration
    - Remove unnecessary `runtime.GC()` calls
    - Fix golangci-lint configuration conflict

    ## Test plan

    - [x] All existing tests pass
    - [x] New writer tests added (`writer_test.go`)
    - [x] `just ci-check` passes
    - [x] Tested with production-size configs (1-5 MB)

- Cli interface enhancement,  command structure, help system, progress completion (#193)
    This pull request introduces several improvements to the CLI, focusing
    on enhanced shell completion, structured error handling, improved help
    output, and better user experience for command suggestions and flag
    completions. The changes add machine-readable exit codes and JSON error
    output, organize help and flag completion logic, and provide more robust
    shell completions for commands and flags.

    **Shell Completion and Flag Improvements**
    - Added shell completion for XML files, formats, themes, sections, and
    color modes via new functions like `ValidXMLFiles`, `ValidFormats`,
    `ValidThemes`, `ValidSections`, and `ValidColorModes` in
    `cmd/shared_flags.go`. These are now registered with relevant commands
    for better tab completion.
    (`[[1]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485R86-R111)`,
    `[[2]](diffhunk://#diff-b579cf2ee593864eee64ebab2f7a6173a4a90365f6d4c9fff26130eec6e5da66R30-R55)`,
    `[[3]](diffhunk://#diff-a137a9df9f6cc3dc15f0ee375211ec7e2a34898c18bf30b84947e5ebe3da938aR77-R175)`,
    `[[4]](diffhunk://#diff-ab967ab1a2f3a1b769106eeb7bfe892ef0e81d1d27811fa15be08e6749feee1fR177)`,
    `[[5]](diffhunk://#diff-6701a60d95525f3d714ff656fdc86ef5dc9753df9e79b60f0a9a7d2be4d884c6R26)`)
    - Registered flag completion functions for `convert`, `display`, and
    root commands, improving usability and discoverability of valid flag
    values.
    (`[[1]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485R86-R111)`,
    `[[2]](diffhunk://#diff-b579cf2ee593864eee64ebab2f7a6173a4a90365f6d4c9fff26130eec6e5da66R30-R55)`,
    `[[3]](diffhunk://#diff-ab967ab1a2f3a1b769106eeb7bfe892ef0e81d1d27811fa15be08e6749feee1fR205-R219)`)

    **Error Handling and Exit Codes**
    - Added a new `cmd/exitcodes.go` file that defines structured exit
    codes, JSON error output, and utility functions for machine-readable
    error handling, enabling better integration with CI/CD pipelines and
    automation.
    (`[cmd/exitcodes.goR1-R134](diffhunk://#diff-149fe2c317fa86b49fca6aa9601af3034d0a58b90c83aaa428f90ddef5d84025R1-R134)`)
    - Updated the `validate` command to use atomic operations for tracking
    the highest error exit code across multiple files and to support JSON
    output for errors.
    (`[cmd/validate.goL57-R78](diffhunk://#diff-6701a60d95525f3d714ff656fdc86ef5dc9753df9e79b60f0a9a7d2be4d884c6L57-R78)`)

    **Help System and Suggestions**
    - Introduced a new `cmd/help.go` file with a custom help template,
    enhanced usage output, and suggestion logic for both commands and flags
    using Levenshtein distance. This provides better guidance and typo
    correction for users.
    (`[cmd/help.goR1-R211](diffhunk://#diff-2d95fb0760367a9d7561dc586144634b92b1fdf6feb3ef5282066bd4a922e945R1-R211)`)
    - Initialized the enhanced help system in the root command, ensuring all
    commands benefit from improved help and suggestions.
    (`[cmd/root.goR205-R219](diffhunk://#diff-ab967ab1a2f3a1b769106eeb7bfe892ef0e81d1d27811fa15be08e6749feee1fR205-R219)`)

    **Command Grouping and Metadata**
    - Added `GroupID: "utility"` or `GroupID: "core"` to commands like
    `completion`, `man`, and `version` for better grouping and help
    organization.
    (`[[1]](diffhunk://#diff-87715bd8df67eade3c959a576ad99e341b9c6978dc9e50f8769ddcdb46e486b2R13)`,
    `[[2]](diffhunk://#diff-226a81639020480e2772009f4eaab778d5a05f78ffdb9b0f5338de819e66a06eR17)`,
    `[[3]](diffhunk://#diff-ab967ab1a2f3a1b769106eeb7bfe892ef0e81d1d27811fa15be08e6749feee1fR161)`)

    **Documentation Updates**
    - Updated `AGENTS.md` with new sections on streaming interface patterns
    and best practices for map iteration in tests.
    (`[[1]](diffhunk://#diff-a54ff182c7e8acf56acfd6e4b9c3ff41e2c41a31c9b211b2deb9df75d9a478f9R253-R261)`,
    `[[2]](diffhunk://#diff-a54ff182c7e8acf56acfd6e4b9c3ff41e2c41a31c9b211b2deb9df75d9a478f9R396-R403)`)

    **Other Minor Changes**
    - Removed the `learning-output-style` plugin from
    `.claude/settings.json`.
    (`[.claude/settings.jsonL2-R2](diffhunk://#diff-f27ac6f39d89fe021c56900069198aa7d9968f2cd6645c00b11ffd1b78fcf546L2-R2)`)
    - Added necessary imports for new functionality in several files.
    (`[[1]](diffhunk://#diff-a137a9df9f6cc3dc15f0ee375211ec7e2a34898c18bf30b84947e5ebe3da938aR5-R8)`,
    `[[2]](diffhunk://#diff-6701a60d95525f3d714ff656fdc86ef5dc9753df9e79b60f0a9a7d2be4d884c6R11)`)

    These changes collectively make the CLI more robust, user-friendly, and
    suitable for both interactive use and automation.

    ---------

- *(config)* Enhance configuration management system (#194)
    ## Summary

    Implements Issue #10 - Configuration Management Enhancement (TASK-026
    through TASK-029).

    - Add nested configuration structures (DisplayConfig, ExportConfig,
    LoggingConfig, ValidationConfig)
    - Add environment variable support for all nested fields with
    OPNDOSSIER_ prefix
    - Add `config` subcommand group with `show`, `init`, and `validate`
    commands
    - Implement comprehensive validation with styled error reporting using
    Lipgloss
    - Add comprehensive documentation in docs/configuration.md

    ## Changes

    ### New Files
    - `cmd/config.go` - Config command group
    - `cmd/config_show.go` - Display effective configuration with source
    indicators
    - `cmd/config_init.go` - Generate template configuration file
    - `cmd/config_validate.go` - Validate configuration with line-number
    error reporting
    - `internal/config/validation.go` - Comprehensive validation logic
    - `internal/config/errors.go` - Styled error formatting with Lipgloss
    - `docs/configuration.md` - Complete configuration guide

    ### Modified Files
    - `internal/config/config.go` - Add nested structs and integrate new
    validator
    - `example-config.yaml` - Updated with all nested options

    ## Test Plan

    - [x] All tests pass (`go test ./...`)
    - [x] CI checks pass (`just ci-check`)
    - [x] Test coverage >80% for config package (93.5%)
    - [x] Config loading benchmark <50ms (46ms for env-only)
    - [x] `opnDossier config show` displays configuration
    - [x] `opnDossier config init` generates template
    - [x] `opnDossier config validate` checks config files

    ## Closes #10

    🤖 Generated with [Claude Code](https://claude.ai/code)

    ---------

- *(hardening)* Epic - Production Hardening (Phases 1-4) (#214)
    ## Summary

    Implements GitHub Issue #11 - Epic: Production Hardening - Performance,
    Testing, Security & Cross-Platform.

    ### Phase 1 - Performance Foundation ✅
    - Concurrent processing worker pool for batch operations
    - CLI startup optimization (<100ms target achieved)
    - Memory pooling with sync.Pool for buffer reuse
    - Benchmark infrastructure with regression detection in CI

    ### Phase 2 - Enhanced Testing ✅
    - E2E integration tests for CLI commands (convert, validate, help,
    version)
    - Stress tests for worker pool and buffer pool under load
    - CI enhancements: integration tests, race detection
    - New justfile commands: `test-race`, `test-stress`

    ### Phase 3 - Security Hardening ✅
    - Security tests verifying no network dependencies
    - Telemetry verification tests (zero telemetry confirmed)
    - Secure defaults verified (0o600 file permissions)
    - Error message security audit (no sensitive data leakage)

    ### Phase 4 - Cross-Platform Support ✅
    - Cross-platform CI testing (Ubuntu, macOS, Windows)
    - Static compilation verification (CGO_ENABLED=0)
    - Cross-compilation validation for all target platforms

    ## Test plan

    - [x] All existing tests pass (`just test`)
    - [x] New E2E integration tests pass (`just test-integration`)
    - [x] Stress tests pass (`just test-stress`)
    - [x] Race detection passes (`just test-race`)
    - [x] Security tests pass
    - [x] CI checks pass (`just ci-check`)
    - [x] Benchmarks run successfully

    🤖 Generated with [Claude Code](https://claude.com/claude-code)

    ---------

- *(processor)* Implement comprehensive service detection for unused interface analysis (#215)
    ## Summary

- *(docs)* Add comprehensive template documentation and model reference (#216)
    ## Summary

    Implements Issue #50: Add comprehensive template documentation and
    auto-generated model reference.

    - Add `internal/docgen` package with reflection-based struct
    introspection for generating model documentation
    - Create `tools/docgen` CLI tool to auto-generate model reference from
    Go types
    - Add `just generate-docs` target for documentation regeneration
    - Create comprehensive `docs/templates/` section with integration guides
    and examples
    - Update mkdocs.yml with "Data Model & Integration" navigation section

    ## Changes

    | File | Purpose |
    |------|---------|
    | `internal/docgen/generator.go` | Model introspection and markdown
    generation |
    | `internal/docgen/generator_test.go` | 11 unit tests for the docgen
    package |
    | `tools/docgen/main.go` | CLI tool to generate model reference |
    | `docs/templates/index.md` | Overview and integration guide |
    | `docs/templates/model-reference.md` | Auto-generated field reference
    (46 fields) |
    | `docs/templates/examples/json-export.md` | jq query examples |
    | `docs/templates/examples/yaml-processing.md` | yq query examples |
    | `justfile` | Added `generate-docs` target |
    | `mkdocs.yml` | Added navigation section |

    ## Technical Approach

    The implementation documents existing JSON/YAML export capabilities
    rather than introducing a new template system, following the KISS
    principle. Users can:

    1. Export configs to JSON/YAML with `opndossier convert`
    2. Query data with `jq`/`yq` using the documented field paths
    3. Integrate with Ansible, Python, or shell scripts

    ## Test plan

    - [x] All docgen unit tests pass (11 tests)
    - [x] `just ci-check` passes
    - [x] `just generate-docs` successfully generates model reference
    - [x] Documentation renders correctly in mkdocs

- *(builder)* Add missing network sections to comprehensive report (#218)
    ## Summary
    - Implements #67: Add VLAN, Static Routes, IPsec, OpenVPN, and High
    Availability sections to the comprehensive report
    - All data models were already parsed from OPNsense XML; this PR adds
    the rendering logic

    ## Changes

    ### New Builder Methods
    - `BuildVLANTable()` - Renders VLAN configurations (interface, tag,
    description)
    - `BuildStaticRoutesTable()` - Renders static routes with
    enabled/disabled status
    - `BuildIPsecSection()` - Renders IPsec General and Charon IKE daemon
    configuration
    - `BuildOpenVPNSection()` - Renders OpenVPN servers, clients, and
    client-specific overrides
    - `BuildHASection()` - Renders CARP VIPs and HA synchronization settings

    ### Updated Components
    - `ReportBuilder` interface extended with 5 new methods
    - `BuildComprehensiveReport()` and `WriteComprehensiveReport()` now
    include all new sections
    - Table of Contents updated with links to new sections

    ### Test Coverage
    - 15 new unit tests covering empty states, single items, and multiple
    items
    - Golden files updated for comprehensive reports
    - All existing tests continue to pass

    ## Test plan
    - [x] `just ci-check` passes
    - [x] Golden file tests pass with `-update` flag
    - [x] All new builder methods have unit tests
    - [x] Empty configuration states render gracefully

    🤖 Generated with [Claude Code](https://claude.com/claude-code)

    ---------

- Enhanced dhcp reporting   expand coverage of server configuration static mappings and advanced options feat(markdown-builder): add DHCP table generation (#223)
    This pull request introduces major improvements to how DHCP server
    configuration is summarized and displayed in Markdown reports. It adds
    new table-based summaries for DHCP scopes and static leases, refactors
    the service section to use these tables, and provides helper functions
    for formatting lease times and detecting advanced DHCP configuration.
    Documentation and golden test files are updated to reflect and validate
    these changes.

    **DHCP Table Rendering and Summarization:**

    * Added new methods `WriteDHCPSummaryTable` and
    `WriteDHCPStaticLeasesTable` to `MarkdownBuilder` for generating
    table-based summaries of DHCP scopes and static leases, including helper
    functions for building table data.
    [[1]](diffhunk://#diff-2fa27e12b9f3887955cadf77c229066536944608aede84b9d2a856b18e8013d7R52-R55)
    [[2]](diffhunk://#diff-2fa27e12b9f3887955cadf77c229066536944608aede84b9d2a856b18e8013d7R979-R1079)
    * Refactored the DHCP section in the service configuration to use the
    new summary and detail tables, with per-interface breakdowns for static
    leases, advanced options, number options, and DHCPv6 configurations.

    **Helper Functions for DHCP Formatting:**

    * Introduced `FormatLeaseTime` and supporting functions to convert DHCP
    lease times from seconds to human-readable format, and added detection
    helpers for advanced DHCP and DHCPv6 configuration fields.
    [[1]](diffhunk://#diff-6aab317fd59e4378543937a7114f26a4238ec4fc5f2086932d3209cf77a19c1cR112-R383)
    [[2]](diffhunk://#diff-6aab317fd59e4378543937a7114f26a4238ec4fc5f2086932d3209cf77a19c1cR4-R17)

    **Documentation Updates:**

    * Updated `AGENTS.md` to document best practices for Markdown table
    chaining and golden file testing, including normalization and validation
    steps.
    [[1]](diffhunk://#diff-a54ff182c7e8acf56acfd6e4b9c3ff41e2c41a31c9b211b2deb9df75d9a478f9R399-R413)
    [[2]](diffhunk://#diff-a54ff182c7e8acf56acfd6e4b9c3ff41e2c41a31c9b211b2deb9df75d9a478f9R570-R580)

    **Golden File and Test Updates:**

    * Updated golden Markdown files to show the new DHCP summary tables and
    reflect timestamp changes from recent test runs.
    [[1]](diffhunk://#diff-f505dd3ed011af506f145587f9cb51b786b5d9fe9b430629722d4ec10749c313R147-R150)
    [[2]](diffhunk://#diff-498810bfd8fd90bf82f80961cb27d1ac287e246aada17e78327acc7b77d3db31R117-R120)
    [[3]](diffhunk://#diff-8079119967109fa6f00637a7b53e4857f7ad983aa99edfd355d156a568822147R122-R125)

    **Dependency Imports:**

    * Added imports for `maps` and `slices` to support deterministic table
    row ordering.

    ---------

- *(cmd)* Integrate audit mode and compliance plugin system into CLI (#224)
    ## Summary

    - Integrate existing audit mode infrastructure (`internal/audit/`) into
    the CLI
    - Add `--audit-mode`, `--audit-blackhat`, and `--audit-plugins` flags to
    convert command
    - Wire compliance plugins (STIG, SANS, Firewall) for security auditing
    and compliance reporting
    - Add comprehensive tests for audit handler functionality

    ## Changes

    ### New CLI Flags
    ```bash
    --audit-mode standard|blue|red    # Enable audit reporting mode
    --audit-blackhat                   # Enable blackhat commentary (red mode)
    --audit-plugins stig,sans,firewall # Select compliance plugins to run
    ```

    ### Files Changed
    | File | Description |
    |------|-------------|
    | `internal/converter/options.go` | Added `AuditMode`, `BlackhatMode`,
    `SelectedPlugins` fields |
    | `internal/converter/options_test.go` | Tests for new option fields and
    builder methods |
    | `cmd/shared_flags.go` | Flag variables, registration, validation,
    shell completions |
    | `cmd/convert.go` | Flag wiring and audit handler integration |
    | `cmd/audit_handler.go` | New audit handler with `handleAuditMode()`
    and `appendAuditFindings()` |
    | `cmd/audit_handler_test.go` | Comprehensive tests (645 lines, 20 test
    functions) |

    ### Example Usage
    ```bash
    # Blue team defensive audit with STIG compliance
    opnDossier convert config.xml --audit-mode blue --audit-plugins stig,sans

    # Red team attack surface analysis with blackhat commentary
    opnDossier convert config.xml --audit-mode red --audit-blackhat

    # Standard documentation with all compliance checks
    opnDossier convert config.xml --audit-mode standard --audit-plugins stig,sans,firewall
    ```

    ## Test plan

    - [x] Unit tests for `appendAuditFindings()` function (8 test cases)
    - [x] Unit tests for helper functions (`escapePipeForMarkdown`,
    `truncateString`)
    - [x] Validation tests for audit mode (valid/invalid modes,
    case-insensitive)
    - [x] Validation tests for audit plugins (valid/invalid plugins)
    - [x] Shell completion tests for `ValidAuditModes` and
    `ValidAuditPlugins`
    - [x] `just ci-check` passes
    - [x] Backward compatibility verified (existing tests pass)

- *(release)* Add GPG signing for release artifacts
    - Add GPG signing configuration to goreleaser for archives and packages
    - Add GPG key import step to release workflow
    - Add EvilBit Labs software signing public key (software@evilbitlabs.io)
    - Document GPG verification process in RELEASING.md
    - Document GPG_PRIVATE_KEY and GPG_PASSPHRASE secrets

    Signing is optional - releases work without GPG secrets configured.

- *(tools)* Add Anchore Quill for improved container security analysis

### Bug Fixes

- *(release)* Remove GO_VERSION dependency and add mdformat to changelog generation
- Refactor firewall rule interface handling to support multiple interfaces
    - Introduced InterfaceList type to manage multiple interfaces in firewall rules.
    - Updated XML marshaling and unmarshaling for InterfaceList to handle comma-separated values.
    - Modified rule analysis, statistics generation, and validation to accommodate multiple interfaces.
    - Adjusted tests to reflect changes in interface handling, ensuring compatibility with new structure.
    - Enhanced code readability and maintainability by encapsulating interface-related logic within InterfaceList methods.

- *(converter)* Update protocol references in markdown templates
- *(templates)* Resolve comprehensive report structural inconsistencies with summary report
    - Fix field name inconsistencies (.Version -> .System.Firmware.Version)
    - Add missing sections from summary report (OpenVPN, Services & Daemons, System Notes)
    - Ensure comprehensive report is true superset of summary report
    - Add both summary and detailed views for each section
    - Maintain consistent table structures and field mappings
    - Fix table of contents to match actual sections

- Correct minor formatting issues in templates
- *(templates)* Correct boolean formatting in OPNsense report templates
    - Updated SNMP and NTP service boolean formatting for consistency.
    - Ensured proper handling of empty values in the comprehensive report template.
    - Maintained alignment with previous structural changes in the summary report.

- *(docs)* Remove unnecessary newline in README.md
    - Cleaned up formatting by removing an extra newline before the FOSSA badge.
    - Ensured consistent presentation of project information.

    No tests affected.

- *(templates)* Correct boolean formatting in OPNsense report templates
    - Updated SNMP and NTP service boolean formatting for consistency.
    - Ensured proper handling of empty values in the comprehensive report template.
    - Maintained alignment with previous structural changes in the summary report.

- *(tests)* Enhance test coverage and validation checks
    - Added validation to ensure test files are within the testdata directory in `opnsense_test.go`.
    - Included a comment to clarify the controlled execution of the main function test in `main_test.go`.

    No tests affected; all existing tests passed successfully.

- *(templates)* Correct boolean formatting in OPNsense report templates
    - Updated SNMP and NTP service boolean formatting for consistency.
    - Ensured proper handling of empty values in the comprehensive report template.
    - Maintained alignment with previous structural changes in the summary report.

- *(templates)* Correct boolean formatting in OPNsense report templates
    - Updated SNMP and NTP service boolean formatting for consistency.
    - Ensured proper handling of empty values in the comprehensive report template.
    - Maintained alignment with previous structural changes in the summary report.

- *(templates)* Correct boolean formatting in OPNsense report templates
    - Updated SNMP and NTP service boolean formatting for consistency.
    - Ensured proper handling of empty values in the comprehensive report template.
    - Maintained alignment with previous structural changes in the summary report.

- *(templates)* Correct boolean formatting in OPNsense report templates
    - Updated SNMP and NTP service boolean formatting for consistency.
    - Ensured proper handling of empty values in the comprehensive report template.
    - Maintained alignment with previous structural changes in the summary report.

- *(ci)* Update git-cliff installation path in Copilot setup workflow
    - Changed the installation path for git-cliff to include the version-specific directory.
    - Ensured that the correct binary is moved to /usr/local/bin/ for proper execution.

    All tests passed successfully; no tests were affected by these changes.

- *(test)* Modernize benchmark loops using b.Loop() for Go 1.24+ compatibility
- *(docs)* Apply mdformat table formatting to README_TESTS.md
- *(docs)* Apply mdformat corrections to README_TESTS.md
- *(test)* Adjust performance baseline thresholds to realistic values
- *(tests)* Enhance markdown escaping and improve test coverage
    - Adjusted the escaping logic in `EscapeTableContent` to handle special characters consistently, including asterisks, underscores, backticks, square brackets, and angle brackets.
    - Updated tests to validate the escaping functionality for various edge cases, ensuring robustness against special characters in markdown.
    - Refactored `generateLargeBenchmarkData` to utilize `makeLargeDataset` for consistency in test data generation.
    - Added new test cases for validating table structure and escaping behavior in markdown content.

- *(test)* Adjust performance baseline thresholds for CI environment stability
- *(docs)* Clarify task completion requirements and enhance migration guide
    - Updated critical task completion note to specify that `just ci-check` must be run and fully passed.
    - Enhanced migration guide with details on environment variable usage and CLI flag precedence.
    - Improved documentation consistency across various files.
    - All changes have been validated, and tests passed successfully.

- *(cmd)* Ensure consistent path separators in getSharedTemplateDir
    - Updated getSharedTemplateDir function to use filepath.ToSlash for consistent path separators across platforms.
    - This change maintains backward compatibility while simplifying the user experience.
    - All changes have been validated, and tests passed successfully.

- *(cmd)* Update UseTemplateEngine to prioritize CLI flags over config settings
    - Modified generateWithHybridGenerator to set opt.UseTemplateEngine based on CLI flag precedence.
    - This change ensures that user-specified CLI flags take priority over configuration file settings, improving flexibility in template engine selection.

- *(tests)* Update test assertions for markdown library v0.10.0
    The nao1215/markdown library v0.10.0 changed table header rendering
    from uppercase to title case. Update test assertions to expect:
    - "Tunable" instead of "TUNABLE"
    - "Value" instead of "VALUE"
    - "Description" instead of "DESCRIPTION"
    - "Type" instead of "TYPE"
    - "Inter" instead of "INT"
    - "Sou" instead of "SOU"
    - "Des" instead of "DES"

    This fixes test failures in PR #137 (dependabot markdown upgrade).

- *(tests)* Improve error message assertions for file not found cases
    Updated the test for the `convert` command to assert that error messages indicate missing files more clearly. The test now checks for both "no such file or directory" and "The system cannot find the file specified" to enhance error handling in the command execution.

- *(test)* Use windowsOS constant to fix goconst linting issue
    - Replace string literal "windows" with windowsOS constant
    - Satisfies goconst linter requirement for repeated strings
    - Improves code maintainability

- Replace panic based error handling in production code (#167)
    * refactor(logger): replace panic-based error handling with graceful error returns

- Remove deprecated logging configuration functions (#168)
    * chore: update FOSSA configuration for target type

- Remove stubbed audit mode code and defer implementation to v2.1 (#175)
    * feat(devcontainer): add Go development container configuration

    - Introduced a new devcontainer.json file for Go development.
    - Configured essential features and VSCode extensions for a better development experience.


### Refactor

- *(processor)* Simplify interface check and add context cancellation handling
    - Replaced manual interface list check with slices.Contains for better readability.
    - Added context cancellation checks in the Process method to handle cancellation gracefully.
    - Improved test cases by using require instead of assert for better error handling.
    - Added mutex for concurrent access protection in the Report struct.

- Streamline logging configuration and remove deprecated methods
    - Updated logging initialization to determine log level based on verbose and quiet flags, removing reliance on deprecated GetLogLevel and GetLogFormat methods.
    - Replaced string concatenation with strings.Builder for performance improvements in error message formatting.
    - Removed unnecessary build constraints from integration and completeness test files, simplifying the build process.
    - Marked Error function in display package as deprecated in favor of StyleSheet.ErrorPrint.

- Replace custom contains function with slices.Contains
    - Updated the validation functions in `convert`, `display`, and `root` commands to use `slices.Contains` for checking valid formats, themes, log levels, and log formats.
    - Removed the custom `contains` function as it is no longer needed.
    - Added a warning flag in `shared_flags.go` to prevent repeated warnings about absolute template paths.
    - Enhanced the deprecation warning handling in the markdown generator to ensure proper logging and user notifications.

- Simplify mapTemplateName and fix help text indentation
    - Flatten nested switch in mapTemplateName() for clarity
    - Fix inconsistent tab/space indentation in convert command help text
    - Address code review suggestions from PR review

- *(model)* Split model package into schema and enrichment (#144) (#186)
    Refactor model package to use type aliases for schema/enrichment packages.

    Reduces model package from ~3,565 to ~537 non-test lines while maintaining full backward compatibility.

- *(builder)* Leverage markdown library methods to reduce code verbosity (#222)
    This pull request introduces several improvements to the Markdown report
    generation and testing infrastructure. The main focus is on refactoring
    the report builder for more concise and maintainable code, modernizing
    and improving the golden file testing approach, and updating
    dependencies to support these changes.

    **Report Generation Refactoring:**

    * Refactored the `MarkdownBuilder` methods to use chained calls and the
    `BulletList` method for generating report headers and table of contents,
    resulting in more concise and readable code
    (`internal/converter/builder/writer.go`).
    [[1]](diffhunk://#diff-9b2034771808safe83d92dd7fcabca965d4aa7b9cfc6930fa739dd4aaf961e498L182-R191)
    [[2]](diffhunk://#diff-9b2034771808safe83d92dd7fcabca965d4aa7b9cfc6930fa739dd4aaf961e498L200-R244)
    * Updated how user and sysctl tables are written in the report by
    delegating directly to `WriteUserTable` and `WriteSysctlTable` methods,
    further simplifying the code (`internal/converter/builder/writer.go`).

    **Testing Improvements:**

    * Refactored table-related tests to verify rendered Markdown output
    instead of internal table data structures, aligning tests with actual
    output and improving reliability
    (`internal/converter/builder/writer_test.go`).
    [[1]](diffhunk://#diff-ec95912d8d44cf0bdcb2cf014c2c70449443da15411e1e5f9f989c98d5d9fcb9L220-R236)
    [[2]](diffhunk://#diff-ec95912d8d44cf0bdcb2cf014c2c70449443da15411e1e5f9f989c98d5d9fcb9L257-R269)
    [[3]](diffhunk://#diff-ec95912d8d44cf0bdcb2cf014c2c70449443da15411e1e5f9f989c98d5d9fcb9L287-R308)
    [[4]](diffhunk://#diff-ec95912d8d44cf0bdcb2cf014c2c70449443da15411e1e5f9f989c98d5d9fcb9L342-R348)
    * Updated imports in tests to support new code structure
    (`internal/converter/builder/writer_test.go`,
    `internal/converter/markdown_builder_test.go`).
    [[1]](diffhunk://#diff-ec95912d8d44cf0bdcb2cf014c2c70449443da15411e1e5f9f989c98d5d9fcb9R10)
    [[2]](diffhunk://#diff-d58907c81871959415617e75751807718fe654a11c6f7663d587b368d3d409f6R8)

    **Golden File Testing Modernization:**

    * Replaced custom golden file comparison logic with the `goldie` testing
    library, which handles golden file updates and diffing automatically,
    and added normalization logic to handle dynamic content (timestamps,
    versions) for deterministic comparisons
    (`internal/converter/golden_test.go`).
    [[1]](diffhunk://#diff-a4b6adfcf109430d11112fbdc6c5bb37694c355ac45b5fdb44517011e0df14f2R4-L20)
    [[2]](diffhunk://#diff-a4b6adfcf109430d11112fbdc6c5bb37694c355ac45b5fdb44517011e0df14f2L36-R112)
    [[3]](diffhunk://#diff-a4b6adfcf109430d11112fbdc6c5bb37694c355ac45b5fdb44517011e0df14f2L100-R144)
    [[4]](diffhunk://#diff-a4b6adfcf109430d11112fbdc6c5bb37694c355ac45b5fdb44517011e0df14f2L183-R199)
    [[5]](diffhunk://#diff-a4b6adfcf109430d11112fbdc6c5bb37694c355ac45b5fdb44517011e0df14f2L271-L372)
    [[6]](diffhunk://#diff-a4b6adfcf109430d11112fbdc6c5bb37694c355ac45b5fdb44517011e0df14f2L385-R297)
    * Updated golden file naming conventions and fixture directory usage to
    match `goldie` expectations (`internal/converter/golden_test.go`).

    **Dependency Updates:**

    * Added `github.com/sebdah/goldie/v2` and `github.com/sergi/go-diff` as
    dependencies for improved golden file testing and diffing (`go.mod`).
    [[1]](diffhunk://#diff-33ef32bf6c23acb95f5902d7097b7a1d5128ca061167ec0716715b0b9eeaa5f6R16)
    [[2]](diffhunk://#diff-33ef32bf6c23acb95f5902d7097b7a1d5128ca061167ec0716715b0b9eeaa5f6R83)

    These changes collectively improve code maintainability, test
    reliability, and developer experience when updating or verifying
    Markdown report output.

    ---------


### Documentation

- Fix changelog format for v1.0.0 release
- Finalize changelog for v1.0.0 release
- Format changelog for v1.0.0 release
- Enhance GitHub Copilot instructions and project overview
- Add project description to core-concepts.mdc
    - Included a brief description of the opnDossier project, outlining its purpose as a tool for auditing and reporting on OPNsense configurations.
    - Added a link to the project's GitHub repository for easy access.

    All tests passed successfully; no tests were affected by these changes.

- *(copilot)* Expand GitHub Copilot instructions and project guidelines
    - Added comprehensive sections on rule precedence, project overview, core philosophy, technology stack, and coding standards.
    - Included detailed guidelines for AI assistant behavior, development process, and mandatory practices for AI agents.
    - Enhanced documentation to clarify project-specific conventions and CI/CD integration standards.

    All tests passed successfully; no tests were affected by these changes.

- *(agents)* Expand documentation on brand principles and CI/CD integration standards
    - Added a new section detailing EvilBit Labs brand principles emphasizing trust, quality, and ethical constraints.
    - Updated CI/CD integration standards to include commit message formats, quality gates, and development commands.
    - Enhanced AI assistant guidelines with clear rules of engagement and code generation requirements.

    All tests passed successfully; no tests were affected by these changes.

- *(template)* Fix markdown formatting in template function migration guide
- Complete programmatic markdown generation documentation
- Enhance GitHub Copilot instructions with structured logging and error handling guidelines
    - Added comprehensive guidance for GitHub Copilot, emphasizing the importance of AGENTS.md as the primary reference for AI assistant behavior.
    - Included examples for error handling and structured logging patterns using `charmbracelet/log`.
    - Updated the AI agent code review checklist to reflect new standards for error context and logging practices.
    - Improved project structure documentation for clarity and reference.

- Update migration guide and template function mapping
    - Enhanced the migration guide with a detailed deprecation timeline and migration checklist to assist users in transitioning from template to programmatic methods.
    - Updated the custom template function mapping table to reflect the current status of functions, marking several as migrated and providing implementation details.
    - Improved the validation script for migration, adding checks for custom templates and ensuring users are informed about unmigrated functions.

- Remove template references and add modular report architecture (#187)
    This pull request focuses on removing legacy template-based report
    generation and fully transitioning the documentation and architecture to
    a programmatic, modular approach. All references, documentation, and
    technical debt related to template-based generation have been removed or
    reworded to reflect the new architecture, and a new section on modular
    report generators has been added.

    **Key changes include:**

    ### Removal of Template-Based Generation

    - Deleted the entire `docs/deprecation-policy.md` file, which documented
    the deprecation and removal process for template-based generation.
    - Removed all documentation, diagrams, and references to template-based
    and hybrid generation modes from `docs/api.md`,
    `docs/architecture-review.md`, `docs/dev-guide/architecture.md`, and
    `docs/development/architecture.md`. This includes migration guides,
    technical debt notes, and comparison tables.
    [[1]](diffhunk://#diff-9eddf4dc51bf6a0125ca7fb094468ad284112270385c41cebce4f8f0a29620abL361-L381)
    [[2]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L204-L205)
    [[3]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L228-L229)
    [[4]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L661-L666)
    [[5]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L728-R723)
    [[6]](diffhunk://#diff-e620ea3bc4f558f3c6962b55bad846298b581e9b784cd0a9a93643275f09a219L150-L157)
    [[7]](diffhunk://#diff-e620ea3bc4f558f3c6962b55bad846298b581e9b784cd0a9a93643275f09a219L247)
    [[8]](diffhunk://#diff-e620ea3bc4f558f3c6962b55bad846298b581e9b784cd0a9a93643275f09a219L372-R381)
    [[9]](diffhunk://#diff-e620ea3bc4f558f3c6962b55bad846298b581e9b784cd0a9a93643275f09a219L484)
    [[10]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L194-R198)
    [[11]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L250-R254)
    [[12]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L389-L421)
    [[13]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L453-L485)

    ### Documentation and Architecture Updates

    - Updated all architectural diagrams and documentation to reflect a
    programmatic-only report generation flow, removing all template-related
    components and references.
    [[1]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L194-R198)
    [[2]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L250-R254)
    [[3]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L389-L421)
    [[4]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L453-L485)
    - Revised the executive summary and recommendations in
    `docs/architecture-review.md` to remove mention of template migration
    technical debt and to focus on current architectural priorities.
    [[1]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L9-R9)
    [[2]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L184-R192)
    [[3]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L645-R640)
    [[4]](diffhunk://#diff-28678a5787d754c08928f4d819d6f23f3a560ac0916c0d14fc7e21be241382f3L773-R761)

    ### New Modular Report Generator Architecture

    - Added a new section to `AGENTS.md` describing the modular architecture
    for report generators, including guidance on self-contained modules,
    shared helpers, and build flag integration for Pro-level features.

    ### Consistency and Clarity Improvements

    - Updated terminology throughout documentation to refer to "programmatic
    generation" and "enhanced blue team reports" instead of templates.
    [[1]](diffhunk://#diff-6e48ff7a14ec41ad1065115529cf8a7dde591d31f856ca254ef297956254c88aL219-R223)
    [[2]](diffhunk://#diff-9eddf4dc51bf6a0125ca7fb094468ad284112270385c41cebce4f8f0a29620abL7-R7)
    - Removed outdated migration and deprecation instructions, ensuring all
    documentation is current with the programmatic approach.
    [[1]](diffhunk://#diff-9eddf4dc51bf6a0125ca7fb094468ad284112270385c41cebce4f8f0a29620abL394)
    [[2]](diffhunk://#diff-e620ea3bc4f558f3c6962b55bad846298b581e9b784cd0a9a93643275f09a219L372-R381)
    [[3]](diffhunk://#diff-3caedd95aefa51553be1069772560367e021728814e3e4cb4e732e19460e0502L389-L421)

    These changes collectively complete the transition away from
    template-based generation, clarify the codebase's direction, and
    introduce a modular architecture for future extensibility.

    ---------

- *(release)* Add release documentation and standardize on CycloneDX SBOM
    - Add RELEASING.md with comprehensive release process documentation
    - Add llms.txt for AI/LLM project context
    - Update goreleaser to use cyclonedx-gomod instead of Syft for SBOM
    - Update CI workflows to remove Syft/SPDX, keep only CycloneDX
    - Update .gitignore with CycloneDX output files
    - Configure Cosign v3 keyless signing with .sigstore.json bundles
    - Add GitHub attestations for build provenance
    - Document macOS code signing with Quill (optional)


### Styling

- Fix markdown formatting in security-scoring.md

### Testing

- *(coverage)* Improve test coverage to address Codecov requirements
    - Added comprehensive test coverage for cmd package functions
    - Improved config package coverage to 92.6%
    - Added tests for determineOutputPath, generateOutputByFormat, generateWithHybridGenerator
    - Added tests for validateTemplatePath, getSharedTemplateDir, buildConversionOptions
    - Added tests for config validation functions and getter methods
    - Overall project coverage improved to 78.0% (from ~65.7%)
    - Addressed the 47 missing lines identified by Codecov analysis

- *(converter)* Verify NAT interface hyperlinks (#217)
    ## Summary

    - Add comprehensive tests to verify NAT rules render interface names as
    clickable markdown links (Issue #61)
    - Document standalone tools pattern in AGENTS.md

    ## Details

    After analysis, the core implementation for NAT interface hyperlinking
    was **already complete** in `BuildOutboundNATTable()` and
    `BuildInboundNATTable()` (both use
    `formatters.FormatInterfacesAsLinks()`).

    However, the existing tests only checked that interface names were
    *present* in the output, not that they were rendered as proper markdown
    links.

    ### New Tests Added

    - `TestMarkdownBuilder_NATRulesWithInterfaceLinks`: Verifies both
    outbound and inbound NAT rules render interfaces in
    `[name](#name-interface)` format with proper anchor links
    - `TestMarkdownBuilder_NATRulesEmptyInterfaceList`: Verifies empty
    interface lists are handled gracefully

    ### Acceptance Criteria Verified

    | Criterion | Status |
    |-----------|--------|
    | NAT rule interface names rendered as clickable hyperlinks | Done |
    | Links use correct anchor format `#<interface>-interface` | Done |
    | Multi-interface rules render as comma-separated links | Done |
    | Empty interface lists handled gracefully | Done |

    ## Test plan

    - [x] `just ci-check` passes
    - [x] New tests verify link format, not just presence of interface names
    - [x] Tests cover both outbound and inbound NAT rules
    - [x] Tests cover single and multi-interface cases
    - [x] Tests cover empty interface edge case


### Miscellaneous Tasks

- Update changelog generation process
    - Removed GO_VERSION dependency and added mdformat for improved changelog generation.
    - Formatted changelog for v1.0.0 release.

    Tested with `just test` and `just ci-check`, all checks passed successfully.

- Clean up formatting in copilot instructions
- *(docs)* Update GitHub Copilot instructions for clarity
- *(docs)* Add guidelines for project structure, Go development, and plugin architecture
    - Add documentation consistency rules for markdown
    - Add Go project organization and development standards
    - Add Go testing and plugin architecture guidelines
    - Add requirements management and project structure docs

- *(docs)* Update copilot and project guidelines for clarity
- *(converter)* Update firewall rules table to include IP version
- *(roadmap)* Add v2.0 roadmap outlining major changes
- Remove FOSSA configuration files and workflows as part of project cleanup
- Remove Snyk workflow from GitHub Actions
    - Deleted the Snyk security scan workflow file from the GitHub Actions directory.
    - Updated documentation to reflect the removal and integration of Snyk as a GitHub App for vulnerability scanning.

    No tests affected; all existing tests passed successfully.

- Remove Snyk workflow from GitHub Actions
    - Deleted the Snyk security scan workflow file from the GitHub Actions directory.
    - Updated documentation to reflect the removal and integration of Snyk as a GitHub App for vulnerability scanning.

    No tests affected; all existing tests passed successfully.

- Remove team entry from FOSSA configuration
    - Deleted the `team` field from the `.fossa.yml` configuration file to streamline project settings.
    - This change does not affect any functionality or tests.

    All tests passed successfully; no tests were affected by this change.

- Enhance justfile with dependency update targets
    - Added new targets in the `justfile` for updating Go, Python, and pnpm dependencies, as well as pre-commit hooks and development tools.
    - Removed the outdated `team` entry from the `.fossa.yml` configuration file.

    All tests passed successfully; no tests were affected by these changes.

- Update README badges for improved visibility
    - Replaced the coverage badge with a Codecov badge for better integration with coverage reporting.
    - This change enhances the project's documentation and visibility regarding code coverage.

    All tests passed successfully; no tests were affected by this change.

- *(config)* Update .coderabbit.yaml for improved formatting and timeout settings
    - Reformatted tone instructions for better readability.
    - Changed auto title placeholders and instructions to use single quotes for consistency.
    - Increased GitHub checks timeout from 90 seconds to 300 seconds.

    All tests passed successfully; no tests were affected by these changes.

- *(rules)* Reorganize and update Cursor rules for clarity and consistency
    - Deleted outdated rules files: `commit-style.mdc`, `compliance-standards.mdc`, `project-structure.mdc`.
    - Introduced new `INDEX.md` for quick reference to Cursor rules and their organization.
    - Added comprehensive documentation for AI assistant guidelines and development workflow.
    - Established clear project structure and requirements management guidelines to enhance maintainability.

    All tests passed successfully; no tests were affected by these changes.

- *(config)* Update .coderabbit.yaml for enhanced CLI usability and documentation
    - Revised tone instructions to focus on OPNsense XML parsing, markdown generation, and audit compliance.
    - Disabled free tier access for improved control and security.
    - Updated review profile to assertive and added detailed labeling instructions for issue categorization.

    All tests passed successfully; no tests were affected by these changes.

- Update documentation and improve formatting
    - Enhanced GitHub Copilot instructions for clarity.
    - Streamlined pull request template for better usability.
    - Updated pre-commit configuration for improved hooks.
    - Consolidated badge display in README for better readability.
    - Refined usage examples for concise instructions.
    - Improved migration guide formatting for better readability.
    - Updated test suite documentation for clarity.

- Update .mdformat.toml to include additional exclusions
- Update actionlint version to v1.7.10
- Add prompts for Continuous Integration Check and Simplicity Review
- Update code structure for better readability
- Remove requirements management document
    The requirements management instructions document has been deleted as it is no longer needed. Consolidated development standards and project structure have been updated in AGENTS.md to reflect this change.

- Update CI workflow for improved dependency management
    - Upgrade actions/checkout to v6
    - Use just for dependency installation
    - Update golangci-lint action to v9

- Refactor justfile for improved organization
    - Consolidate setup and installation commands
    - Streamline dependency management
    - Enhance readability and maintainability

- Update CI workflow for improved linting and testing
- Update golangci-lint version to v2.8
- Update model version in CI check prompt
- Update formatting and error handling in CONTRIBUTING.md
- Update code block formatting in AGENTS.md
- Improve formatting of user stories in documentation
    Consolidate user story formatting for better readability and consistency throughout the user_stories.md file.

- Enhance error handling and improve code clarity
    - Updated template cache creation functions to handle errors gracefully.
    - Modified generation engine determination to return errors for unknown types.
    - Improved test cases to validate error scenarios.
    - Refactored code for better readability and maintainability.

- Consolidate role definition formatting in documentation
- Remove gomod dependency updates from config
- Fix formatting inconsistencies in documentation
- Fix numbering format in AI agent practices
- Improve formatting and clarity in compliance guide
- Improve formatting and readability in README.md
- Remove CodeQL workflow configuration
- Update migration guides for template support removal
    - Removed checkmarks from migration guide and function mapping for clarity.
    - Updated compliance report formatting for consistency.

- Add .gitignore and project.yml for configuration
- Enhance error handling and warning messages in migration script
    - Updated error handling to exit on error/unset vars.
    - Introduced a consistent warning printing function.
    - Replaced direct status prints with warning function for clarity.

- Update .coderabbit.yaml with schema and formatting fixes
    Added yaml-language-server schema reference for improved validation. Updated string quoting for placeholders and instructions to ensure consistency and compatibility.

- Add Charmbracelet ecosystem compatibility research
    - Introduced a new document for dependency analysis, version matrix, breaking changes, and upgrade recommendations for the Charmbracelet package ecosystem.
    - Updated JSON, YAML, and Markdown converters to normalize line endings based on the platform.
    - Enhanced tests to validate platform-specific line endings and encoding issues.

- Add initial vale configuration file
- Update .gitignore to include coverage and test files
- Remove bash from supported languages list
- Update line ending normalization with logging support
    - Refactored normalizeLineEndings function to accept a logger for warnings.
    - Removed redundant line ending normalization code from multiple files.
    - Added comprehensive tests for line ending normalization behavior.

- Migrate to mise for tool management and CI updates (#172)
    * chore: migrate to mise for tool management and CI updates

    - Replace setup-go and setup-node actions with mise-action in CI workflows.
    - Update justfile to utilize mise for managing development tools.
    - Add mise.toml for tool version management.
    - Remove obsolete commitlint configuration file.

- *(devcontainer)* Add nonFreePackages and claude-code feature
- *(docs)* Update audit and compliance documentation
    - Removed references to audit functionality in v1.0.
    - Deferred audit mode features to v2.1 for clarity.
    - Updated examples and notes in automation and troubleshooting guides.
    - Adjusted user stories and tasks to reflect deferred features.

- Fix indentation in convert command examples
- Update Go and tool versions in mise.toml
- Refactor markdown generation to use converter package (#183)
    This pull request refactors the codebase to remove direct dependencies
    on the legacy `markdown` package, replacing it with the newer
    `converter` and `converter/builder` packages. This improves modularity,
    future-proofs the code, and provides clearer separation between report
    generation logic and markdown formatting. The update touches CLI
    commands, tests, and introduces new helper and compatibility modules.

    **Migration from `markdown` to `converter` and `builder`:**

    * All references to `markdown.Options`, `markdown.Format`,
    `markdown.Theme`, and generator functions are replaced with their
    `converter` equivalents in CLI command files (`cmd/convert.go`,
    `cmd/display.go`) and related tests.
    [[1]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485L511-R516)
    [[2]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485L675-R676)
    [[3]](diffhunk://#diff-b579cf2ee593864eee64ebab2f7a6173a4a90365f6d4c9fff26130eec6e5da66L155-R155)
    [[4]](diffhunk://#diff-b579cf2ee593864eee64ebab2f7a6173a4a90365f6d4c9fff26130eec6e5da66L184-R186)
    [[5]](diffhunk://#diff-e733ee1b937b9e1ab3ae3e2fdcfb0a962e9a1b8e0d9616925185282155779961L80-R82)
    [[6]](diffhunk://#diff-e733ee1b937b9e1ab3ae3e2fdcfb0a962e9a1b8e0d9616925185282155779961L94-R102)
    [[7]](diffhunk://#diff-e733ee1b937b9e1ab3ae3e2fdcfb0a962e9a1b8e0d9616925185282155779961L128-R130)
    [[8]](diffhunk://#diff-0acfc12cd16678cd621b85358d5964cf21305e5c0442e6f0d99f8fb29fe8095bL13-R13)
    [[9]](diffhunk://#diff-0acfc12cd16678cd621b85358d5964cf21305e5c0442e6f0d99f8fb29fe8095bL139-R139)
    [[10]](diffhunk://#diff-0acfc12cd16678cd621b85358d5964cf21305e5c0442e6f0d99f8fb29fe8095bL150-R154)
    [[11]](diffhunk://#diff-0acfc12cd16678cd621b85358d5964cf21305e5c0442e6f0d99f8fb29fe8095bL163-R167)
    [[12]](diffhunk://#diff-b579cf2ee593864eee64ebab2f7a6173a4a90365f6d4c9fff26130eec6e5da66R14-L15)
    [[13]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485R19-L21)
    [[14]](diffhunk://#diff-b579cf2ee593864eee64ebab2f7a6173a4a90365f6d4c9fff26130eec6e5da66L195-R197)
    [[15]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485L537-R537)
    [[16]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485L660-R660)
    [[17]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485L692-R692)
    [[18]](diffhunk://#diff-3f25b8d534eca4ae5511295cc530ea2f792e3041b0361676093476ddfdccd485L707-R710)
    [[19]](diffhunk://#diff-e733ee1b937b9e1ab3ae3e2fdcfb0a962e9a1b8e0d9616925185282155779961R10-L11)

    **Introduction of new builder and formatters helpers:**

    * Adds `internal/converter/builder/helpers.go`, providing a suite of
    utility methods for markdown table formatting, string manipulation, risk
    assessment, and data aggregation, all delegated to the `formatters`
    package.
    * Adds `internal/converter/builder/errors.go` for builder-specific error
    definitions.
    * Adds a stub `internal/converter/builder/options.go` for builder
    options.

    **Compatibility layer for legacy API:**

    * Introduces `internal/converter/compat.go`, which provides deprecated
    type aliases and functions to maintain backward compatibility for
    callers still using the old `markdown` API. All legacy formatting
    functions are mapped to the new `formatters` implementations.

    These changes modernize the report generation pipeline, making it easier
    to extend and maintain while ensuring legacy code continues to work.

    ---------

- *(config)* Gitignore .claude/settings.local.json
    User-specific permission settings should not be tracked in version
    control. The .local. naming convention indicates machine-specific
    configuration that may differ between users.

- Bump dependencies ci: update GitHub Actions to newer versions (#220)
    This pull request updates several GitHub Actions workflows to use the
    latest versions of commonly used actions. The primary focus is on
    upgrading actions for code checkout, environment setup, artifact
    uploading, and some security and container registry steps. These changes
    help ensure better reliability, security, and compatibility with the
    latest GitHub Actions features.

    **Workflow action version upgrades:**

    * Upgraded `actions/checkout` from `v6` to `v6.0.2` across all workflows
    for more precise version pinning and potential bug fixes.
    [[1]](diffhunk://#diff-22eef62c9d7b36d02f5fd5aaada92702e22d6795c464239cb7b8fe0f26ea1e1cL25-R27)
    [[2]](diffhunk://#diff-22eef62c9d7b36d02f5fd5aaada92702e22d6795c464239cb7b8fe0f26ea1e1cL153-R155)
    [[3]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL20-R21)
    [[4]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL43-R45)
    [[5]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL67-R68)
    [[6]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL85-R86)
    [[7]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL110-R112)
    [[8]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL139-R140)
    [[9]](diffhunk://#diff-98dad98422cf59793a353f9b6bfe6a129977e92af3d5b4e38f98ae45bcb7560dL20-R21)
    [[10]](diffhunk://#diff-9cf2000c53760d837a449f874e53f792819108d3a4bf346336d0f7d082deae2cL25-R26)
    [[11]](diffhunk://#diff-87db21a973eed4fef5f32b267aa60fcee5cbdf03c67fafdc2a9b553bb0b15f34L22-R33)
    [[12]](diffhunk://#diff-a3f913c1fa8c348e5409e1fe8data2933204d77ab0f67cb99d67c84a2035ca875L16-R17)
    * Updated `jdx/mise-action` from `v2` to `v3` in all workflows for
    environment setup improvements.
    [[1]](diffhunk://#diff-22eef62c9d7b36d02f5fd5aaada92702e22d6795c464239cb7b8fe0f26ea1e1cL25-R27)
    [[2]](diffhunk://#diff-22eef62c9d7b36d02f5fd5aaada92702e22d6795c464239cb7b8fe0f26ea1e1cL153-R155)
    [[3]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL20-R21)
    [[4]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL43-R45)
    [[5]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL67-R68)
    [[6]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL85-R86)
    [[7]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL110-R112)
    [[8]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL139-R140)
    [[9]](diffhunk://#diff-98dad98422cf59793a353f9b6bfe6a129977e92af3d5b4e38f98ae45bcb7560dL20-R21)
    [[10]](diffhunk://#diff-9cf2000c53760d837a449f874e53f792819108d3a4bf346336d0f7d082deae2cL25-R26)
    [[11]](diffhunk://#diff-87db21a973eed4fef5f32b267aa60fcee5cbdf03c67fafdc2a9b553bb0b15f34L22-R33)
    [[12]](diffhunk://#diff-a3f913c1fa8c348e5409e1fe8data2933204d77ab0f67cb99d67c84a2035ca875L16-R17)

    **Artifact upload and security steps:**

    * Bumped `actions/upload-artifact` from `v3`/`v4` to `v6` for artifact
    upload steps in all relevant workflows, including benchmarks, SBOM,
    release, and documentation.
    [[1]](diffhunk://#diff-22eef62c9d7b36d02f5fd5aaada92702e22d6795c464239cb7b8fe0f26ea1e1cL137-R137)
    [[2]](diffhunk://#diff-22eef62c9d7b36d02f5fd5aaada92702e22d6795c464239cb7b8fe0f26ea1e1cL200-R200)
    [[3]](diffhunk://#diff-b803fcb7f17ed9235f1e5cb1fcd2f5d3b2838429d4368ae4c57ce4436577f03fL169-R169)
    [[4]](diffhunk://#diff-87db21a973eed4fef5f32b267aa60fcee5cbdf03c67fafdc2a9b553bb0b15f34L49-R49)
    [[5]](diffhunk://#diff-a3f913c1fa8c348e5409e1fe8data2933204d77ab0f67cb99d67c84a2035ca875L42-R42)
    [[6]](diffhunk://#diff-42c9e8de9b02b38190aa003b14db6be144d9d6f34b266cf401330e9e62a3bba9L240-R240)
    * Updated the pinned commit for `actions/upload-artifact` in
    `scorecard.yml` to a newer commit on `v4.4.0`.
    * Upgraded `github/codeql-action/upload-sarif` from a v3 commit to a v4
    commit in `scorecard.yml` for improved security scanning integration.

    **Container registry and Docker steps:**

    * Upgraded `docker/login-action` from `v3.6.0` to `v3.7.0` in the
    release workflow to ensure the latest features and fixes for container
    publishing.

    ---------


## [1.0.0] - 2025-08-04

### Features

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


### Bug Fixes

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


### Refactor

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


### Miscellaneous Tasks

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

### Features

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
    - Updated `.github/workflows/release.yml` to trigger the release workflow on git tag pushes matching 'v*'.
    - Marked TASK-063 as complete in `tasks.md`, confirming the implementation of the automated release process with GoReleaser.
    - Added detailed notes on the release management features, including multi-platform builds and Docker support.

    Tested with `just test` and `just ci-check`, all checks passed successfully.


### Bug Fixes

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


### Refactor

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


### Documentation

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

- Update mapping table with issue #26 for Phase 4.3 tasks (TASK-023–TASK-029)
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


### Testing

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


### Miscellaneous Tasks

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
