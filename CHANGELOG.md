# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **schema**: NATS-3 audit and harden public API surface for cross-repo consumption ([#569](https://github.com/EvilBit-Labs/opnDossier/pull/569))
- **schema**: Parse OPNsense Unbound MVC and flip FIREWALL-007 polarity - NATS-77 ([#571](https://github.com/EvilBit-Labs/opnDossier/pull/571))
- **parser**: Audit and harden public API surface - NATS-144 ([#575](https://github.com/EvilBit-Labs/opnDossier/pull/575))

### Changed

- **[breaking]** Renamed `CommonDevice.ComplianceChecks` -> `CommonDevice.ComplianceResults`
  to match the `ComplianceResults` type name. JSON tag also renames
  (`complianceChecks` -> `complianceResults`). Affects `pkg/model` public API
  from v1.5; pre-v1.5 consumers had no semver commitment.
  See `docs/development/public-api.md` § Current Regime.
- **[breaking]** Renamed `pkg/parser.XMLDecoder` -> `pkg/parser.OPNsenseXMLDecoder`
  to reflect that the interface is typed to `*schema.OpnSenseDocument` and
  cannot be used for pfSense parsing. Affects `pkg/parser` public API from
  v1.5; pre-v1.5 consumers had no semver commitment.
- **mergify**: Upgrade configuration to current format ([#543](https://github.com/EvilBit-Labs/opnDossier/pull/543))
- Update labeling instructions and configuration settings in `.coderabbit.yaml`
- Add OPNsense/pfSense XML data structure research ([#547](https://github.com/EvilBit-Labs/opnDossier/pull/547))
- **NATS-6**: Remove template system dead code for v2.0 ([#550](https://github.com/EvilBit-Labs/opnDossier/pull/550))
- Address CodeRabbit feedback from PR #550 ([#552](https://github.com/EvilBit-Labs/opnDossier/pull/552))
- **NATS-7**: Replace O(n²) duplicate rule detection with hash buckets ([#554](https://github.com/EvilBit-Labs/opnDossier/pull/554))
- **NATS-6**: Clean up residuals after template system removal ([#556](https://github.com/EvilBit-Labs/opnDossier/pull/556))
- Add Jira as primary task tracker to Rules of Engagement
- Update heading level for Agent Rules and remove unused dependency from `tessl.json`
- **pkg**: Audit converters and ConversionWarning API — NATS-145 ([#580](https://github.com/EvilBit-Labs/opnDossier/pull/580))
- **api**: Document public pkg/ consumer contract - NATS-146
- **tooling**: Phase 1 — infrastructure and pre-commit quality gates
- **ci,release,docs**: Phase 2 round 2 — CI matrix, coverage gate, docker snapshot, action pin

### Fixed

- **firewall,schema**: Post-merge review feedback on NATS-77 (PR #571) ([#573](https://github.com/EvilBit-Labs/opnDossier/pull/573))
- **parser**: Liberal boolean parsing for OPNsense config.xml ([#558](https://github.com/EvilBit-Labs/opnDossier/pull/558)) ([#577](https://github.com/EvilBit-Labs/opnDossier/pull/577))

### Security

- **security,deps,docs**: Phase 2 round 1 — new `.github/workflows/security.yml` (govulncheck + Trivy), 9 pseudo-version indirect deps inventoried in `go.mod`, and `SECURITY.md` aligned with the actual scanner set (Grype/Snyk claims removed)

## [1.4.0] - 2026-04-03

### Features

- **parser**: Add IPsec parsing support for pfSense configurations ([#476](https://github.com/EvilBit-Labs/opnDossier/pull/476))

- **plugin**: Report compliant controls alongside findings in blue mode reports ([#495](https://github.com/EvilBit-Labs/opnDossier/pull/495))

- Parse full Kea DHCP4 subnets and unify with ISC DHCP in CommonDevice ([#519](https://github.com/EvilBit-Labs/opnDossier/pull/519))

- Add basic `Dockerfile` and `action.yaml` ([#521](https://github.com/EvilBit-Labs/opnDossier/pull/521))


### Bug Fixes

- **release**: Fix universal binary, man pages, and release footer ([#477](https://github.com/EvilBit-Labs/opnDossier/pull/477))

- **cli**: Defer audit plugin name validation to support dynamic plugins ([#480](https://github.com/EvilBit-Labs/opnDossier/pull/480))

- **audit**: Count info severity, add inventory controls, render Configuration Notes ([#449](https://github.com/EvilBit-Labs/opnDossier/pull/449)) ([#510](https://github.com/EvilBit-Labs/opnDossier/pull/510))

- **cli**: Scope --json-output flag to validate command only ([#516](https://github.com/EvilBit-Labs/opnDossier/pull/516))

- **docs**: Resolve broken links for GitHub Pages

- **docs**: Split XML fragments into individual code blocks

- **sanitize**: Pseudonymize authserver LDAP values ([#529](https://github.com/EvilBit-Labs/opnDossier/pull/529))

- Comprehensive tech debt cleanup — security, CI, docs, tests, refactors ([#535](https://github.com/EvilBit-Labs/opnDossier/pull/535))

- Update versions for Jeffallan/claude-skills and mcollina/skills dependencies


### Documentation

- Update CONTRIBUTING.md and development standards

- Add all-contributors recognition ([#530](https://github.com/EvilBit-Labs/opnDossier/pull/530))

- Add KryptoKat08 as a contributor for security ([#534](https://github.com/EvilBit-Labs/opnDossier/pull/534))


### Miscellaneous Tasks

- **repo**: Untrack local AI tooling configs from version control


## [1.3.0] - 2026-03-23

### Features

- **audit**: Implement dynamic logging levels for audit mode ([#257](https://github.com/EvilBit-Labs/opnDossier/pull/257))

- **schema**: Fix schema gaps with missing fields and type mismatches ([#258](https://github.com/EvilBit-Labs/opnDossier/pull/258))

- **converter**: Add text and HTML output formats with alert rendering ([#264](https://github.com/EvilBit-Labs/opnDossier/pull/264))

- **model**: Enhance OPNsense converters and configurations with tests and fields ([#315](https://github.com/EvilBit-Labs/opnDossier/pull/315))

- **converter**: Make sensitive field redaction opt-in via `--redact` flag ([#326](https://github.com/EvilBit-Labs/opnDossier/pull/326))

- **sanitize**: Additional tags for the sanitize command: secrets & topology ([#344](https://github.com/EvilBit-Labs/opnDossier/pull/344))

- **converter**: Add non-fatal conversion warnings to OPNsense converter pipeline ([#394](https://github.com/EvilBit-Labs/opnDossier/pull/394))

- **pkg**: Expose schemas and CommonDevice model as public packages ([#404](https://github.com/EvilBit-Labs/opnDossier/pull/404))

- **parser**: Add pluggable DeviceParser registry for compile-time extensions ([#437](https://github.com/EvilBit-Labs/opnDossier/pull/437))

- **plugin**: Add panic recovery around plugin RunChecks calls ([#309](https://github.com/EvilBit-Labs/opnDossier/pull/309)) ([#442](https://github.com/EvilBit-Labs/opnDossier/pull/442))

- **plugin**: Surface dynamic plugin load failures to user ([#445](https://github.com/EvilBit-Labs/opnDossier/pull/445))

- **cli**: Add dedicated audit command as first-class entry point ([#454](https://github.com/EvilBit-Labs/opnDossier/pull/454))

- **parser**: Add pfSense configuration parser with multi-device abstraction ([#459](https://github.com/EvilBit-Labs/opnDossier/pull/459))


### Bug Fixes

- **builder**: Add Dest Port column and fix Any field handling ([#253](https://github.com/EvilBit-Labs/opnDossier/pull/253)) ([#254](https://github.com/EvilBit-Labs/opnDossier/pull/254))

- **converter**: Sort map iterations for deterministic report output ([#256](https://github.com/EvilBit-Labs/opnDossier/pull/256))

- **model**: Address PR #273 review findings ([#277](https://github.com/EvilBit-Labs/opnDossier/pull/277))

- **processor**: Restore semantic validation for CommonDevice ([#303](https://github.com/EvilBit-Labs/opnDossier/pull/303))

- **plugin**: Implement firewall compliance check helpers ([#305](https://github.com/EvilBit-Labs/opnDossier/pull/305))

- **dependencies**: Update uv to version 0.10.6 and specify platform checksums

- **processor**: Prevent shared backing array mutations in normalize   deep copy all mutable slice fields ([#313](https://github.com/EvilBit-Labs/opnDossier/pull/313))

- **audit**: Resolve severity breakdown missing in audit reports ([#310](https://github.com/EvilBit-Labs/opnDossier/pull/310)) ([#373](https://github.com/EvilBit-Labs/opnDossier/pull/373))

- **diff**: Restore section added/removed detection for value types ([#388](https://github.com/EvilBit-Labs/opnDossier/pull/388))

- **mise.lock**: Remove duplicate gosec entry and add baseline support for uv tool across platforms

- **converter**: Wire --include-tunables flag through display and convert commands ([#413](https://github.com/EvilBit-Labs/opnDossier/pull/413))

- **report**: Add certificate and CA private key redaction to report serialization ([#470](https://github.com/EvilBit-Labs/opnDossier/pull/470))

- **pfsense**: Resolve interfaces and DHCP scopes always reporting as disabled ([#461](https://github.com/EvilBit-Labs/opnDossier/pull/461)) ([#473](https://github.com/EvilBit-Labs/opnDossier/pull/473))

- **release**: Reset mise.lock to avoid dirty-tree failure and add platform checksums

- **ci**: Install cyclonedx-gomod in release workflow for SBOM generation

- **ci**: Strip mise shims from PATH before goreleaser SBOM generation

- **ci**: Delete mise go shim instead of PATH manipulation

- **release**: Include shell completions in archive tarballs


### Refactor

- **model**: Address tech debt across model, enrichment, display, and logging ([#269](https://github.com/EvilBit-Labs/opnDossier/pull/269))

- **model**: Multi-device model layer with CommonDevice and ParserFactory ([#273](https://github.com/EvilBit-Labs/opnDossier/pull/273))

- Harden multi-device model, fix bugs, and remove CIS trademark references ([#274](https://github.com/EvilBit-Labs/opnDossier/pull/274))

- Unify finding types across compliance processor and audit packages to eliminate duplication ([#391](https://github.com/EvilBit-Labs/opnDossier/pull/391))

- **audit**: Move audit report rendering from cmd to converter/builder layer ([#400](https://github.com/EvilBit-Labs/opnDossier/pull/400))

- **docs**: Update AGENTS.md and add pkg-internal-import-boundary… ([#408](https://github.com/EvilBit-Labs/opnDossier/pull/408))

- **analysis**: Extract shared analysis package to eliminate enrichment mirror ([#409](https://github.com/EvilBit-Labs/opnDossier/pull/409))

- **processor**: Split report.go into focused files ([#415](https://github.com/EvilBit-Labs/opnDossier/pull/415))

- **validator**: Split opnsense.go into domain specific files ([#417](https://github.com/EvilBit-Labs/opnDossier/pull/417))

- **builder**: Split builder.go into domain-specific files ([#419](https://github.com/EvilBit-Labs/opnDossier/pull/419))

- **builder**: Split ReportBuilder interface into focused interfaces ([#431](https://github.com/EvilBit-Labs/opnDossier/pull/431))

- **converter**: Introduce FormatRegistry to centralize format dispatch ([#434](https://github.com/EvilBit-Labs/opnDossier/pull/434))

- **model**: Improve type safety with enums for firewall rules, NAT, and DHCP ([#452](https://github.com/EvilBit-Labs/opnDossier/pull/452))

- **audit**: Remove standard mode — duplicates convert with no audit value ([#465](https://github.com/EvilBit-Labs/opnDossier/pull/465))


### Documentation

- Fix inaccurate content across MkDocs site ([#267](https://github.com/EvilBit-Labs/opnDossier/pull/267))

- Updates for PR #348 ([#349](https://github.com/EvilBit-Labs/opnDossier/pull/349))

- Rewrite data-model docs for CommonDevice export model ([#355](https://github.com/EvilBit-Labs/opnDossier/pull/355))

- Add comprehensive requirements document for opnDossier CLI tool ([#371](https://github.com/EvilBit-Labs/opnDossier/pull/371))

- Add plugin development guide and API reference ([#377](https://github.com/EvilBit-Labs/opnDossier/pull/377))

- **user-guide**: Restructure commands documentation ([#381](https://github.com/EvilBit-Labs/opnDossier/pull/381))

- **audit**: Document thread-safety guarantees for global PluginRegistry ([#290](https://github.com/EvilBit-Labs/opnDossier/pull/290)) ([#384](https://github.com/EvilBit-Labs/opnDossier/pull/384))

- Add plugin development guide and update API/architecture docs ([#393](https://github.com/EvilBit-Labs/opnDossier/pull/393))

- Add comprehensive system architecture documentation ([#402](https://github.com/EvilBit-Labs/opnDossier/pull/402))

- Expand contributing guide with architecture and governance ([#406](https://github.com/EvilBit-Labs/opnDossier/pull/406))

- **agents**: Fix translateCommonStats path after report.go split

- **contributing**: Sync CONTRIBUTING.md with AGENTS.md coverage ([#440](https://github.com/EvilBit-Labs/opnDossier/pull/440))

- **gotchas**: Add guidelines for git tagging after squash-merge commits

- Comprehensively restructure README and add Copilot guidance ([#467](https://github.com/EvilBit-Labs/opnDossier/pull/467))

- Add comprehensive security assurance case document ([#471](https://github.com/EvilBit-Labs/opnDossier/pull/471))


### Miscellaneous Tasks

- **Mergify**: Configuration update ([#259](https://github.com/EvilBit-Labs/opnDossier/pull/259))

- **ci**: Various minor improvements to mergify configs, documentation, mise settings, and AGENTS.md rules ([#348](https://github.com/EvilBit-Labs/opnDossier/pull/348))

- **changelog**: Update changelog with new features, bug fixes, and refactors


### Security

- Overhaul SECURITY.md and add fuzz tests ([#252](https://github.com/EvilBit-Labs/opnDossier/pull/252))


## [1.2.2] - 2026-02-12

### Features

- **security**: Add security policy documentation  

- **templates**: Add issue and pull request templates

- **config**: Add new sample configuration files for OPNsense

- Add support for including system tunables in report generation

- Add initial configuration for CodeRabbit integration

- Implement embedded template functionality and testing

- Enhance build tests for embedded templates

- Add opnsense configuration DTD and update XSD schema

- Enhance display options and add new utility functions

- Add GitHub Actions workflow testing commands for Unix and Windows

- Add utility functions for boolean evaluation and formatting

- Refactor command flags and shared functionality for convert and display commands

- Enhance release process and documentation

- Enhance CI workflows and documentation for compliance

- **compliance**: Complete Pipeline v2 standards implementation

- Enhance CI workflows and documentation for compliance

- Integrate local Snyk and FOSSA scanning into the justfile

- Enhance release process with security features and tooling

- Enhance CI workflows and documentation for compliance

- Enhance CI workflows and documentation for compliance

- Add release-please configuration and clean up CI workflows

- Update GoReleaser and CI workflows for enhanced artifact signing

- **NAT**: Prominently display NAT mode and forwarding rules with enhanced security information

- **NAT**: Prominently display NAT mode and forwarding rules with enhanced security information

- **NAT**: Add inbound rules to NAT summary and enhance report templates

- **NAT**: Update inbound rules representation in NAT struct and report templates

- **NAT**: Refactor NATSummary method for safety and clarity

- **ci**: Implement Windows smoke-only testing strategy

- **ci**: Enhance smoke test commands and CI workflow conditions

- **ci**: Add Copilot setup steps workflow for automated environment configuration

- **ci**: Enhance Copilot setup workflow with additional tools and validation steps

- **ci**: Simplify Copilot setup workflow by removing options and adding bash  check

- **ci**: Update pre-commit configuration and enhance Copilot setup workflow

- **markdown**: Enhance interface link formatting in markdown reports

- **markdown**: Improve inline link formatting for interfaces in markdown

- **constants**: Add gateway complexity weights and report template paths

- **reports**: Implement gateway groups in reports for GitHub Issue 65

- **metrics**: Add configuration metrics calculations and tests

- **tests**: Add comprehensive tests for MarkdownBuilder functionality

- **markdown**: Implement hybrid markdown generator for flexible output

- **template**: Implement caching for template loading and enhance test coverage

- **template**: Integrate LRU caching for template management and enhance test coverage

- **converter**: Implement utility functions for template migration Phase 3.2

- **converter**: Implement data transformation functions for markdown generation

- **converter**: Implement Phase 3.4 security assessment functions

- **test**: Complete comprehensive test suite for ported methods

- **test**: Add performance baseline validation and fix TERM environment issues

- **benchmarks**: Add comprehensive performance benchmarking suite

- **cli**: Implement programmatic mode by default with engine selection

- **cli**: Add comprehensive tests, config support, and migration guide

- **docs**: Update agent practices and migration guide with critical task completion note

- **docs**: Refine requirements management guidelines

- **docs**: Enhance requirements management documentation

- **docs**: Add comprehensive migration guide for custom template users

- Add settings.local.json for permission configuration

- Enhance command validation and error handling

- **docs**: Add release and development standards documentation

- Implement template mode deprecation framework for v2.0 ([#151](https://github.com/EvilBit-Labs/opnDossier/pull/151))

- **ci**: Enhance Grype vulnerability scanning in CI pipeline ([#156](https://github.com/EvilBit-Labs/opnDossier/pull/156))

- **display**: Implement proper text wrapping support for --wrap flag ([#158](https://github.com/EvilBit-Labs/opnDossier/pull/158))

- **parser**: Implement proper ISO-8859-1 and Windows-1252 encoding support ([#169](https://github.com/EvilBit-Labs/opnDossier/pull/169))

- Add --no-wrap flag as explicit alias for --wrap 0 ([#170](https://github.com/EvilBit-Labs/opnDossier/pull/170))

- **devcontainer**: Add Go development container configuration

- **compliance**: Add extended checks for password policy and audit logging ([#181](https://github.com/EvilBit-Labs/opnDossier/pull/181))

- **display**: Improve NAT rule directionality presentation in markdown reports ([#182](https://github.com/EvilBit-Labs/opnDossier/pull/182))

- Complete template system migration and removal for v2.0 ([#184](https://github.com/EvilBit-Labs/opnDossier/pull/184))

- **cmd**: Implement CommandContext pattern for dependency injection ([#188](https://github.com/EvilBit-Labs/opnDossier/pull/188))

- **converter**: Add streaming generation for large configurations ([#189](https://github.com/EvilBit-Labs/opnDossier/pull/189))

- Cli interface enhancement,  command structure, help system, progress completion ([#193](https://github.com/EvilBit-Labs/opnDossier/pull/193))

- **config**: Enhance configuration management system ([#194](https://github.com/EvilBit-Labs/opnDossier/pull/194))

- **hardening**: Epic - Production Hardening (Phases 1-4) ([#214](https://github.com/EvilBit-Labs/opnDossier/pull/214))

- **processor**: Implement comprehensive service detection for unused interface analysis ([#215](https://github.com/EvilBit-Labs/opnDossier/pull/215))

- **docs**: Add comprehensive template documentation and model reference ([#216](https://github.com/EvilBit-Labs/opnDossier/pull/216))

- **builder**: Add missing network sections to comprehensive report ([#218](https://github.com/EvilBit-Labs/opnDossier/pull/218))

- Enhanced dhcp reporting   expand coverage of server configuration static mappings and advanced options feat(markdown-builder): add DHCP table generation ([#223](https://github.com/EvilBit-Labs/opnDossier/pull/223))

- **cmd**: Integrate audit mode and compliance plugin system into CLI ([#224](https://github.com/EvilBit-Labs/opnDossier/pull/224))

- **diff**: Add configuration diff tool for OPNsense XML comparison ([#227](https://github.com/EvilBit-Labs/opnDossier/pull/227))

- **sanitizer**: Add sanitize command to redact sensitive data from OPNsense configs ([#234](https://github.com/EvilBit-Labs/opnDossier/pull/234))

- Parse and report IDS/Suricata configuration ([#237](https://github.com/EvilBit-Labs/opnDossier/pull/237))

- **diff**: Add HTML formatter, side-by-side mode, analyzers, and security scoring ([#245](https://github.com/EvilBit-Labs/opnDossier/pull/245))


### Bug Fixes

- **display**: Remove validation from display command by default

- **migration**: Update module path instructions in migration.md

- **docs**: Update issue template and installation guide

- **templates**: Update formatting for system notes in OPNsense report template

- **tests**: Simplify markdown test assertions by removing ANSI stripping

- **tests**: Enhance config test assertions and output path handling

- **validate**: Display all validation errors instead of just the first one

- Standardize MTU field naming in VPN model and templates

- Standardize PSK field naming in VPN model and templates

- Improve number parsing in IsTruthy function

- Update directory permissions and timestamp formatting

- Update logging methods and documentation

- **release**: Remove GO_VERSION dependency and add mdformat to changelog generation

- Refactor firewall rule interface handling to support multiple interfaces

- **converter**: Update protocol references in markdown templates

- **templates**: Resolve comprehensive report structural inconsistencies with summary report

- Correct minor formatting issues in templates

- **templates**: Correct boolean formatting in OPNsense report templates

- **docs**: Remove unnecessary newline in README.md

- **templates**: Correct boolean formatting in OPNsense report templates

- **tests**: Enhance test coverage and validation checks

- **templates**: Correct boolean formatting in OPNsense report templates

- **templates**: Correct boolean formatting in OPNsense report templates

- **templates**: Correct boolean formatting in OPNsense report templates

- **templates**: Correct boolean formatting in OPNsense report templates

- **ci**: Update git-cliff installation path in Copilot setup workflow

- **test**: Modernize benchmark loops using b.Loop() for Go 1.24+ compatibility

- **docs**: Apply mdformat table formatting to README_TESTS.md

- **docs**: Apply mdformat corrections to README_TESTS.md

- **test**: Adjust performance baseline thresholds to realistic values

- **tests**: Enhance markdown escaping and improve test coverage

- **test**: Adjust performance baseline thresholds for CI environment stability

- **docs**: Clarify task completion requirements and enhance migration guide

- **cmd**: Ensure consistent path separators in getSharedTemplateDir

- **cmd**: Update UseTemplateEngine to prioritize CLI flags over config settings

- **tests**: Update test assertions for markdown library v0.10.0

- **tests**: Improve error message assertions for file not found cases

- **test**: Use windowsOS constant to fix goconst linting issue

- Replace panic based error handling in production code ([#167](https://github.com/EvilBit-Labs/opnDossier/pull/167))

- Remove deprecated logging configuration functions ([#168](https://github.com/EvilBit-Labs/opnDossier/pull/168))

- Remove stubbed audit mode code and defer implementation to v2.1 ([#175](https://github.com/EvilBit-Labs/opnDossier/pull/175))

- **ci**: Add mise trust step before goreleaser

- **ci**: Install cyclonedx-gomod directly to bypass mise shim

- **mise**: Remove cyclonedx-gomod to prevent shim interference

- **ci**: Set MISE_YES=1 at job level for subprocess inheritance

- **ci**: Clean up extracted archives and remove mdformat hook

- **release**: Disable GPG signing until secrets are configured


### Refactor

- Remove JSON and YAML template files and update related functionality

- Simplify opnsense-config XSD schema by removing deprecated elements

- **processor**: Simplify interface check and add context cancellation handling

- Streamline logging configuration and remove deprecated methods

- Replace custom contains function with slices.Contains

- Simplify mapTemplateName and fix help text indentation

- **model**: Split model package into schema and enrichment ([#144](https://github.com/EvilBit-Labs/opnDossier/pull/144)) ([#186](https://github.com/EvilBit-Labs/opnDossier/pull/186))

- **builder**: Leverage markdown library methods to reduce code verbosity ([#222](https://github.com/EvilBit-Labs/opnDossier/pull/222))

- **ci**: Replace mise with vendor actions in release workflow


### Documentation

- Fix changelog format for v1.0.0 release

- Finalize changelog for v1.0.0 release

- Format changelog for v1.0.0 release

- Enhance GitHub Copilot instructions and project overview

- Add project description to core-concepts.mdc

- **copilot**: Expand GitHub Copilot instructions and project guidelines

- **agents**: Expand documentation on brand principles and CI/CD integration standards

- **template**: Fix markdown formatting in template function migration guide

- Complete programmatic markdown generation documentation

- Enhance GitHub Copilot instructions with structured logging and error handling guidelines

- Update migration guide and template function mapping

- Remove template references and add modular report architecture ([#187](https://github.com/EvilBit-Labs/opnDossier/pull/187))

- Add Contributor Covenant Code of Conduct ([#236](https://github.com/EvilBit-Labs/opnDossier/pull/236))

- **go**: Add doc comments to all exported symbols for 100% coverage ([#241](https://github.com/EvilBit-Labs/opnDossier/pull/241))


### Styling

- Fix markdown formatting in security-scoring.md


### Testing

- **coverage**: Improve test coverage to address Codecov requirements

- **converter**: Verify NAT interface hyperlinks ([#217](https://github.com/EvilBit-Labs/opnDossier/pull/217))


### Miscellaneous Tasks

- **ci**: Refactor CI configuration and enhance testing workflow

- **ci**: Add golangci-lint setup to CI workflow

- **justfile**: Add full-checks command to streamline CI process

- **workflow**: Remove summary workflow for issue summarization

- **ci**: Simplify Go version matrix in CI workflow

- **workflow**: Remove summary workflow for issue summarization

- **ci**: Simplify Go version matrix in CI workflow

- Add MIGRATION IN-PROGRESS notice to README.md

- Update compliance and project documentation for opnDossier

- Rename project from opnFocus to opnDossier and update documentation

- Update documentation to reflect project name change to opnDossier

- Update project references and configurations for opnDossier

- Update documentation and configuration for opnDossier

- Update report templates to reflect project name change to opnDossier

- Rename project references from opnFocus to opnDossier

- Add CI and CodeQL badges to README.md

- Add CodeRabbit Pull Request Reviews badge to README.md

- Update .gitignore and justfile for improved coverage reporting

- Update CI workflow and justfile for testing improvements

- Update CI workflow to run tests across all packages

- Update release workflow to include main branch

- Update .coderabbit.yaml configuration

- Update CI configuration and enable GitHub checks

- Update changelog generation process

- Clean up formatting in copilot instructions

- **docs**: Update GitHub Copilot instructions for clarity

- **docs**: Add guidelines for project structure, Go development, and plugin architecture

- **docs**: Update copilot and project guidelines for clarity

- **converter**: Update firewall rules table to include IP version

- **roadmap**: Add v2.0 roadmap outlining major changes

- Remove FOSSA configuration files and workflows as part of project cleanup

- Remove Snyk workflow from GitHub Actions

- Remove Snyk workflow from GitHub Actions

- Remove team entry from FOSSA configuration

- Enhance justfile with dependency update targets

- Update README badges for improved visibility

- **config**: Update .coderabbit.yaml for improved formatting and timeout settings

- **rules**: Reorganize and update Cursor rules for clarity and consistency

- **config**: Update .coderabbit.yaml for enhanced CLI usability and documentation

- Update documentation and improve formatting

- Update .mdformat.toml to include additional exclusions

- Update actionlint version to v1.7.10

- Add prompts for Continuous Integration Check and Simplicity Review

- Update code structure for better readability

- Remove requirements management document

- Update CI workflow for improved dependency management

- Refactor justfile for improved organization

- Update CI workflow for improved linting and testing

- Update golangci-lint version to v2.8

- Update model version in CI check prompt

- Update formatting and error handling in CONTRIBUTING.md

- Update code block formatting in AGENTS.md

- Improve formatting of user stories in documentation

- Enhance error handling and improve code clarity

- Consolidate role definition formatting in documentation

- Remove gomod dependency updates from config

- Fix formatting inconsistencies in documentation

- Fix numbering format in AI agent practices

- Improve formatting and clarity in compliance guide

- Improve formatting and readability in README.md

- Remove CodeQL workflow configuration

- Update migration guides for template support removal

- Add .gitignore and project.yml for configuration

- Enhance error handling and warning messages in migration script

- Update .coderabbit.yaml with schema and formatting fixes

- Add Charmbracelet ecosystem compatibility research

- Add initial vale configuration file

- Update .gitignore to include coverage and test files

- Remove bash from supported languages list

- Update line ending normalization with logging support

- Migrate to mise for tool management and CI updates ([#172](https://github.com/EvilBit-Labs/opnDossier/pull/172))

- **devcontainer**: Add nonFreePackages and claude-code feature

- **docs**: Update audit and compliance documentation

- Fix indentation in convert command examples

- Update Go and tool versions in mise.toml

- Refactor markdown generation to use converter package ([#183](https://github.com/EvilBit-Labs/opnDossier/pull/183))

- **config**: Gitignore .claude/settings.local.json

- Bump dependencies ci: update GitHub Actions to newer versions ([#220](https://github.com/EvilBit-Labs/opnDossier/pull/220))

- Update release workflow and dependencies ([#226](https://github.com/EvilBit-Labs/opnDossier/pull/226))


### Security

- **security**: Pin GitHub Actions to SHA commits ([#240](https://github.com/EvilBit-Labs/opnDossier/pull/240))


## [1.0.0-rc1] - 2025-08-01

### Features

- Enhance XMLParser with security features and input size limit

- Implement basic xml parsing functionality for opnsense configuration files

- **core**: Migrate to fang config and structured logging

- **logging**: Enhance logger initialization with error handling and validation

- **config**: Enhance configuration management and error handling

- **validation**: Introduce comprehensive validation feature for configuration integrity

- **validation**: Implement comprehensive validation system for configuration integrity

- **config**: Add sample configuration files for OPNsense

- **converter**: Add JSON conversion support and enhance output handling

- **templates**: Add comprehensive OPNsense report templates

- **todos**: Add TODO comments for addressing minor gaps in OPNsense analysis

- **tasks**: Mark XML parser and validation tasks as complete

- **tasks**: Update markdown generator tasks with enhanced context

- **docs**: Enhance AGENTS.md and DEVELOPMENT_STANDARDS.md with new features and structure

- Implement comprehensive markdown generation for opnsense configurations

- **markdown**: Introduce new markdown generation and formatting capabilities

- **testdata**: Replace config.xml with opnfocus-config.xsd and add sample configurations

- **opnsense**: Update dependencies and enhance model completeness checks

- **model**: Refactor OPNsense model and enhance documentation

- **model**: Refactor WebGUI and related structures for consistency

- **documentation**: Add comprehensive model completeness tasks for OPNsense

- **model**: Extend SysctlItem and APIKey structures with additional fields

- **tests**: Add debug model paths test for completeness validation

- **github**: Add Dependabot configuration and CodeQL analysis workflow

- **model**: Enhance completeness checks and extend model structures

- **model**: Remove MODEL_COMPLETENESS_TASKS.md and update model structures

- **dependencies**: Update Go module dependencies and improve markdown generator

- **model**: Implement document enrichment and enhance markdown generation

- **cleanup**: Remove unused markdown.py and opnsense.py files, update .editorconfig

- **refactor**: Update types to use `any` and enhance markdown generation

- **model**: Enhance System and User structs with additional fields

- **tests**: Add tests for display functionality and progress handling

- **tasks**: Mark TASK-014 as completed for terminal display implementation

- **display**: Add theme support for terminal display

- **display**: Enhance display command with customizable options

- **user_stories**: Add new user stories for recon report and audits

- **display**: Enhance terminal display tests and functionality

- **user_stories**: Expand acceptance criteria for analyze command modes

- **config**: Add template validation in configuration

- **enrichment**: Add dynamic interface counting and analysis tests

- **reports**: Add markdown templates for blue, red, and standard audit reports

- **tests**: Add comprehensive markdown export validation tests

- **tests**: Add JSON export validation tests

- **tests**: Add YAML export validation tests

- **markdown**: Implement JSON and YAML template-based export functionality

- **output**: Implement output file naming and overwrite protection

- **export**: Enhance file export functionality with comprehensive validation and error handling

- **tests**: Implement comprehensive validation tests for exported files

- **markdown**: Implement escapeTableContent function for markdown templates

- **compliance**: Implement plugin-based architecture for compliance standards

- **docs**: Enhance compliance and core concepts documentation

- **docs**: Update requirements and tasks for audit report generation

- **docs**: Update AI agent guidelines and add development workflow documentation

- **convert**: Enhance conversion command with audit report generation capabilities

- **audit**: Enhance audit report generation and validation logging

- **docs**: Expand tasks for opnFocus CLI tool implementation

- **docs**: Mark TASK-030 as complete for CLI command structure refactor

- **cli**: Enhance command flag organization and documentation

- **docs**: Mark TASK-032 as complete for verbose/quiet output modes

- **docs**: Mark TASK-035 as complete for YAML configuration file support

- **docs**: Add changelog and git-cliff configuration

- **docs**: Mark TASK-035 as complete for YAML configuration file support

- **tests**: Add comprehensive environment variable tests for configuration loading

- **docs**: Mark TASK-037 as complete for CLI flag override system

- **tests**: Enhance audit mode tests and add plugin registry functionality

- **ci**: Add CI workflow for comprehensive checks and testing

- **docs**: Update README and add comprehensive documentation examples

- **goreleaser**: Enhance multi-platform build configuration and add Docker support

- **release**: Enable automated release process on tag pushes


### Bug Fixes

- Format markdown files to pass pre-commit checks

- **logging**: Update logging output and enhance Kubernetes configuration documentation

- **requirements**: Update gofmt reference to golangci-lint

- **docs**: Correct formatting and content in AGENTS.md, DEVELOPMENT_STANDARDS.md, and README.md

- **tests**: Align indentation in completeness_test.go for consistency

- **tests**: Update display tests to use context for improved handling

- **docs**: Update plugin architecture and firewall reference documentation

- Resolve remaining testifylint issues

- **cli**: Update command flag requirements and task status


### Refactor

- Update struct field names in opnsense model for consistency

- **display**: Streamline command definitions and enhance terminal display handling

- Update docstrings for clarity and consistency across multiple files

- **display**: Update terminal display initialization to use options

- **tests**: Simplify command retrieval in convert tests

- **tests**: Replace inline structs with configuration types in OPNsense tests

- **display**: Replace theme string literals with constants in display package

- **markdown**: Optimize configuration content detection in formatters

- **processor**: Enhance CoreProcessor initialization and improve MDNode documentation


### Documentation

- Add project configuration files and documentation for OPNsense CLI tool

- Update project documentation and configuration files for opnFocus

- Enhance project documentation for opnFocus

- Update project documentation and structure for opnFocus

- Update documentation and formatting for opnFocus

- Standardize configuration formatting and update documentation

- **tasks**: Mark TASK-004 and TASK-005 as completed ([#4](https://github.com/EvilBit-Labs/opnDossier/pull/4))

- **CONTRIBUTING**: Add comprehensive contributing guide

- Add comprehensive Copilot instructions for opnFocus project

- **validator**: Clean up comment formatting in `demo.go`

- **CONTRIBUTING**: Standardize commit message formatting in guidelines

- **validator**: Add package-level comments to `opnsense.go`

- Update requirements and user stories documents to include Table of Contents

- **requirements**: Clarify report generation modes and template usage

- Update mapping table with issue #26 for Phase 4.3 tasks (TASK-023–TASK-029)

- Update AGENTS.md and add migration.md for project transition

- **migration**: Enhance migration.md with detailed steps for repository transition

- **configuration**: Improve JSON formatting in configuration.md for clarity

- **migration**: Expand migration.md with detailed commands for repository transition

- **tasks**: Reorganize input validation task in project_spec/tasks.md

- **tasks**: Mark TASK-024 as complete for multi-mode report controller


### Testing

- **tests**: Remove module_files_test.go due to redundancy

- **tests**: Remove markdown_spec_test.go due to redundancy

- **errors**: Add unit tests for AggregatedValidationError functionality


### Miscellaneous Tasks

- Update golangci-lint configuration and justfile for opnFocus

- Update golangci-lint settings and enhance justfile for opnFocus

- Update dependencies and refactor opnFocus CLI structure

- Update module path in go.mod for opnFocus

- Update import paths to use the new module structure

- Update .gitignore and refactor justfile for environment setup

- Add @commitlint/config-conventional dependency for commit message linting

- Update dependencies and .gitignore for improved project structure

- Add CI workflow for golangci-lint

- Remove wsl_v5 linter from golangci configuration

- Update golangci-lint version in CI workflow

- Update configuration management documentation and code

- Streamline environment setup in justfile

- Update configuration management and CLI enhancement documentation

- Update dependabot configuration and release workflow

- Remove outdated OPNsense model update documentation

- Add initial project configuration files for Go development

- Remove opnsense report analysis template

- **rules**: Remove deprecated container-use rules documentation

- **docs**: Remove AI agent guidelines and update core concepts and workflow documentation

- **lint**: Update golangci-lint configuration and remove gap analysis documentation

- **lint**: Update golangci-lint configuration for improved code quality

- **cleanup**: Remove obsolete configuration and documentation files

- **cleanup**: Remove obsolete GoReleaser configuration and test file list

- **changelog**: Update to version 1.0.0-rc1 and document notable changes


<!-- generated by git-cliff -->
