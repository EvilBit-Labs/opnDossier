# OpenSSF Best Practices Badge — Silver Level

**Project:** opnDossier **Repository:** <https://github.com/EvilBit-Labs/opnDossier> **Website:** <https://evilbitlabs.io/opnDossier/> **License:** Apache-2.0 **Language:** Go

> This document provides answers for each criterion of the OpenSSF Best Practices **Silver** badge. Each control includes a status (**Met** / **Unmet** / **N/A**), the justification text to enter on the form, and a URL where applicable.
>
> **Prerequisite:** The Passing badge must be achieved first. See [ossf-best-practices-passing.md](ossf-best-practices-passing.md).

---

## Basics

### Prerequisites

**`achieve_passing`** — *Unmet*

> The project has not yet achieved the Passing level badge. One blocking MUST criterion remains (`release_notes`). A fix has been prepared by switching GoReleaser to `changelog.use: git-cliff` so release bodies include human-readable change summaries.
>
> **Action needed:** Merge the GoReleaser changelog fix, cut a release to validate, then submit the Passing badge application.

---

### Basic project website content

**`contribution_requirements`** — *Met*

> (Elevated from SHOULD to MUST at Silver.) The CONTRIBUTING.md specifically lists code quality requirements (golangci-lint, >80% test coverage), coding standards (Go conventions documented in AGENTS.md), commit message format (Conventional Commits with scope), documentation standards, and a detailed PR checklist including security considerations.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md#quality-standards>

---

### Project oversight

**`dco`** — *Met*

> All commits include `Signed-off-by:` trailers. DCO is enforced via GitHub App on all pull requests. The CONTRIBUTING.md documents the requirement. Example from git log: `Signed-off-by: UncleSp1d3r <unclesp1d3r@evilbitlabs.io>`

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

**`governance`** — *Met*

> The project documents its governance model in the "Project Governance" section of CONTRIBUTING.md. It describes a maintainer-driven model with decisions made through consensus on GitHub issues and pull requests. Decision-making tiers are defined: bug fixes (any maintainer), new features (maintainer approval), architecture changes (maintainer approval with rationale), and breaking changes (community input + maintainer approval).

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md#project-governance>

---

**`code_of_conduct`** — *Met*

> The project has adopted the Contributor Covenant v2.0, posted in the standard location (`CODE_OF_CONDUCT.md`). It includes enforcement guidelines with four escalation levels (correction, warning, temporary ban, permanent ban) and enforcement contact (support@evilbitlabs.io).

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CODE_OF_CONDUCT.md>

---

**`roles_responsibilities`** — *Met*

> Key roles are documented in the "Project Governance" section of CONTRIBUTING.md with a roles table defining Maintainer (merge PRs, manage releases, set direction, review security reports), Security Contact (triage vulnerability reports, coordinate fixes, publish advisories), and Contributor (submit issues, PRs, participate in discussions). Current holders are listed for each role.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md#roles>

---

**`access_continuity`** — *Met*

> The project documents a continuity plan in the "Continuity Plan" subsection of CONTRIBUTING.md's governance section. Key provisions:
>
> - The GitHub organization (EvilBit-Labs) has multiple administrators
> - CI/CD pipelines are fully automated and documented
> - All standards, architecture, and processes are documented in AGENTS.md, CONTRIBUTING.md, and docs/
> - Security response procedures are documented with alternative contacts
> - Release signing uses Sigstore keyless signatures (no personal keys)

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md#continuity-plan>

---

**`bus_factor`** — *Unmet* (SHOULD)

> The project has a bus factor of 1. Only one human contributor (UncleSp1d3r, 412 commits) exists. Bot accounts (Dependabot, Copilot, CodeRabbit, FOSSA, Mergify) handle automated tasks but cannot substitute for maintainer judgment.
>
> **Action needed:** Recruit at least one additional maintainer or co-maintainer with commit access and release capability.

---

### Documentation

**`documentation_roadmap`** — *Met*

> The project has a documented roadmap in `project_spec/ROADMAP_V2.0.md` describing planned features, architectural improvements, and priorities. GitHub milestones and issues are also used for tracking planned work.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/project_spec/ROADMAP_V2.0.md>

---

**`documentation_architecture`** — *Met*

> The project includes comprehensive architecture documentation covering system design, component interactions, data flow, technology stack, and modular report generator architecture. Mermaid diagrams illustrate the data model and component relationships.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/development/architecture.md>

---

**`documentation_security`** — *Met*

> Security expectations are documented in multiple locations: SECURITY.md covers vulnerability reporting and security features; the security assurance case (`docs/security/security-assurance.md`) documents the threat model, trust boundaries, Saltzer & Schroeder design principles, and CWE/SANS Top 25 countermeasures. The README lists security features (no telemetry, input validation, SBOM generation, offline operation).

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/security/security-assurance.md>

---

**`documentation_quick_start`** — *Met*

> The README includes a Quick Start section with basic usage examples. The documentation site provides installation instructions for multiple platforms (pre-built binaries, `go install`, build from source). Users can go from install to first report in under 5 minutes.

URL: <https://github.com/EvilBit-Labs/opnDossier#quick-start>

---

**`documentation_current`** — *Met*

> Documentation is maintained alongside code changes. The PR template requires documentation updates for user-facing changes. AGENTS.md (section 12.1) mandates "Documentation updated" as part of the code review checklist. The MkDocs site is auto-deployed on push to main.

---

**`documentation_achievements`** — *Unmet*

> The project does not yet display the OSSF Best Practices badge on the README or website. This criterion requires displaying the badge within 48 hours of achievement.
>
> **Action needed:** After achieving Passing badge, add the badge to the README header:
>
> ```markdown
> [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
> ```

---

### Accessibility and internationalization

**`accessibility_best_practices`** — *Met* (SHOULD)

> The project is a CLI tool with plain text output. Terminal output respects `TERM=dumb` and `NO_COLOR` environment variables for accessibility in screen readers and CI environments. The documentation site uses MkDocs Material, which follows web accessibility standards.

---

**`internationalization`** — *N/A* (SHOULD)

> The project is a CLI tool targeting English-speaking network operators and security professionals. OPNsense configuration files and security standards (STIG, SANS) are English-only. Internationalization is not applicable for the target audience.

---

### Other

**`sites_password_security`** — *N/A*

> The project sites (GitHub, documentation site) do not manage their own password storage. GitHub handles authentication. The project software itself does not store passwords.

---

## Change Control

### Previous versions

**`maintenance_or_update`** — *Met*

> The project maintains the two most recent minor versions (1.2.x, 1.1.x) per the supported versions table in SECURITY.md. Older versions (1.0.x and below) are documented as unsupported with a clear upgrade path to the latest release.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md>

---

## Reporting

### Bug-reporting process

**`report_tracker`** — *Met*

> (Elevated from SHOULD to MUST at Silver.) The project uses GitHub Issues with structured templates for bug reports, feature requests, and documentation issues.

URL: <https://github.com/EvilBit-Labs/opnDossier/issues>

---

### Vulnerability report process

**`vulnerability_report_credit`** — *N/A*

> No vulnerability reports have been received in the last 12 months. SECURITY.md documents the credit policy: "We will credit you in the security advisory (if you want to be credited)."

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md>

---

**`vulnerability_response_process`** — *Met*

> The project has a documented vulnerability response process in SECURITY.md with defined timelines: acknowledge within 1 week, initial assessment within 2 weeks, fix target within 90 days. Disclosure is coordinated via GitHub Security Advisory. The process includes scope definition and safe harbor provisions.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md>

---

## Quality

### Coding standards

**`coding_standards`** — *Met*

> The project identifies specific coding style guides in AGENTS.md (section 5: "Go Development Standards") covering naming conventions, error handling, logging, documentation, import organization, and 10+ common linter patterns with fixes. CONTRIBUTING.md references these standards for all contributions.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/AGENTS.md>

---

**`coding_standards_enforced`** — *Met*

> Coding standards are automatically enforced by golangci-lint v2.8 with 38 active linters in CI. gofumpt enforces formatting stricter than gofmt. goimports enforces import organization. The CI build fails if any linter issue is found. Pre-commit hooks (`just check`) run the same checks locally.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.golangci.yml>

---

### Working build system

**`build_standard_variables`** — *N/A*

> Go does not use C/C++ compiler environment variables (CC, CFLAGS, CXX, CXXFLAGS, LDFLAGS). The Go toolchain manages compilation internally. The build does honor `CGO_ENABLED`, `GOOS`, and `GOARCH` which are the standard Go build variables.

---

**`build_preserve_debug`** — *Met* (SHOULD)

> The default development build (`go build`) preserves full debug information. Only release builds strip debug info via `-ldflags="-s -w"` in GoReleaser. Developers can always build with debug info using standard `go build` without flags.

---

**`build_non_recursive`** — *N/A*

> Go's build system does not use recursive make or subdirectory builds. `go build ./...` resolves all dependencies through the module system in a single pass. There are no cross-directory build dependencies that require ordering.

---

**`build_repeatable`** — *Met*

> The project is configured for reproducible builds:
>
> - `CGO_ENABLED=0` for static, portable binaries
> - `-trimpath` removes local filesystem paths from binaries
> - `mod_timestamp: "{{ .CommitTimestamp }}"` ensures module timestamps match the commit
> - `go.sum` is committed, pinning all dependency hashes
> - GoReleaser uses `CommitDate` for all date stamps

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.goreleaser.yaml>

---

### Installation system

**`installation_common`** — *Met*

> Multiple standard installation methods are provided:
>
> - `go install github.com/EvilBit-Labs/opnDossier@latest`
> - Pre-built binaries for Linux, macOS (Intel/Silicon), Windows, FreeBSD
> - Linux packages: deb, rpm, apk, archlinux (via NFPM)
> - Homebrew cask (via tap repository)
> - Docker: `ghcr.io/evilbit-labs/opndossier`
> - Build from source: `just build`

---

**`installation_standard_variables`** — *N/A*

> Go binaries are statically compiled and do not use DESTDIR or other POSIX installation conventions. Installation is via `go install` (which uses `$GOPATH/bin`) or by copying the pre-built binary. Linux packages (deb/rpm/apk) follow FHS conventions via NFPM configuration.

---

**`installation_development_quick`** — *Met*

> CONTRIBUTING.md provides a complete developer setup guide: prerequisites (Go 1.21+, Just, git, golangci-lint), clone instructions, and verification commands (`just check`). A new developer can be running tests within minutes.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

### Externally-maintained components

**`external_dependencies`** — *Met*

> All external dependencies are declared in `go.mod` and `go.sum`, which are computer-processable. CycloneDX SBOMs are generated per release in JSON format, listing all transitive dependencies with version and license information.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/go.mod>

---

**`dependency_monitoring`** — *Met*

> Dependencies are monitored through multiple channels:
>
> - Dependabot: Weekly automated PRs for Go modules, GitHub Actions, Docker, and devcontainers
> - Grype: Vulnerability scanning in CI on every push
> - Snyk: Additional dependency and code scanning
> - CodeQL: Semantic security analysis
> - OSSF Scorecard: Supply chain security assessment (weekly)

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/dependabot.yml>

---

**`updateable_reused_components`** — *Met*

> All external components are managed through Go modules with pinned versions in `go.mod`. Dependabot creates automated PRs for updates. No vendored copies or convenience copies exist — all dependencies are fetched from their canonical sources.

---

**`interfaces_current`** — *Met* (SHOULD)

> The project uses current, non-deprecated APIs. Go modules ensure the latest compatible versions are used. The golangci-lint configuration includes `staticcheck` which warns about deprecated stdlib usage. No deprecated API calls exist in the codebase.

---

### Automated test suite

**`automated_integration_testing`** — *Met*

> GitHub Actions CI runs the full automated test suite on every push to main and on every pull request. The pipeline includes unit tests, integration tests (with `-tags=integration`), and linting. All must pass before merge.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

**`regression_tests_added50`** — *Met*

> Recent bug-fix PRs include regression tests or are covered by existing test suites. Examples from the last 6 months:
>
> - PR #256 (fix: sort map iterations) — added deterministic output tests
> - PR #254 (fix: Dest Port column) — added field handling tests
> - PR #252 (security overhaul) — added fuzz tests
> - PR #167 (fix: replace panic error handling) — added error path tests
>
> The PR template and AGENTS.md mandate tests for all changes. CI enforces test passage.

URL: <https://github.com/EvilBit-Labs/opnDossier/pulls?q=is%3Apr+is%3Amerged+fix>

---

**`test_statement_coverage80`** — *Unmet*

> Current test coverage is 71.5% of statements, below the 80% MUST threshold. High-coverage packages include sanitizer (90.3%) and validator (83.3%), but schema (42.8%) and progress (55.8%) bring the overall total down.
>
> **Action needed:** Increase coverage to 80%+ by focusing on:
>
> - `internal/schema/` (42.8%) — add tests for XML field accessors
> - `internal/progress/` (55.8%) — add tests for progress bar states
> - `internal/converter/` — increase coverage in report generation paths
> - `cmd/` — add CLI integration tests for flag combinations

---

### New functionality testing

**`test_policy_mandated`** — *Met*

> (Elevated from general policy to formal written policy at Silver.) AGENTS.md section 12.1 mandates: "Write comprehensive tests for new functionality." CONTRIBUTING.md requires ">80% coverage" for all PRs. The PR template checklist includes an explicit test requirement. These constitute a formal written policy.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

**`tests_documented_added`** — *Met*

> (Elevated from SUGGESTED to MUST at Silver.) Documented in CONTRIBUTING.md under Quality Standards: "Tests required for new functionality (>80% coverage)." The PR template checklist explicitly includes test requirements. AGENTS.md section 7 provides detailed test organization guidance.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

### Warning flags

**`warnings_strict`** — *Met*

> (Elevated from SUGGESTED to MUST at Silver.) The project uses 38 active linters with zero tolerance — CI fails on any warning. gofumpt (stricter than gofmt) is enforced. gosec checks for security issues. Every disabled linter has documented rationale in `.golangci.yml`.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.golangci.yml>

---

## Security

### Secure development knowledge

**`implement_secure_design`** — *Met*

> The project implements secure design principles documented in the security assurance case (`docs/security/security-assurance.md`):
>
> - **Economy of mechanism:** Pure Go, minimal dependencies
> - **Fail-safe defaults:** XXE-safe by default, overwrite protection, offline-first
> - **Complete mediation:** All XML elements → typed structs, all CLI args validated by Cobra, all output paths checked
> - **Open design:** Fully open source, no security by obscurity
> - **Separation of privilege:** Parser, schema, audit, export are separate modules
> - **Least privilege:** Reads config files, writes reports, no modifications, no commands, no network
> - **Least common mechanism:** No shared mutable state

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/security/security-assurance.md>

---

### Use basic good cryptographic practices

**`crypto_weaknesses`** — *N/A*

> (Elevated from SHOULD to MUST at Silver.) The software does not use cryptographic algorithms or modes. N/A.

---

**`crypto_algorithm_agility`** — *N/A*

> The software does not implement cryptography. N/A.

---

**`crypto_credential_agility`** — *N/A*

> The software does not store authentication credentials or private cryptographic keys. It reads OPNsense configuration files (which may contain such data) but does not manage credential storage. N/A.

---

**`crypto_used_network`** — *N/A*

> The software has no network communications. It operates entirely offline, reading local files and writing local reports. N/A.

---

**`crypto_tls12`** — *N/A*

> The software does not use TLS. It has no network functionality. N/A.

---

**`crypto_certificate_verification`** — *N/A*

> The software does not use TLS. N/A.

---

**`crypto_verification_private`** — *N/A*

> The software does not use TLS or send HTTP headers. N/A.

---

### Secure release

**`signed_releases`** — *Met*

> All releases are cryptographically signed with Cosign v3 keyless signatures via Sigstore transparency log. Each release includes:
>
> - SHA256 checksums (`opnDossier_checksums.txt`)
> - Cosign signature bundle (`opnDossier_checksums.txt.sigstore.json`)
> - SLSA Level 3 provenance attestations via `actions/attest-build-provenance`
>
> The release notes include verification instructions with the exact `cosign verify-blob` command.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.goreleaser.yaml>

---

**`version_tags_signed`** — *Unmet* (SUGGESTED)

> Git tags are not cryptographically signed (not GPG-signed). Tags are created by GoReleaser during the release workflow. While the release artifacts themselves are signed via Cosign, the git tags are lightweight tags without GPG signatures.
>
> **Action needed:** Configure the release workflow to create signed tags using `git tag -s` with a GPG key, or use Sigstore's gitsign for keyless tag signing.

---

### Other security issues

**`input_validation`** — *Met*

> All inputs from potentially untrusted sources are validated:
>
> - CLI arguments validated by Cobra with type checking and allowed values
> - XML configuration files parsed into strictly typed Go structs (allowlist approach — unknown elements are ignored, not executed)
> - Output file paths checked for overwrite protection
> - `internal/validator/` provides configuration validation
> - `internal/config/validation.go` validates application configuration
> - Security assurance case documents "Complete mediation" principle

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/internal/validator/>

---

**`hardening`** — *Met* (SHOULD)

> Multiple hardening mechanisms are in place:
>
> - **Memory safety:** Pure Go with garbage collection, no `unsafe` package
> - **XXE protection:** Go's `encoding/xml` does not support external entities or DTD processing
> - **Bounds checking:** Go runtime bounds-checks all array/slice access
> - **No shell execution:** No `os/exec` calls in application code
> - **Static compilation:** `CGO_ENABLED=0` eliminates C library attack surface
> - **GitHub Actions pinning:** All Actions pinned to SHA hashes for supply chain security
> - **Dependency scanning:** Grype, Snyk, CodeQL in CI

---

**`assurance_case`** — *Met*

> The project provides a comprehensive security assurance case in `docs/security/security-assurance.md` following NIST IR 7608 structure:
>
> - **Threat model:** Three threat actors (malicious config author, insider with report access, supply chain attacker), seven attack vectors mapped to security requirements
> - **Trust boundaries:** Clearly identified (untrusted input → parser → typed model → report generator → output)
> - **Secure design principles:** Saltzer & Schroeder principles applied and documented for each
> - **Common vulnerabilities countered:** CWE/SANS Top 25 mapped with status and countermeasures; OWASP Top 10 addressed where applicable

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/security/security-assurance.md>

---

## Analysis

### Static code analysis

**`static_analysis_common_vulnerabilities`** — *Met*

> (Elevated from SUGGESTED to MUST at Silver.) CodeQL specifically targets common vulnerabilities (injection, buffer overflows, insecure data handling). gosec checks for Go-specific security issues. Grype checks dependencies against the National Vulnerability Database for known CVEs.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

### Dynamic code analysis

**`dynamic_analysis_unsafe`** — *N/A*

> The project is pure Go, which is a memory-safe language. Go uses garbage collection and bounds-checked arrays. The project does not use the `unsafe` package. No memory-unsafe languages are used.

---

## Summary

### Status Overview

| Category       | Met    | Unmet | N/A    | Total  |
| -------------- | ------ | ----- | ------ | ------ |
| Basics         | 13     | 2     | 2      | 17     |
| Change Control | 1      | 0     | 0      | 1      |
| Reporting      | 2      | 0     | 1      | 3      |
| Quality        | 14     | 1     | 2      | 17     |
| Security       | 4      | 1     | 8      | 13     |
| Analysis       | 1      | 0     | 1      | 2      |
| **Total**      | **35** | **4** | **14** | **53** |

### Blocking Items (MUST criteria)

| Criterion                    | Category | Action Required                                               |
| ---------------------------- | -------- | ------------------------------------------------------------- |
| `achieve_passing`            | Basics   | Fix `release_notes` at Passing level, then submit application |
| `documentation_achievements` | Basics   | Display badge on README after achieving Passing               |
| `test_statement_coverage80`  | Quality  | Increase coverage from 71.5% to 80%+                          |

### Non-Blocking Items (SHOULD criteria)

| Criterion             | Category | Action Required                            |
| --------------------- | -------- | ------------------------------------------ |
| `bus_factor`          | Basics   | Recruit at least one additional maintainer |
| `version_tags_signed` | Security | Sign git tags with GPG or gitsign          |

### Recommended Priority Order

1. **Fix `release_notes`** — Merge GoReleaser changelog fix (already prepared)
2. **Submit Passing badge** — Unblocks all Silver work
3. **Increase test coverage to 80%** — Focus on `schema/`, `progress/`, `cmd/`
4. **Display badge on README** — Simple once Passing is achieved
5. **(SHOULD) Sign git tags** — Nice-to-have for supply chain integrity
6. **(SHOULD) Recruit co-maintainer** — Addresses bus factor long-term
