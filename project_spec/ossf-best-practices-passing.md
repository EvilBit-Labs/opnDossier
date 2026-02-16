# OpenSSF Best Practices Badge — Passing Level

**Project:** opnDossier **Repository:** <https://github.com/EvilBit-Labs/opnDossier> **Website:** <https://evilbitlabs.io/opnDossier/> **License:** Apache-2.0 **Language:** Go

This document provides answers for each criterion of the OpenSSF Best Practices **Passing** badge. Each control includes a status (**Met** / **Unmet** / **N/A**), the justification text to enter on the form, and a URL where applicable.

---

## Basics (13 criteria)

### Identification

| Field                   | Value                                                                                                                                                                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Human-readable name     | opnDossier                                                                                                                                                                                                                                    |
| Brief description       | A command-line tool for transforming OPNsense firewall XML configurations into readable documentation and identifying security issues, misconfigurations, and optimization opportunities. Built for offline operation in secure environments. |
| Project URL             | \<https://evilbitlabs.io/opnDossier/                                                                                                                                                                                                          |
| Repository URL          | \<https://github.com/EvilBit-Labs/opnDossier                                                                                                                                                                                                  |
| Programming language(s) | Go                                                                                                                                                                                                                                            |
| CPE name                | *(none assigned)*                                                                                                                                                                                                                             |

### Basic project website content

**`description_good`** — *Met*

The project website and README succinctly describe what the software does: “Transform complex XML configuration files into clear, readable documentation and identify security issues, misconfigurations, and optimization opportunities.” The description uses minimal jargon and is understandable by potential users

URL: https://github.com/EvilBit-Labs/opnDossier#what-is-opndossier

---

**`interact`** — *Met*

The project has a CONTRIBUTING.md linked from the README and uses both GitHub Issues and Discussions for accepting user feedback, bug reports, and enhancement requests. Installation instructions are provided in the README and on the documentation site.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

**`contribution`** — *Met*

Non-trivial contribution file in the repository explains the contribution process: fork, branch, submit PR with conventional commits, pass CI checks (lint + tests), and receive code review.

URL: https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md

---

**`contribution_requirements`** — *Met*

The CONTRIBUTING.md specifically lists code quality requirements (golangci-lint, >80% test coverage), coding standards (Go conventions documented in AGENTS.md), commit message format (Conventional Commits with scope), documentation standards, and a detailed PR checklist including security considerations.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md#quality-standards>

---

### FLOSS license

**License:** `Apache-2.0`

**`floss_license`** — *Met*

The Apache-2.0 license is approved by the Open Source Initiative (OSI).

---

**`floss_license_osi`** — *Met*

The Apache-2.0 license is approved by the Open Source Initiative (OSI).

---

**`license_location`** — *Met*

Non-trivial license location file in repository.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/LICENSE>

---

### Documentation

**`documentation_basics`** — *Met*

The project provides comprehensive documentation: a README with installation instructions, quick start guide, CLI usage examples, configuration options, and a dedicated documentation site built with MkDocs Material deployed to GitHub Pages. Security documentation covers what to do and what not to do.

URL: <https://evilbitlabs.io/opnDossier/>

---

**`documentation_interface`** — *Met*

The project is a command-line tool. The CLI interface is documented in the README with usage examples for all subcommands (convert, display, validate, sanitize, diff). The `--help` flag provides built-in reference documentation for every command and flag. The documentation site includes detailed reference for all commands, options, and output formats.

URL: <https://evilbitlabs.io/opnDossier/>

---

### Other

**`sites_https`** — *Met*

All project sites use HTTPS:

- <https://evilbitlabs.io/opnDossier/>
- <https://github.com/EvilBit-Labs/opnDossier>

---

**`discussion`** — *Met*

GitHub supports discussions on issues and pull requests. All are searchable, URL-addressable, open to new participants, and require no proprietary client-side software.

---

**`english`** — *Met*

All project documentation (README, CONTRIBUTING.md, AGENTS.md, MkDocs site, inline code comments) is in English. GitHub Issues and PRs accept English-language bug reports and comments.

---

**`maintained`** — *Met*

Actively maintained. Recent commits within the last 30 days, open issues are triaged and organized into milestones. The project has published four releases (v1.0.0 through v1.2.1). Dependencies are monitored by Dependabot across four ecosystems (Go modules, GitHub Actions, Docker, devcontainers). CI runs on every PR.

---

### Other general comments

opnDossier is a Go CLI tool for network operators and security professionals working with OPNsense firewalls. It is at v1.2.1 with active development.

- **Documentation:** MkDocs site, comprehensive README, CONTRIBUTING.md, AGENTS.md, Code of Conduct, SECURITY.md
- **Testing:** 71.5% statement coverage across 30 test packages, with unit, integration, golden file, and fuzz tests
- **CI/CD:** GitHub Actions with golangci-lint (38 linters), cross-platform testing (Linux/macOS/Windows), CodeQL, OSSF Scorecard, Codecov integration, Dependabot for dependencies. All actions pinned to SHA hashes
- **Releases:** GoReleaser with Cosign keyless signing, SBOM generation, SLSA provenance attestations

---

## Change Control (9 criteria)

### Public version-controlled source repository

**`repo_public`** — *Met*

Repository on GitHub, which provides public git repositories with URLs.

URL: <https://github.com/EvilBit-Labs/opnDossier>

---

**`repo_track`** — *Met*

Repository on GitHub, which uses git. git can track the changes, who made them, and when they were made.

---

**`repo_interim`** — *Met*

All development happens on feature branches with pull requests reviewed before merging to main. The full commit history and interim development state is preserved in the repository. Releases are tagged separately via GoReleaser.

---

**`repo_distributed`** — *Met*

Repository on GitHub, which uses git. git is distributed.

---

### Unique version numbering

**`version_unique`** — *Met*

We use SemVer. Each release gets a unique vX.Y.Z git tag. GoReleaser automates release creation from tags. No two releases share the same version string. Published releases: v1.0.0-rc1, v1.0.0, v1.1.0, v1.2.1.

---

**`version_semver`** — *Met*

The project uses Semantic Versioning (SemVer) for all releases.

---

**`version_tags`** — *Met*

We use git tags that match the SemVer number (e.g., "v1.2.1").

---

### Release notes

**`release_notes`** — *Unmet*

The release infrastructure uses GoReleaser with git-cliff for changelog generation. However, the current GitHub Releases contain only a "Full Changelog" comparison link and installation/verification instructions — they lack a human-readable summary of major changes in each release. The CHANGELOG.md file exists but is not inlined into release notes.

**Action needed:** Configure GoReleaser to include git-cliff output (grouped by type: features, fixes, breaking changes) directly in the GitHub Release body, providing users a human-readable summary of what changed and whether they should upgrade.

URL: <https://github.com/EvilBit-Labs/opnDossier/releases>

---

**`release_notes_vulns`** — *N/A*

No CVEs have been assigned against the project. No publicly known vulnerabilities have needed to be disclosed in release notes. If vulnerabilities are discovered in the future, they will be identified in release notes per the project's security policy.

---

## Reporting (8 criteria)

### Bug-reporting process

**`report_process`** — *Met*

The project uses GitHub Issues to allow users to submit public bug reports. An issue template is provided to guide reporters through structured bug reports with reproduction steps, expected/actual behavior, and environment details.

URL: <https://github.com/EvilBit-Labs/opnDossier/issues>

---

**`report_tracker`** — *Met*

The project uses GitHub Issues to allow users to submit and track issue reports.

URL: <https://github.com/EvilBit-Labs/opnDossier/issues>

---

**`report_responses`** — *Met*

The project has 100 issues filed (76 closed, 24 open), including 16 bug reports. All issues are acknowledged and triaged by the maintainer. The single maintainer actively responds to all issues.

URL: <https://github.com/EvilBit-Labs/opnDossier/issues>

---

**`enhancement_responses`** — *Met*

The single maintainer actively responds to all enhancement requests. All issues are triaged and organized into milestones.

---

**`report_archive`** — *Met*

All issues are tracked via GitHub Issues, which is public and searchable.

URL: <https://github.com/EvilBit-Labs/opnDossier/issues>

---

### Vulnerability report process

**`vulnerability_report_process`** — *Met*

The project publishes a comprehensive security policy with multiple reporting channels: GitHub's private vulnerability reporting (enabled), email (support@evilbitlabs.io with PGP key), and GitHub Security Advisories. Public issues are explicitly discouraged for vulnerabilities. The policy includes scope definition, safe harbor provisions, and response timelines.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md>

---

**`vulnerability_report_private`** — *Met*

The project supports private vulnerability reporting through two channels: GitHub's private vulnerability reporting feature (preferred) and PGP-encrypted email to support@evilbitlabs.io (fingerprint: `F839 4B2C F0FE C451 1B11 E721 8F71 D62B F438 2BC0`).

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md>

---

**`vulnerability_report_response`** — *N/A*

While the project has a published process with defined response timelines (1 week acknowledgment, 2 weeks initial assessment), there have been no vulnerability reports received in the last 6 months.

---

## Quality (13 criteria)

### Working build system

**`build`** — *Met*

Standard Go build system. The project uses `go build` to compile from source, automatically resolving and fetching dependencies via Go modules. `go install` builds and installs the binary. The project also uses GoReleaser for cross-platform release builds. A justfile provides convenient build targets (`just build`, `just build-release`).

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/justfile>

---

**`build_common_tools`** — *Met*

Go's built-in build system is the standard build tool for Go — equivalent to Maven for Java or npm for Node.js. No custom build tooling. The justfile wraps standard Go commands for convenience.

---

**`build_floss_tools`** — *Met*

Go is open source (BSD-3-Clause license). All build tools used are FLOSS: Go toolchain, GoReleaser (MIT), just (CC0), golangci-lint (GPL-3.0), git-cliff (MIT/Apache-2.0).

---

### Automated test suite

**`test`** — *Met*

The project has an automated test suite across 30 packages run via `go test ./...` and documented in the justfile (`just test`). Tests run automatically in CI via GitHub Actions on every push and PR. The CI workflow is publicly visible. Test coverage is 71.5% of statements, measured by Go's built-in coverage tooling.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

**`test_invocation`** — *Met*

Test suite is triggered by standard Go commands (`go test ./...`) and also uses just as a task runner (`just test`, `just test-race`, `just test-coverage`).

---

**`test_most`** — *Unmet*

Current test coverage is 71.5% of statements. While the project has comprehensive tests including unit, integration, golden file, and fuzz tests, coverage has not yet reached the project's own 80% target. Some packages have high coverage (sanitizer: 90.3%, validator: 83.3%) while others are lower (schema: 42.8%, progress: 55.8%).

**Action needed:** Increase coverage in lower-coverage packages, particularly `internal/schema/` and `internal/progress/`, to bring the overall total above 80%.

---

**`test_continuous_integration`** — *Met*

GitHub Actions CI runs on every push and PR. The pipeline includes linting, cross-platform testing (Ubuntu, macOS, Windows), integration tests, coverage reporting to Codecov, and build verification.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

### New functionality testing

**`test_policy`** — *Met*

The project's AGENTS.md (section 12.1) requires "Write comprehensive tests for new functionality" and the CONTRIBUTING.md requires ">80% coverage" for all PRs. The PR template includes a checklist item for test coverage. CI enforces test passage before merge.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

**`tests_are_added`** — *Met*

Every merged PR in the project's recent history includes tests alongside new functionality. For example:

- PR #257 (audit logging levels) — added tests
- PR #256 (deterministic map output) — added tests
- PR #254 (Dest Port column fix) — added tests
- PR #252 (security overhaul) — added fuzz tests
- PR #245 (HTML diff formatter) — added tests
- PR #237 (IDS/Suricata parsing) — added tests
- PR #234 (sanitize command) — added tests

URL: <https://github.com/EvilBit-Labs/opnDossier/pulls?q=is%3Apr+is%3Amerged>

---

**`tests_documented_added`** — *Met*

Documented in CONTRIBUTING.md under the Quality Standards section: "Tests required for new functionality (>80% coverage)." The PR template checklist explicitly includes test requirements. AGENTS.md section 7 provides detailed test organization guidance and section 12.1 mandates writing comprehensive tests.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md>

---

### Warning flags

**`warnings`** — *Met*

The project enforces multiple layers of code quality checking:

- golangci-lint v2.8 with 38 active linters (including gosec for security, gocritic for correctness, staticcheck for bugs)
- gofumpt for strict formatting (stricter than gofmt)
- CodeQL via GitHub Actions for semantic security analysis
- Grype and Snyk for dependency vulnerability detection

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.golangci.yml>

---

**`warnings_fixed`** — *Met*

Zero linter warnings. The CI enforces all warnings — the build fails if any linter issue is found. The project currently passes with zero golangci-lint issues across the entire codebase.

---

**`warnings_strict`** — *Met*

The project uses 38 active linters including strict options. gofumpt (stricter than gofmt) is enforced. gosec checks for security issues. gocritic with performance and diagnostic tags. The project has documented rationale for each disabled linter in `.golangci.yml`.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.golangci.yml>

---

## Security (16 criteria)

### Secure development knowledge

**`know_secure_design`** — *Met*

The primary developer has experience developing secure software for high-security and government environments. The project reflects secure design principles in practice: economy of mechanism (pure Go, minimal dependencies), fail-safe defaults (XXE-safe by default, offline-first, overwrite protection), complete mediation (typed structs, Cobra validation), input validation, and limited attack surface (read-only file operations, no network exposure). The project maintains a formal security assurance case documenting Saltzer and Schroeder design principles.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/security/security-assurance.md>

---

**`know_common_errors`** — *Met*

The primary developer knows common security errors and the project's security assurance case maps countermeasures against CWE/SANS Top 25 vulnerabilities: XXE (CWE-611), path traversal (CWE-22), command injection (CWE-78), improper input validation (CWE-20), resource exhaustion (CWE-400), and untrusted deserialization (CWE-502). Each has documented mitigations.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/docs/security/security-assurance.md>

---

### Use basic good cryptographic practices

**`crypto_published`** — *N/A*

The software does not implement or use cryptographic protocols or algorithms. It is a configuration parser and report generator that operates on local files.

---

**`crypto_call`** — *N/A*

The software does not implement cryptography. Its primary purpose is parsing XML configuration files and generating reports.

---

**`crypto_floss`** — *N/A*

The software does not depend on cryptography for its functionality.

---

**`crypto_keylength`** — *N/A*

The software has no security mechanisms that use cryptographic keys.

---

**`crypto_working`** — *N/A*

The software does not use cryptographic algorithms.

---

**`crypto_weaknesses`** — *N/A*

The software does not depend on cryptographic algorithms or modes.

---

**`crypto_pfs`** — *N/A*

The software does not implement key agreement protocols.

---

**`crypto_password_storage`** — *N/A*

The software does not store passwords for authentication of external users. It reads OPNsense configuration files (which may contain hashed passwords) but does not perform authentication.

---

**`crypto_random`** — *N/A*

The software does not generate cryptographic keys or nonces.

---

### Secured delivery against man-in-the-middle (MITM) attacks

**`delivery_mitm`** — *Met*

Multiple layers:

- Source code delivered via GitHub over HTTPS/SSH
- Releases built with GoReleaser and signed with Cosign v3 keyless signatures (Sigstore transparency log)
- SLSA Level 3 provenance attestations via `actions/attest-build-provenance`
- Dependencies fetched by Go modules over HTTPS
- SHA256 checksums published with each release
- Homebrew formula delivered via tap repository over HTTPS

URL: <https://github.com/EvilBit-Labs/opnDossier/releases>

---

**`delivery_unsigned`** — *N/A*

The project does not retrieve or verify cryptographic hashes over HTTP. All dependency resolution is handled by Go modules over HTTPS, and release artifacts include Cosign signatures and provenance attestations via Sigstore.

---

### Publicly known vulnerabilities fixed

**`vulnerabilities_fixed_60_days`** — *Met*

Zero known vulnerabilities. Grype and Snyk run in CI on every push. CodeQL runs on every push. No CVEs have been filed against the project. Dependabot is configured for automated dependency updates across four ecosystems.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

**`vulnerabilities_critical_fixed`** — *Met*

No critical vulnerabilities have been reported. The project has a documented security policy with response timelines (1 week acknowledgment, 2 weeks assessment, 90 days fix target), private vulnerability reporting enabled, and automated dependency scanning running on every push.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md>

---

### Other security issues

**`no_leaked_credentials`** — *Met*

GitHub secret scanning and push protection are both enabled on the repository. No credentials are stored in the codebase. The `.gitignore` excludes `.env` files and all variants (`.env.local`, `.env.development.local`, etc.). Pre-commit hooks check for common credential patterns.

---

## Analysis (8 criteria)

### Static code analysis

**`static_analysis`** — *Met*

Multiple static analysis tools run on every PR and pre-release:

- golangci-lint (beyond compiler warnings — includes 38 linters for correctness, security, performance, and style)
- CodeQL via GitHub Actions for semantic security analysis
- gosec (within golangci-lint) for Go-specific security vulnerabilities
- Grype for known vulnerability detection in dependencies
- Snyk for additional dependency and code scanning
- OSSF Scorecard for supply chain security assessment

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

**`static_analysis_common_vulnerabilities`** — *Met*

CodeQL specifically targets common vulnerabilities (injection, buffer overflows, insecure data handling). gosec checks for Go-specific security issues (G101 credentials, G104 unhandled errors, G115 integer overflow, etc.). Grype checks dependencies against the National Vulnerability Database for known CVEs.

---

**`static_analysis_fixed`** — *Met*

CI enforces zero tolerance for golangci-lint and CodeQL findings — both block merging if issues are found. No outstanding static analysis findings exist.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

**`static_analysis_often`** — *Met*

golangci-lint and CodeQL run on every push to main and on every pull request. Static analysis occurs on every commit, not just daily.

URL: <https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/ci.yml>

---

### Dynamic code analysis

**`dynamic_analysis`** — *Met*

The project uses `go test -race` for race condition detection at runtime, and includes property-based fuzz tests (via Go's built-in fuzzing framework) that exercise the parser with randomized inputs to probe for runtime failures. `go test` itself executes code with specific inputs, qualifying as dynamic analysis.

---

**`dynamic_analysis_unsafe`** — *N/A*

The project is pure Go, which is a memory-safe language. Go uses garbage collection and bounds-checked arrays. The project does not use the `unsafe` package. No memory-unsafe languages are used.

---

**`dynamic_analysis_enable_assertions`** — *Met*

Go's testing framework includes assertion-style checks via `testify` assertions. The fuzz tests generate randomized inputs that exercise assertion paths. Race detection (`go test -race`) enables runtime assertions for concurrent access violations. Go's built-in bounds checking is always active (panics on out-of-bounds access).

---

**`dynamic_analysis_fixed`** — *Met*

No dynamic analysis vulnerabilities have been discovered. All test suites pass with zero failures. Race detection passes cleanly.

---

## Summary

### Status Overview

| Category       | Met    | Unmet | N/A    | Total  |
| -------------- | ------ | ----- | ------ | ------ |
| Basics         | 13     | 0     | 0      | 13     |
| Change Control | 7      | 1     | 1      | 9      |
| Reporting      | 6      | 0     | 2      | 8      |
| Quality        | 12     | 1     | 0      | 13     |
| Security       | 5      | 0     | 11     | 16     |
| Analysis       | 7      | 0     | 1      | 8      |
| **Total**      | **50** | **2** | **15** | **67** |

### Items Requiring Action

| Criterion       | Status                | Action Required                                                                                                                                  |
| --------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `release_notes` | **Unmet**             | Configure GoReleaser to inline git-cliff changelog output into GitHub Release body so each release has a human-readable summary of major changes |
| `test_most`     | **Unmet** (SUGGESTED) | Increase test coverage from 71.5% toward 80%+, focusing on `internal/schema/` (42.8%) and `internal/progress/` (55.8%)                           |

**Note:** `test_most` is a SUGGESTED criterion, not a MUST, so it does not block passing. However, `release_notes` is a MUST criterion and must be resolved before the badge can be awarded.
