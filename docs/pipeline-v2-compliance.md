# Pipeline v2 Compliance Guide

This document details how opnDossier implements the EvilBit Labs Pipeline v2 Specification for comprehensive OSS project quality gates and tooling.

## Overview

Pipeline v2 defines mandatory tooling and quality gates for all EvilBit Labs public OSS projects, focusing on:

- **Consistency** - Same core tools and gates across all projects
- **Local/CI parity** - All CI steps runnable locally via `just`
- **Fail fast** - Blocking gates for linting, testing, security, and licensing
- **Trustworthiness** - Signed releases with SBOM and provenance
- **Airgap-ready** - Offline-capable artifacts with verification metadata

## Implementation Status

### Go Language Tooling (Section 3.1)

| Requirement        | Implementation                                         | Status   |
| ------------------ | ------------------------------------------------------ | -------- |
| **Build/Release**  | GoReleaser with homebrew, nfpm, archives, Docker       | Complete |
| **Lint**           | `golangci-lint` with comprehensive configuration       | Complete |
| **Test/Coverage**  | `go test ./... -cover -race` with 85% minimum coverage | Complete |
| **Race Detection** | Mandatory `-race` flag in all test commands            | Complete |
| **Airgap Builds**  | GOMODCACHE + vendor directory for offline builds       | Complete |

**Files:**

- [`.goreleaser.yaml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.goreleaser.yaml) - Complete GoReleaser configuration
- [`.golangci.yml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.golangci.yml) - Comprehensive linting rules
- [`justfile`](https://github.com/EvilBit-Labs/opnDossier/blob/main/justfile) - Local testing commands

**Go Tooling Details:**

- **Test Coverage**: Minimum 85% coverage threshold enforced via `go test -coverprofile=coverage.out` and coverage analysis
- **Race Detection**: All test commands include `-race` flag for concurrent code safety
- **Airgap Support**: Module caching via `GOMODCACHE` and vendor directory for reproducible offline builds

**Airgap Build Strategy:**

- **Module Caching**: Use `GOMODCACHE` environment variable to specify module cache location
- **Vendor Directory**: Maintain `vendor/` directory with `go mod vendor` for offline builds
- **Reproducible Builds**: All builds use locked dependency versions via `go.sum`
- **Offline Verification**: Build process validates all dependencies are available locally

### Cross-Cutting Tools (Section 4)

| Tool                      | Implementation                                                       | Status   |
| ------------------------- | -------------------------------------------------------------------- | -------- |
| **Commit Discipline**     | Conventional Commits via pre-commit + CodeRabbit                     | Complete |
| **Static Analysis**       | GitHub CodeQL (Go)                                                   | Complete |
| **Go Vulnerability Scan** | `govulncheck` against the Go vulnerability database                  | Complete |
| **Dependency Scan**       | Trivy filesystem scan (CRITICAL/HIGH/MEDIUM, `ignore-unfixed: true`) | Complete |
| **SBOM Generation**       | CycloneDX-gomod via GoReleaser + dedicated SBOM workflow             | Complete |
| **License Scanning**      | FOSSA integration (GitHub App)                                       | Complete |
| **Signing & Attestation** | Cosign (keyless OIDC) + SLSA Level 3 build provenance                | Complete |
| **Coverage Reporting**    | Codecov integration                                                  | Complete |
| **AI-Assisted Review**    | CodeRabbit.ai                                                        | Complete |

**Files:**

- [`.github/workflows/security.yml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/security.yml) - `govulncheck` and Trivy filesystem scan. CodeQL is handled by GitHub's repository-level default-setup code scanning (not a job in this workflow — GitHub rejects SARIF upload from a manually-configured CodeQL job when default setup is enabled).
- [`.github/workflows/sbom.yml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/sbom.yml) - Repository SBOM generation
- FOSSA license scanning (GitHub App integration)
- [`.github/workflows/release.yml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/release.yml) - SLSA provenance + Cosign signing
- [`.coderabbit.yaml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.coderabbit.yaml) - CodeRabbit configuration

### Repository Hygiene & Dependency Management

| Tool               | Implementation                                                                                                                                                  | Status   |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| **OSSF Scorecard** | Weekly repository hygiene scoring via [`.github/workflows/scorecard.yml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/workflows/scorecard.yml) | Complete |
| **Dependabot**     | Automated dependency update PRs via [`.github/dependabot.yml`](https://github.com/EvilBit-Labs/opnDossier/blob/main/.github/dependabot.yml)                     | Complete |

### Local CLI Tools

The project provides the following local security and compliance tooling:

- **`just scan`** — run `gosec` source-code security analysis
- **`just sbom`** — generate a CycloneDX SBOM via `cyclonedx-gomod`
- **`just security-all`** — run `gosec` and SBOM generation together
- **`govulncheck`** — install via `go install golang.org/x/vuln/cmd/govulncheck@latest`, then run `govulncheck ./...` to reproduce the CI check locally
- **FOSSA CLI** — run `fossa analyze` and `fossa test` locally (requires `FOSSA_API_KEY`)

Trivy and CodeQL are executed only in CI. To reproduce a Trivy finding locally, install the CLI from the upstream project and run `trivy fs --severity CRITICAL,HIGH,MEDIUM --ignore-unfixed .`.

## Local Development Workflow

Pipeline v2 requires local/CI parity. All CI steps can be run locally:

```bash
# Core development workflow
just test              # Run tests locally
just lint              # Run linters locally
just check             # Run pre-commit checks
just ci-check          # Full CI validation locally

# Security scanning
just scan                  # Run gosec source-code security scanner
just sbom                  # Generate SBOM with cyclonedx-gomod
just security-all          # Run gosec + SBOM generation

# Release workflow
just build-release         # Build optimized release binary
just release-check         # Validate GoReleaser config
just release-snapshot      # Test release build (snapshot)
```

## Quality Gates

### PR Merge Criteria (Section 5.1)

Every PR must:

1. Pass all linters (`golangci-lint`)
2. Pass format checks (`gofumpt`, `goimports`)
3. Pass all tests with race detection (`-race` flag) and minimum 85% coverage
4. Upload coverage to Codecov
5. Pass security gates (`govulncheck`, CodeQL, Trivy filesystem scan)
6. Pass license compliance (FOSSA GitHub App)
7. Use valid Conventional Commits
8. Acknowledge CodeRabbit.ai findings

### Release Criteria (Section 5.2)

Every release must:

1. Be created via the automated GoReleaser flow
2. Include signed artifacts with SHA256 checksums
3. Include SBOM (CycloneDX-gomod)
4. Include SLSA Level 3 provenance attestation
5. Include Cosign signatures (keyless OIDC, `.sigstore.json` bundle)
6. Pass all PR criteria above

## Security Features

### Supply Chain Security

- **SLSA Level 3 Provenance**: Every release includes cryptographic proof of build integrity.
- **Cosign Signatures**: All release artifacts are signed using keyless OIDC signing; Cosign v3 produces `.sigstore.json` bundles.
- **SBOM Generation**: Complete software bill of materials in CycloneDX format, attached to every release.
- **Vulnerability Scanning**: `govulncheck` (Go-specific), CodeQL (semantic analysis), and Trivy (filesystem SCA + misconfiguration) run on every PR, push to `main`, and on a weekly schedule.

### Verification

Users can verify releases:

```bash
# Verify checksums
sha256sum -c opnDossier_checksums.txt

# Verify SLSA provenance (requires slsa-verifier)
slsa-verifier verify-artifact \
  --provenance-path opnDossier-v1.0.0.intoto.jsonl \
  --source-uri github.com/EvilBit-Labs/opnDossier \
  opnDossier_checksums.txt

# Verify Cosign v3 signature bundle
cosign verify-blob \
  --certificate-identity "https://github.com/EvilBit-Labs/opnDossier/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle opnDossier_checksums.txt.sigstore.json \
  opnDossier_checksums.txt
```

## Continuous Monitoring

### Scheduled Scans

- **OSSF Scorecard**: Weekly repository hygiene assessment
- **Security workflow**: Weekly run of `govulncheck`, CodeQL, and Trivy (Mondays at 06:00 UTC)
- **Dependabot**: Weekly dependency update PRs

### Real-time Monitoring

- **Pull Request Gates**: All security and quality checks run on every PR
- **Commit Validation**: Conventional commits enforced
- **License Policy**: FOSSA license policy enforcement (GitHub App)
- **Code Review**: CodeRabbit.ai advisory feedback

## Exceptions

Per Pipeline v2 specification, any deviations must be documented in the README under **Exceptions**.

**Current Status**: No exceptions required - full compliance achieved.

## Secret Management

Required secrets for full functionality:

| Secret            | Purpose                       | Required For |
| ----------------- | ----------------------------- | ------------ |
| `CODECOV_TOKEN`   | Coverage reporting            | CI           |
| `FOSSA_API_KEY`   | License scanning (GitHub App) | CI + Local   |
| `SCORECARD_TOKEN` | OSSF Scorecard (optional)     | CI           |

`govulncheck`, CodeQL, and Trivy require no additional secrets — they run against public data sources and upload SARIF using the default `GITHUB_TOKEN`.

## Compliance Verification

To verify Pipeline v2 compliance:

```bash
# Run full compliance check
just ci-full

# Check individual components
just ci-check          # Core quality gates
just security-all      # Security compliance (gosec + SBOM)
just release-check     # Release compliance
```

## Resources

- [EvilBit Labs Pipeline v2 Specification](https://github.com/EvilBit-Labs/Standards/blob/main/pipeline_v_2_spec.md)
- [SLSA Framework](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
- [Go vulnerability database (`govulncheck`)](https://go.dev/security/vuln/)
- [Trivy](https://github.com/aquasecurity/trivy)
- [CodeQL](https://codeql.github.com/)
