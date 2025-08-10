# Pipeline v2 Compliance Guide

This document details how opnDossier implements the [EvilBit Labs Pipeline v2 Specification](https://github.com/EvilBit-Labs/Standards/blob/main/pipeline_v_2_spec.md) for comprehensive OSS project quality gates and tooling.

## Overview

Pipeline v2 defines mandatory tooling and quality gates for all EvilBit Labs public OSS projects, focusing on:

- **Consistency** – Same core tools and gates across all projects
- **Local/CI parity** – All CI steps runnable locally via `just`
- **Fail fast** – Blocking gates for linting, testing, security, and licensing
- **Trustworthiness** – Signed releases with SBOM and provenance
- **Airgap-ready** – Offline-capable artifacts with verification metadata

## Implementation Status

### ✅ **Go Language Tooling (Section 3.1)**

| Requirement        | Implementation                                         | Status      |
| ------------------ | ------------------------------------------------------ | ----------- |
| **Build/Release**  | GoReleaser with homebrew, nfpm, archives, Docker       | ✅ Complete |
| **Lint**           | `golangci-lint` with comprehensive configuration       | ✅ Complete |
| **Test/Coverage**  | `go test ./... -cover -race` with 85% minimum coverage | ✅ Complete |
| **Race Detection** | Mandatory `-race` flag in all test commands            | ✅ Complete |
| **Airgap Builds**  | GOMODCACHE + vendor directory for offline builds       | ✅ Complete |

**Files:**

- [`.goreleaser.yaml`](../.goreleaser.yaml) - Complete GoReleaser configuration
- [`.golangci.yml`](../.golangci.yml) - Comprehensive linting rules
- [`justfile`](../justfile) - Local testing commands

**Go Tooling Details:**

- **Test Coverage**: Minimum 85% coverage threshold enforced via `go test -coverprofile=coverage.out` and coverage analysis
- **Race Detection**: All test commands include `-race` flag for concurrent code safety
- **Airgap Support**: Module caching via `GOMODCACHE` and vendor directory for reproducible offline builds

**Airgap Build Strategy:**

- **Module Caching**: Use `GOMODCACHE` environment variable to specify module cache location
- **Vendor Directory**: Maintain `vendor/` directory with `go mod vendor` for offline builds
- **Reproducible Builds**: All builds use locked dependency versions via `go.sum`
- **Offline Verification**: Build process validates all dependencies are available locally

### ✅ **Cross-Cutting Tools (Section 4)**

| Tool                       | Implementation                                   | Status      |
| -------------------------- | ------------------------------------------------ | ----------- |
| **Commit Discipline**      | Conventional Commits via pre-commit + CodeRabbit | ✅ Complete |
| **Security Analysis**      | GitHub CodeQL                                    | ✅ Complete |
| **SBOM Generation**        | Syft (SPDX JSON) via GoReleaser                  | ✅ Complete |
| **Vulnerability Scanning** | Grype via GitHub Actions                         | ✅ Complete |
| **License Scanning**       | FOSSA integration (GitHub App)                   | ✅ Complete |
| **Signing & Attestation**  | Cosign + SLSA Level 3                            | ✅ Complete |
| **Coverage Reporting**     | Codecov integration                              | ✅ Complete |
| **AI-Assisted Review**     | CodeRabbit.ai                                    | ✅ Complete |

**Files:**

- [`.github/workflows/ci-check.yml`](../.github/workflows/ci-check.yml) - Grype vulnerability scanning
- [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) - GitHub CodeQL
- FOSSA license scanning (GitHub App integration)
- [`.github/workflows/release.yml`](../.github/workflows/release.yml) - SLSA + Cosign signing
- [`.coderabbit.yaml`](../.coderabbit.yaml) - CodeRabbit configuration

### ✅ **Enhanced SaaS Tools**

| Tool               | Implementation                                                         | Status      |
| ------------------ | ---------------------------------------------------------------------- | ----------- |
| **OSSF Scorecard** | Weekly repository hygiene scoring                                      | ✅ Complete |
| **Snyk**           | Additional dependency + code vulnerability scanning (GitHub App + CLI) | ✅ Complete |
| **Dependabot**     | Automated dependency updates                                           | ✅ Complete |

**Files:**

- [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml) - OSSF Scorecard
- Snyk scanning (GitHub App integration + local CLI)
- [`.github/dependabot.yml`](../.github/dependabot.yml) - Dependabot configuration

### Local CLI Tools

Both Snyk and FOSSA provide local CLI tools for development:

- **Snyk CLI**: `just snyk-scan` - Local vulnerability scanning with `snyk test` and `snyk monitor`
- **FOSSA CLI**: `just fossa-scan` - Local license analysis with `fossa analyze` and `fossa test`

These CLI tools complement the GitHub App integrations and provide local/CI parity for security scanning.

## Local Development Workflow

Pipeline v2 requires local/CI parity. All CI steps can be run locally:

```bash
# Core development workflow
just test              # Run tests locally
just lint              # Run linters locally
just check             # Run pre-commit checks
just ci-check          # Full CI validation locally

# Security scanning
just scan-vulnerabilities  # Grype vulnerability scan
just generate-sbom          # Generate SBOM with Syft
just snyk-scan             # Snyk vulnerability scan (CLI)
just fossa-scan            # FOSSA license analysis (CLI)
just security-scan         # Comprehensive security scan

# Release workflow
just build-for-release     # Test release build
just check-goreleaser      # Validate GoReleaser config
```

## Quality Gates

### PR Merge Criteria (Section 5.1)

Every PR must:

1. ✅ Pass all linters (`golangci-lint`)
2. ✅ Pass format checks (`gofumpt`, `goimports`)
3. ✅ Pass all tests with race detection (`-race` flag) and minimum 85% coverage
4. ✅ Upload coverage to Codecov
5. ✅ Pass security gates (CodeQL, Grype)
6. ✅ Pass license compliance (FOSSA GitHub App)
7. ✅ Use valid Conventional Commits
8. ✅ Acknowledge CodeRabbit.ai findings

### Release Criteria (Section 5.2)

Every release must:

1. ✅ Be created via automated GoReleaser flow
2. ✅ Include signed artifacts with checksums
3. ✅ Include SBOM (Syft-generated SPDX)
4. ✅ Include vulnerability scan reports
5. ✅ Include SLSA Level 3 provenance attestation
6. ✅ Include Cosign signatures
7. ✅ Pass all PR criteria above

## Security Features

### Supply Chain Security

- **SLSA Level 3 Provenance**: Every release includes cryptographic proof of build integrity
- **Cosign Signatures**: All artifacts signed using keyless OIDC signing
- **SBOM Generation**: Complete software bill of materials in SPDX format
- **Vulnerability Scanning**: Comprehensive scanning with Grype and Snyk (GitHub App)

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

# Verify Cosign signatures (requires cosign)
cosign verify-blob \
  --bundle cosign.bundle \
  opnDossier_checksums.txt
```

## Continuous Monitoring

### Scheduled Scans

- **OSSF Scorecard**: Weekly repository hygiene assessment
- **Snyk Vulnerability Scan**: Weekly dependency vulnerability scanning (GitHub App)
- **CodeQL Analysis**: Weekly code security analysis
- **Dependabot Updates**: Weekly dependency updates

### Real-time Monitoring

- **Pull Request Gates**: All security and quality checks on every PR
- **Commit Validation**: Conventional commits enforced
- **License Policy**: FOSSA license policy enforcement (GitHub App)
- **Code Review**: CodeRabbit.ai advisory feedback

## Exceptions

Per Pipeline v2 specification, any deviations must be documented in the README under **Exceptions**.

**Current Status**: No exceptions required - full compliance achieved.

## Secret Management

Required secrets for full functionality:

| Secret            | Purpose                             | Required For |
| ----------------- | ----------------------------------- | ------------ |
| `CODECOV_TOKEN`   | Coverage reporting                  | CI           |
| `FOSSA_API_KEY`   | License scanning (GitHub App)       | CI + Local   |
| `SNYK_TOKEN`      | Vulnerability scanning (GitHub App) | N/A          |
| `SCORECARD_TOKEN` | OSSF Scorecard (optional)           | CI           |

## Compliance Verification

To verify Pipeline v2 compliance:

```bash
# Run full compliance check
just full-checks

# Check individual components
just ci-check          # Core quality gates
just security-scan     # Security compliance
just check-goreleaser  # Release compliance
```

## Resources

- [EvilBit Labs Pipeline v2 Specification](https://github.com/EvilBit-Labs/Standards/blob/main/pipeline_v_2_spec.md)
- [SLSA Framework](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/)
- [SPDX SBOM Standard](https://spdx.dev/)
