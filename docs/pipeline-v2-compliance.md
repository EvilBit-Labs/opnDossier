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

| Requirement       | Implementation                                   | Status      |
| ----------------- | ------------------------------------------------ | ----------- |
| **Build/Release** | GoReleaser with homebrew, nfpm, archives, Docker | ✅ Complete |
| **Lint**          | `golangci-lint` with comprehensive configuration | ✅ Complete |
| **Test/Coverage** | `go test ./... -cover -race`                     | ✅ Complete |

**Files:**

- [`.goreleaser.yaml`](../.goreleaser.yaml) - Complete GoReleaser configuration
- [`.golangci.yml`](../.golangci.yml) - Comprehensive linting rules
- [`justfile`](../justfile) - Local testing commands

### ✅ **Cross-Cutting Tools (Section 4)**

| Tool                       | Implementation                                   | Status      |
| -------------------------- | ------------------------------------------------ | ----------- |
| **Commit Discipline**      | Conventional Commits via pre-commit + CodeRabbit | ✅ Complete |
| **Security Analysis**      | GitHub CodeQL                                    | ✅ Complete |
| **SBOM Generation**        | Syft (SPDX JSON) via GoReleaser                  | ✅ Complete |
| **Vulnerability Scanning** | Grype via GitHub Actions                         | ✅ Complete |
| **License Scanning**       | FOSSA integration                                | ✅ Complete |
| **Signing & Attestation**  | Cosign + SLSA Level 3                            | ✅ Complete |
| **Coverage Reporting**     | Codecov integration                              | ✅ Complete |
| **AI-Assisted Review**     | CodeRabbit.ai                                    | ✅ Complete |

**Files:**

- [`.github/workflows/ci-check.yml`](../.github/workflows/ci-check.yml) - Grype vulnerability scanning
- [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) - GitHub CodeQL
- [`.github/workflows/fossa-scan.yml`](../.github/workflows/fossa-scan.yml) - FOSSA license scanning
- [`.github/workflows/release.yml`](../.github/workflows/release.yml) - SLSA + Cosign signing
- [`.coderabbit.yaml`](../.coderabbit.yaml) - CodeRabbit configuration

### ✅ **Enhanced SaaS Tools**

| Tool               | Implementation                                      | Status      |
| ------------------ | --------------------------------------------------- | ----------- |
| **OSSF Scorecard** | Weekly repository hygiene scoring                   | ✅ Complete |
| **Snyk**           | Additional dependency + code vulnerability scanning | ✅ Complete |
| **Dependabot**     | Automated dependency updates                        | ✅ Complete |

**Files:**

- [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml) - OSSF Scorecard
- [`.github/workflows/snyk.yml`](../.github/workflows/snyk.yml) - Snyk scanning
- [`.github/dependabot.yml`](../.github/dependabot.yml) - Dependabot configuration

## Local Development Workflow

Pipeline v2 requires local/CI parity. All CI steps can be run locally:

`bash\n# Core development workflow\njust test              # Run tests locally\njust lint              # Run linters locally\njust check             # Run pre-commit checks\njust ci-check          # Full CI validation locally\n\n# Security scanning\njust scan-vulnerabilities  # Grype vulnerability scan\njust generate-sbom          # Generate SBOM with Syft\njust fossa-scan            # FOSSA license analysis\njust security-scan         # Comprehensive security scan\n\n# Release workflow\njust build-for-release     # Test release build\njust check-goreleaser      # Validate GoReleaser config\n`\\n\\n## Quality Gates\\n\\n### PR Merge Criteria (Section 5.1)\\n\\nEvery PR must:\\n1. ✅ Pass all linters (`golangci-lint`)\\n2. ✅ Pass format checks (`gofumpt`, `goimports`)\\n3. ✅ Pass all tests with coverage reporting\\n4. ✅ Upload coverage to Codecov\\n5. ✅ Pass security gates (CodeQL, Grype)\\n6. ✅ Pass license compliance (FOSSA)\\n7. ✅ Use valid Conventional Commits\\n8. ✅ Acknowledge CodeRabbit.ai findings\\n\\n### Release Criteria (Section 5.2)\\n\\nEvery release must:\\n1. ✅ Be created via automated GoReleaser flow\\n2. ✅ Include signed artifacts with checksums\\n3. ✅ Include SBOM (Syft-generated SPDX)\\n4. ✅ Include vulnerability scan reports\\n5. ✅ Include SLSA Level 3 provenance attestation\\n6. ✅ Include Cosign signatures\\n7. ✅ Pass all PR criteria above\\n\\n## Security Features\\n\\n### Supply Chain Security\\n\\n- **SLSA Level 3 Provenance**: Every release includes cryptographic proof of build integrity\\n- **Cosign Signatures**: All artifacts signed using keyless OIDC signing\\n- **SBOM Generation**: Complete software bill of materials in SPDX format\\n- **Vulnerability Scanning**: Comprehensive scanning with Grype and Snyk\\n\\n### Verification\\n\\nUsers can verify releases:\\n\\n`bash\n# Verify checksums\nsha256sum -c opnDossier_checksums.txt\n\n# Verify SLSA provenance (requires slsa-verifier)\nslsa-verifier verify-artifact \\\n  --provenance-path opnDossier-v1.0.0.intoto.jsonl \\\n  --source-uri github.com/EvilBit-Labs/opnDossier \\\n  opnDossier_checksums.txt\n\n# Verify Cosign signatures (requires cosign)\ncosign verify-blob \\\n  --bundle cosign.bundle \\\n  opnDossier_checksums.txt\n`\\n\\n## Continuous Monitoring\\n\\n### Scheduled Scans\\n\\n- **OSSF Scorecard**: Weekly repository hygiene assessment\\n- **Snyk Vulnerability Scan**: Weekly dependency vulnerability scanning\\n- **CodeQL Analysis**: Weekly code security analysis\\n- **Dependabot Updates**: Weekly dependency updates\\n\\n### Real-time Monitoring\\n\\n- **Pull Request Gates**: All security and quality checks on every PR\\n- **Commit Validation**: Conventional commits enforced\\n- **License Policy**: FOSSA license policy enforcement\\n- **Code Review**: CodeRabbit.ai advisory feedback\\n\\n## Exceptions\\n\\nPer Pipeline v2 specification, any deviations must be documented in the README under **Exceptions**.\\n\\n**Current Status**: No exceptions required - full compliance achieved.\\n\\n## Secret Management\\n\\nRequired secrets for full functionality:\\n\\n| Secret | Purpose | Required For |\\n|--------|---------|------|\\n| `CODECOV_TOKEN` | Coverage reporting | CI |\\n| `FOSSA_API_KEY` | License scanning | CI + Local |\\n| `SNYK_TOKEN` | Vulnerability scanning | CI |\\n| `SCORECARD_TOKEN` | OSSF Scorecard (optional) | CI |\\n\\n## Compliance Verification\\n\\nTo verify Pipeline v2 compliance:\\n\\n`bash\n# Run full compliance check\njust full-checks\n\n# Check individual components\njust ci-check          # Core quality gates\njust security-scan     # Security compliance\njust check-goreleaser  # Release compliance\n`\\n\\n## Resources\\n\\n- [EvilBit Labs Pipeline v2 Specification](https://github.com/EvilBit-Labs/Standards/blob/main/pipeline_v_2_spec.md)\\n- [SLSA Framework](https://slsa.dev/)\\n- [OpenSSF Scorecard](https://securityscorecards.dev/)\\n- [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/)\\n- [SPDX SBOM Standard](https://spdx.dev/)
