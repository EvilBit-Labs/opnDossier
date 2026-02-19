# Pipeline v2 Compliance

This project follows the [EvilBit Labs Pipeline v2 Specification](https://github.com/EvilBit-Labs/Standards/blob/main/pipeline_v_2_spec.md) for OSS project quality gates and tooling.

## Compliance Overview

opnDossier implements all required components of the Pipeline v2 specification to ensure high-quality, secure, and maintainable code.

## Security Scanning

### GitHub CodeQL

- **Purpose**: Static application security testing (SAST)
- **Trigger**: On push to main, pull requests, and scheduled scans
- **Coverage**: Security vulnerabilities, code quality issues, potential bugs
- **Results**: Available in GitHub Security tab

### Grype Vulnerability Scanning

- **Purpose**: Container and dependency vulnerability scanning
- **Trigger**: CI builds and daily scheduled scans
- **Coverage**:
  - Filesystem scanning for vulnerabilities
  - Go module dependency scanning (`go.mod`)
- **Severity Thresholds**:
  - Main branch: >= medium severity
  - Feature branches: >= high severity
- **Results**: SARIF uploads to GitHub Security tab

### Snyk Integration

- **Purpose**: Dependency vulnerability scanning and monitoring
- **Trigger**: Continuous monitoring and PR checks
- **Coverage**: Known vulnerabilities in dependencies
- **Results**: Automated PR comments and security dashboard

## License Compliance

### FOSSA License Scanning

- **Purpose**: License compliance and policy enforcement
- **Coverage**: All dependencies and transitive dependencies
- **Policy**: Apache License 2.0 compatible dependencies only
- **Results**: [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FEvilBit-Labs%2FopnDossier.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FEvilBit-Labs%2FopnDossier?ref=badge_shield)

## Supply Chain Security

### SLSA Level 3 Provenance

- **Purpose**: Build provenance and supply chain transparency
- **Implementation**: GoReleaser with provenance generation
- **Verification**: Cryptographic attestation of build process
- **Availability**: Provenance files attached to releases

### Cosign Artifact Signing

- **Purpose**: Cryptographic signing of release artifacts
- **Implementation**: Cosign integration in release pipeline
- **Verification**: Public key verification of artifacts
- **Availability**: Signatures attached to releases

### SBOM Generation

- **Purpose**: Software Bill of Materials for transparency
- **Formats**:
  - SPDX JSON (`sbom.spdx.json`)
  - CycloneDX JSON (`sbom.cyclonedx.json`)
- **Generation**: Automated in CI/CD pipeline
- **Availability**: Downloadable from workflow run artifacts

## Code Quality

### golangci-lint

- **Purpose**: Comprehensive Go linting
- **Configuration**: `.golangci.yml` in repository root
- **Trigger**: Pre-commit hooks, CI builds, PR checks
- **Coverage**:
  - Code style
  - Common mistakes
  - Performance issues
  - Security vulnerabilities

### Comprehensive Testing

- **Unit Tests**: Required for all new functionality
- **Integration Tests**: Component interaction testing
- **Coverage Requirements**: Minimum 80% code coverage
- **CI Enforcement**: Coverage reports uploaded to Codecov

## Repository Hygiene

### OSSF Scorecard

- **Purpose**: Security health metrics for open source projects
- **Metrics Tracked**:
  - Branch protection
  - Code review practices
  - CI/CD test coverage
  - Dependency update practices
  - Vulnerability disclosure
- **Results**: Public scorecard available

### Automated Dependency Updates

- **Implementation**: Dependabot
- **Frequency**: Weekly scans for updates
- **Scope**: Go modules, GitHub Actions, development tools
- **Process**: Automated PRs with changelog and compatibility checks

## CI/CD Standards

### GitHub Actions

- **Workflows**:
  - `ci-check.yml`: Comprehensive CI checks
  - `codeql.yml`: Security analysis
  - `vulnerability-scan.yml`: Daily vulnerability scanning
  - `release.yml`: Automated release process
- **Local/CI Parity**: All CI checks runnable locally via `just ci-check`
- **Branch Protection**: Required status checks on main branch

### Just Commands for Local Development

- `just test`: Run test suite
- `just lint`: Run linters
- `just check`: Run all pre-commit checks
- `just ci-check`: Run CI-equivalent checks locally
- `just scan`: Run gosec security scanner
- `just sbom`: Generate SBOM artifacts (cyclonedx-gomod)

## Vulnerability Management

### Scanning Frequency

- **CI Builds**: On every push and pull request
- **Scheduled Scans**: Daily at 00:00 UTC
- **Manual Scans**: Via `just scan` command

### Severity Handling

| Severity | Main Branch | Feature Branch | Action Required      |
| -------- | ----------- | -------------- | -------------------- |
| Critical | Block       | Block          | Immediate fix        |
| High     | Block       | Block          | Fix before merge     |
| Medium   | Block       | Warn           | Fix required on main |
| Low      | Warn        | Info           | Fix in backlog       |

### Reporting

- **SARIF Uploads**: GitHub Security tab (Code Scanning)
- **Workflow Artifacts**:
  - Human-readable table reports
  - Machine-readable JSON reports
  - SBOM files
- **Notifications**: GitHub Security Advisories

## Exceptions

Currently no exceptions to the Pipeline v2 specification are required for this project.

## Compliance Verification

To verify compliance with Pipeline v2 specification:

```bash
# Run all quality checks
just ci-check

# Run security scans
just scan

# Generate SBOM
just sbom

# Run all security checks
just security-all

# Verify test coverage
just test
```

## Related Documentation

- [Vulnerability Scanning](vulnerability-scanning.md)
- [Security Policy](https://github.com/EvilBit-Labs/opnDossier/blob/main/SECURITY.md)
- [Contributing Guidelines](https://github.com/EvilBit-Labs/opnDossier/blob/main/CONTRIBUTING.md)
- [Pipeline v2 Specification](https://github.com/EvilBit-Labs/Standards/blob/main/pipeline_v_2_spec.md)
