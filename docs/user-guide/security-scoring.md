# Security Scoring Methodology

## Overview

opnDossier's security assessment provides a standardized approach to evaluating OPNsense configuration security posture. This document explains the risk label mapping and security scoring methodology implemented in the `internal/converter/formatters/security.go` module.

## Risk Label Mapping

The security assessment uses consistent emoji + text risk labels across all output formats:

| Severity                 | Label            | Description                    |
| ------------------------ | ---------------- | ------------------------------ |
| `critical`               | 🔴 Critical Risk | Immediate attention required   |
| `high`                   | 🟠 High Risk     | High priority security concern |
| `medium`                 | 🟡 Medium Risk   | Moderate security concern      |
| `low`                    | 🟢 Low Risk      | Low priority security issue    |
| `info` / `informational` | ℹ️ Informational | Informational finding          |
| Unknown/Invalid          | ⚪ Unknown Risk  | Unrecognized severity level    |

### Usage in Reports

Risk labels are used consistently across:

- Programmatic markdown generation (`AssessRiskLevel` function)
- Service risk assessment (`AssessServiceRisk` function)

## Service Risk Assessment

The `AssessServiceRisk()` function maps common services to risk levels based on security implications:

### Critical Risk Services

- **Telnet**: Unencrypted remote access protocol

### High Risk Services

- **FTP**: Unencrypted file transfer protocol
- **VNC**: Remote desktop with potential security vulnerabilities

### Medium Risk Services

- **RDP**: Remote desktop protocol with authentication risks

### Low Risk Services

- **SSH**: Secure shell with proper authentication

### Informational Services

- **HTTPS**: Secure web services
- **Unknown/Custom**: Services not in the risk database

## Security Scoring Algorithm

The `CalculateSecurityScore()` function provides a 0-100 security score based on configuration analysis.

### Base Score: 100 points

### Penalty System

| Security Issue           | Penalty Points | Description                                    |
| ------------------------ | -------------- | ---------------------------------------------- |
| No Firewall Rules        | -20            | Missing basic firewall protection              |
| Management on WAN        | -30            | Management ports exposed on WAN interface      |
| Insecure Sysctl Settings | -5 each        | Per misconfigured system tunable               |
| Default User Accounts    | -15 each       | Per default system account (admin, root, user) |

### Sysctl Security Checks

The following system tunables are evaluated for security compliance:

| Tunable                    | Expected Value | Security Impact                                   |
| -------------------------- | -------------- | ------------------------------------------------- |
| `net.inet.ip.forwarding`   | `0`            | Prevents IP forwarding unless explicitly needed   |
| `net.inet6.ip6.forwarding` | `0`            | Prevents IPv6 forwarding unless explicitly needed |
| `net.inet.tcp.blackhole`   | `2`            | Drops TCP packets to closed ports silently        |
| `net.inet.udp.blackhole`   | `1`            | Drops UDP packets to closed ports silently        |

### Management Port Detection

The following ports are considered management ports when exposed on WAN with inbound direction:

- **22** (SSH)
- **80** (HTTP)
- **443** (HTTPS)
- **8080** (Alternative HTTP)

## Implementation Notes

### Conservative Heuristics

- Scoring uses conservative heuristics designed for audit readability
- Penalties are intentionally conservative to avoid false positives
- Score is clamped between 0-100 to ensure consistent ranges
- A `nil` document returns a score of 0

### Architecture

The security scoring functions live in `internal/converter/formatters/security.go` as standalone functions. The `MarkdownBuilder` in `internal/converter/builder/helpers.go` delegates to these functions:

```go
// Standalone functions (canonical implementation)
formatters.AssessRiskLevel("high")       // Returns: "🟠 High Risk"
formatters.CalculateSecurityScore(doc)   // Returns: 0-100
formatters.AssessServiceRisk(service)    // Returns: risk label string

// MarkdownBuilder convenience methods (delegate to formatters)
builder.AssessRiskLevel("high")
builder.CalculateSecurityScore(doc)
builder.AssessServiceRisk(service)
```

### Offline Operation

All security assessment functions operate completely offline with no external dependencies, making them suitable for airgapped environments.

## Integration with Reports

### Blue Team Reports

- Focus on clarity, grouping, and actionability
- Include compliance matrices and remediation guidance
- Highlight security features and vulnerabilities

### Red Team Reports

- Focus on target prioritization and pivot surface discovery
- Emphasize attack vectors and exposure points
- Highlight management interfaces and weak configurations

### Standard Reports

- Balanced view of configuration security posture
- Include both security strengths and areas for improvement
- Provide clear recommendations for security hardening
