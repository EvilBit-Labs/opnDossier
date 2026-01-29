# Security Scoring Methodology

## Overview

The opnDossier security assessment functions provide a standardized approach to evaluating OPNsense configuration security posture. This document explains the risk label mapping and security scoring methodology implemented in the `MarkdownBuilder` security functions.

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

- Programmatic markdown generation (`AssessRiskLevel` method)
- Service risk assessment (`AssessServiceRisk` method)

## Service Risk Assessment

The `AssessServiceRisk()` method maps common services to risk levels based on security implications:

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

The `CalculateSecurityScore()` method provides a 0-100 security score based on configuration analysis.

### Base Score: 100 points

### Penalty System

| Security Issue           | Penalty Points | Description                                           |
| ------------------------ | -------------- | ----------------------------------------------------- |
| No Firewall Rules        | -20            | Missing basic firewall protection                     |
| Management on WAN        | -30            | Administrative services exposed to untrusted networks |
| Insecure Sysctl Settings | -5 each        | Per misconfigured system tunable                      |
| Default User Accounts    | -15 each       | Per default system account (admin, root, user)        |

### Sysctl Security Checks

The following system tunables are evaluated for security compliance:

| Tunable                    | Expected Value | Security Impact                                   |
| -------------------------- | -------------- | ------------------------------------------------- |
| `net.inet.ip.forwarding`   | `0`            | Prevents IP forwarding unless explicitly needed   |
| `net.inet6.ip6.forwarding` | `0`            | Prevents IPv6 forwarding unless explicitly needed |
| `net.inet.tcp.blackhole`   | `2`            | Drops TCP packets to closed ports silently        |
| `net.inet.udp.blackhole`   | `1`            | Drops UDP packets to closed ports silently        |

### Management Port Detection

The following ports are considered management ports when exposed on WAN:

- **22** (SSH)
- **80** (HTTP)
- **443** (HTTPS)
- **8080** (Alternative HTTP)

## Implementation Notes

### Conservative Heuristics

- Scoring uses conservative heuristics designed for audit readability
- Penalties are intentionally conservative to avoid false positives
- Score is clamped between 0-100 to ensure consistent ranges

### Single Source of Truth

The current implementation provides a transparent wrapper while existing scoring logic is consolidated. Future updates will centralize scoring logic to ensure consistency across the model, processor, and converter layers.

### Offline Operation

All security assessment functions operate completely offline with no external dependencies, making them suitable for airgapped environments.

## Usage Examples

### Risk Level Assessment

```go
builder := NewMarkdownBuilder()
risk := builder.AssessRiskLevel("high")
// Returns: "🟠 High Risk"
```

### Service Risk Assessment

```go
service := model.Service{Name: "SSH Daemon"}
risk := builder.AssessServiceRisk(service)
// Returns: "🟢 Low Risk"
```

### Security Score Calculation

```go
score := builder.CalculateSecurityScore(opnSenseDocument)
// Returns: 0-100 integer score
```

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

## Future Enhancements

1. **Centralized Scoring**: Consolidate scoring logic across model, processor, and converter layers
2. **Configurable Weights**: Allow customization of penalty weights for different environments
3. **Extended Service Database**: Expand service risk mappings for additional protocols
4. **Compliance Integration**: Integrate with STIG, SANS, and other compliance frameworks
5. **Dynamic Risk Assessment**: Incorporate threat intelligence and configuration context
