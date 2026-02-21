# Compliance Standards Integration

## Overview

opnDossier integrates industry-standard security compliance frameworks to provide comprehensive blue team audit reports. The system supports **STIG (Security Technical Implementation Guide)**, **SANS Firewall Checklist**, and **CIS-inspired Firewall Security Controls** standards for firewall security assessment.

## Status

Audit mode is implemented but has known issues with finding aggregation and display. See [#266](https://github.com/EvilBit-Labs/opnDossier/issues/266) for details.

## Supported Standards

### STIG (Security Technical Implementation Guide)

STIGs are cybersecurity methodologies for standardizing security configuration within networks, servers, computers, and logical designs to enhance overall security. opnDossier implements the **DISA Firewall Security Requirements Guide** which includes:

#### Key STIG Controls

| Control ID | Title                                                         | Severity | Category            |
| ---------- | ------------------------------------------------------------- | -------- | ------------------- |
| V-206694   | Firewall must deny network communications traffic by default  | High     | Default Deny Policy |
| V-206701   | Firewall must employ filters that prevent DoS attacks         | High     | DoS Protection      |
| V-206674   | Firewall must use packet headers and attributes for filtering | High     | Packet Filtering    |
| V-206690   | Firewall must disable unnecessary network services            | Medium   | Service Hardening   |
| V-206682   | Firewall must generate comprehensive traffic logs             | Medium   | Logging             |
| V-206680   | Firewall must log network location information                | Medium   | Logging             |
| V-206679   | Firewall must log event timestamps                            | Medium   | Logging             |
| V-206678   | Firewall must log event types                                 | Medium   | Logging             |
| V-206681   | Firewall must log source information                          | Low      | Logging             |
| V-206711   | Firewall must alert on DoS incidents                          | Low      | Alerting            |

### SANS Firewall Checklist

The SANS Firewall Checklist provides practical security controls for firewall configuration and management:

#### Key SANS Controls

| Control ID  | Category                 | Title                         | Severity |
| ----------- | ------------------------ | ----------------------------- | -------- |
| SANS-FW-001 | Access Control           | Default Deny Policy           | High     |
| SANS-FW-002 | Rule Management          | Explicit Rule Configuration   | Medium   |
| SANS-FW-003 | Network Segmentation     | Network Zone Separation       | High     |
| SANS-FW-004 | Logging and Monitoring   | Comprehensive Logging         | Medium   |
| SANS-FW-005 | Service Hardening        | Unnecessary Services Disabled | Medium   |
| SANS-FW-006 | Authentication           | Strong Authentication         | High     |
| SANS-FW-007 | Encryption               | Encrypted Management          | High     |
| SANS-FW-008 | Backup and Recovery      | Configuration Backup          | Medium   |
| SANS-FW-009 | Vulnerability Management | Regular Updates               | High     |
| SANS-FW-010 | Incident Response        | Alert Configuration           | Medium   |

### CIS-Inspired Firewall Security Controls

Our CIS-inspired firewall security controls provide comprehensive security guidance designed for OPNsense firewalls, based on general industry best practices for network firewall security:

#### Key Firewall Security Controls

| Control ID   | Category              | Title                      | Severity | Description                           |
| ------------ | --------------------- | -------------------------- | -------- | ------------------------------------- |
| FIREWALL-001 | System Configuration  | SSH Warning Banner         | High     | Configure SSH warning banner          |
| FIREWALL-002 | System Configuration  | Auto Configuration Backup  | Medium   | Enable automatic configuration backup |
| FIREWALL-003 | System Configuration  | Message of the Day         | Medium   | Set appropriate MOTD message          |
| FIREWALL-004 | System Configuration  | Hostname Configuration     | Low      | Set device hostname                   |
| FIREWALL-005 | Network Configuration | DNS Server Configuration   | Medium   | Configure DNS servers                 |
| FIREWALL-006 | Network Configuration | IPv6 Disablement           | Medium   | Disable IPv6 if not used              |
| FIREWALL-007 | Network Configuration | DNS Rebind Check           | Medium   | Disable DNS rebind check              |
| FIREWALL-008 | Management Access     | HTTPS Web Management       | High     | Use HTTPS for web management          |
| FIREWALL-009 | High Availability     | HA Configuration           | Medium   | Configure synchronized HA peer        |
| FIREWALL-010 | User Management       | Session Timeout            | High     | Set session timeout to ≤10 minutes    |
| FIREWALL-011 | Authentication        | Central Authentication     | High     | Configure LDAP/RADIUS authentication  |
| FIREWALL-012 | Access Control        | Console Menu Protection    | Medium   | Password protect console menu         |
| FIREWALL-013 | User Management       | Default Account Management | High     | Secure default accounts               |
| FIREWALL-014 | User Management       | Local Account Status       | Medium   | Disable local accounts except admin   |
| FIREWALL-015 | Security Policy       | Login Protection Threshold | High     | Set threshold to ≤30                  |
| FIREWALL-016 | Security Policy       | Access Block Time          | High     | Set block time to ≥300 seconds        |
| FIREWALL-017 | Security Policy       | Default Password Change    | High     | Change default admin password         |
| FIREWALL-018 | Firewall Rules        | Destination Restrictions   | High     | No "Any" in destination field         |
| FIREWALL-019 | Firewall Rules        | Source Restrictions        | High     | No "Any" in source field              |
| FIREWALL-020 | Firewall Rules        | Service Restrictions       | High     | No "Any" in service field             |

## Implementation Details

### Plugin Architecture

Compliance checking is implemented via the plugin system in `internal/compliance/` and `internal/plugins/`:

- **`internal/compliance/interfaces.go`** - Defines the `Plugin` interface, `Control`, and `Finding` types
- **`internal/audit/plugin.go`** - Plugin registry for dynamic plugin loading
- **`internal/audit/plugin_manager.go`** - Plugin lifecycle management
- **`internal/plugins/stig/`** - STIG compliance plugin
- **`internal/plugins/sans/`** - SANS compliance plugin
- **`internal/plugins/firewall/`** - Firewall security compliance plugin

Each plugin implements the `compliance.Plugin` interface:

```go
type Plugin interface {
    Name() string
    Version() string
    Description() string
    RunChecks(device *common.CommonDevice) []Finding
    GetControls() []Control
    GetControlByID(id string) (*Control, error)
    ValidateConfiguration() error
}
```

### Compliance Checks

The audit engine performs the following types of checks:

#### STIG Compliance Checks

1. **Default Deny Policy (V-206694)**

- Verifies firewall implements deny-by-default approach
- Checks for explicit allow rules only

2. **DoS Protection (V-206701)**

- Validates DoS protection mechanisms
- Checks flood protection and rate limiting

3. **Packet Filtering (V-206674)**

- Analyzes rule specificity
- Identifies overly permissive rules

4. **Service Hardening (V-206690)**

- Checks for unnecessary services
- Validates service configuration

5. **Logging Configuration (V-206682, V-206680, V-206679, V-206678, V-206681)**

- Verifies comprehensive logging
- Checks log content and format

#### SANS Compliance Checks

1. **Access Control (SANS-FW-001)**

- Validates default deny implementation
- Checks explicit allow rules

2. **Rule Management (SANS-FW-002)**

- Analyzes rule documentation
- Checks rule specificity

3. **Network Segmentation (SANS-FW-003)**

- Validates zone separation
- Checks access controls between zones

4. **Logging and Monitoring (SANS-FW-004)**

- Verifies comprehensive logging
- Checks monitoring configuration

#### Firewall Security Compliance Checks

1. **System Configuration (FIREWALL-001, FIREWALL-002, FIREWALL-003, FIREWALL-004)**

- Validates SSH warning banner configuration
- Checks auto configuration backup settings
- Verifies MOTD customization
- Validates hostname configuration

2. **Network Configuration (FIREWALL-005, FIREWALL-006, FIREWALL-007)**

- Verifies DNS server configuration
- Checks IPv6 disablement settings
- Validates DNS rebind check configuration

3. **Management Access (FIREWALL-008)**

- Verifies HTTPS web management configuration
- Checks management access encryption

4. **High Availability (FIREWALL-009)**

- Validates HA peer configuration
- Checks synchronization settings

5. **User Management (FIREWALL-010, FIREWALL-013, FIREWALL-014)**

- Verifies session timeout configuration
- Checks default account management
- Validates local account status

6. **Authentication (FIREWALL-011)**

- Validates central authentication configuration
- Checks LDAP/RADIUS setup

7. **Access Control (FIREWALL-012)**

- Verifies console menu protection
- Checks access control settings

8. **Security Policy (FIREWALL-015, FIREWALL-016, FIREWALL-017)**

- Validates login protection threshold
- Checks access block time configuration
- Verifies default password change

9. **Firewall Rules (FIREWALL-018, FIREWALL-019, FIREWALL-020)**

- Validates destination field restrictions
- Checks source field restrictions
- Verifies service field restrictions

### Blue Team Reports

When audit mode is working correctly ([#266](https://github.com/EvilBit-Labs/opnDossier/issues/266)), the blue team report provides:

- **Executive Summary** with compliance metrics
- **Findings by Severity** with control references
- **STIG Compliance Details** with status matrix
- **SANS Compliance Details** with status matrix
- **Firewall Security Compliance Details** with status matrix
- **Security Recommendations** mapped to controls
- **Compliance Roadmap** for remediation
- **Risk Assessment** based on findings

### Report Sections

#### Executive Summary

- Total findings count
- Severity breakdown
- Compliance status summary across all standards

#### Critical/High Findings

- Detailed findings with control references
- Specific remediation guidance
- STIG/SANS/Firewall control mappings

#### Compliance Details

- Control-by-control status for each standard
- Compliance matrices
- Risk assessments

#### Recommendations

- Prioritized action items
- Control-specific guidance
- Implementation roadmap

## Compliance Mapping

### Finding to Control Mapping

Each plugin maps its findings to the relevant compliance controls using the `Finding` type from `internal/compliance/interfaces.go`. Findings include severity, description, and remediation guidance.

## Benefits

### For Blue Teams

1. **Standardized Assessment**: Use industry-recognized security controls
2. **Compliance Reporting**: Generate reports for regulatory requirements
3. **Risk Prioritization**: Focus on high-impact security issues
4. **Remediation Guidance**: Get specific action items for each finding
5. **Framework Alignment**: Align with STIG, SANS, and industry best practices

### For Organizations

1. **Regulatory Compliance**: Meet STIG, SANS, and industry security requirements
2. **Security Posture**: Understand current security state
3. **Improvement Roadmap**: Plan security enhancements
4. **Audit Readiness**: Prepare for security assessments
5. **Industry Standards**: Follow recognized best practices

## Future Enhancements

### Planned Features

1. **Additional Standards**: NIST Cybersecurity Framework, ISO 27001
2. **Custom Controls**: Organization-specific security requirements
3. **Automated Remediation**: Generate configuration fixes
4. **Compliance Monitoring**: Track compliance over time
5. **Integration**: SIEM and ticketing system integration

### Control Expansion

1. **More STIG Controls**: Additional DISA security requirements
2. **Industry-Specific**: Healthcare, finance, government controls
3. **Regional Standards**: EU, APAC, and other regional requirements
4. **Framework Mapping**: Cross-reference between standards
5. **Additional Controls**: Expand firewall security control coverage

## References

- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [SANS Firewall Checklist](https://www.sans.org/media/score/checklists/FirewallChecklist.pdf)
- [CIS-Inspired Firewall Security Controls Reference](cis-like-firewall-reference.md)
- [STIG Viewer](https://stigviewer.com/stigs/firewall_security_requirements_guide)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Support

For questions about compliance standards integration:

1. **Documentation**: Review this guide and API documentation
2. **Issues**: Report bugs or feature requests via GitHub
3. **Contributions**: Submit improvements to compliance mappings
4. **Standards**: Suggest additional security frameworks to support
