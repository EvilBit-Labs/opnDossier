# Compliance Standards Integration

## Overview

opnDossier integrates industry-standard security compliance frameworks to provide comprehensive blue team audit reports. The system supports **STIG (Security Technical Implementation Guide)**, **SANS Firewall Checklist**, and **Firewall Security Controls** (independently developed cybersecurity best practices) for firewall security assessment.

## Status

Audit mode is implemented but has known issues with finding aggregation and display. See [#266](https://github.com/EvilBit-Labs/opnDossier/issues/266) for details.

## Three-State Check Pattern

Firewall compliance checks use a three-state `checkResult` pattern:

| State                                         | Meaning                          | Audit Behavior                            |
| --------------------------------------------- | -------------------------------- | ----------------------------------------- |
| **Compliant** (`Known=true, Result=pass`)     | The check passed                 | No finding emitted                        |
| **Non-Compliant** (`Known=true, Result=fail`) | The check failed                 | Finding emitted with remediation guidance |
| **Unknown** (`Known=false`)                   | Data not available in config.xml | Check skipped entirely                    |

The "Unknown" state prevents false positives. Some settings (e.g., SSH banners, MOTD) are OS-level configurations stored outside `config.xml` and cannot be assessed from the exported configuration alone. When a check returns Unknown, opnDossier does not report a finding rather than guessing.

## Supported Standards

### STIG (Security Technical Implementation Guide)

STIGs are cybersecurity methodologies for standardizing security configuration within networks, servers, computers, and logical designs to enhance overall security. opnDossier implements the **DISA Firewall Security Requirements Guide** controls listed below.

#### Implemented STIG Controls

| Control ID | Title                                                         | Severity | Category            | Status      |
| ---------- | ------------------------------------------------------------- | -------- | ------------------- | ----------- |
| V-206694   | Firewall must deny network communications traffic by default  | High     | Default Deny Policy | Implemented |
| V-206674   | Firewall must use packet headers and attributes for filtering | High     | Packet Filtering    | Implemented |
| V-206690   | Firewall must disable unnecessary network services            | Medium   | Service Hardening   | Implemented |
| V-206682   | Firewall must generate comprehensive traffic logs             | Medium   | Logging             | Implemented |

### SANS Firewall Checklist

The SANS Firewall Checklist provides practical security controls for firewall configuration and management. The current SANS plugin defines controls and the check framework, but the check helpers use placeholder logic that always returns compliant. They will be replaced with real analysis in a future release.

#### Implemented SANS Controls

| Control ID  | Category               | Title                       | Severity | Status      |
| ----------- | ---------------------- | --------------------------- | -------- | ----------- |
| SANS-FW-001 | Access Control         | Default Deny Policy         | High     | Placeholder |
| SANS-FW-002 | Rule Management        | Explicit Rule Configuration | Medium   | Placeholder |
| SANS-FW-003 | Network Segmentation   | Network Zone Separation     | High     | Placeholder |
| SANS-FW-004 | Logging and Monitoring | Comprehensive Logging       | Medium   | Placeholder |

### Firewall Security Controls

Firewall security controls provide comprehensive security guidance designed for OPNsense firewalls, based on general cybersecurity best practices for network firewall security. See the [Firewall Security Controls Reference](firewall-security-controls-reference.md) for detailed per-control documentation.

#### Implemented Firewall Security Controls

| Control ID   | Category              | Title                            | Severity | Status      |
| ------------ | --------------------- | -------------------------------- | -------- | ----------- |
| FIREWALL-001 | SSH Security          | SSH Warning Banner Configuration | Medium   | Unknown     |
| FIREWALL-002 | Backup and Recovery   | Auto Configuration Backup        | Medium   | Implemented |
| FIREWALL-003 | System Configuration  | Message of the Day               | Low      | Unknown     |
| FIREWALL-004 | System Configuration  | Hostname Configuration           | Low      | Implemented |
| FIREWALL-005 | Network Configuration | DNS Server Configuration         | Medium   | Implemented |
| FIREWALL-006 | Network Configuration | IPv6 Disablement                 | Medium   | Implemented |
| FIREWALL-007 | DNS Security          | DNS Rebind Check                 | Low      | Unknown     |
| FIREWALL-008 | Management Access     | HTTPS Web Management             | High     | Implemented |

**Status key:**

- **Implemented** - Check logic evaluates config.xml data and produces compliant/non-compliant results
- **Unknown** - Control is defined but the required data is not available in config.xml (OS-level or model gap); the check always returns Unknown and no finding is emitted
- **Placeholder** - Control is defined with placeholder check logic that always returns compliant; real analysis will be added in a future release

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

The audit engine performs the following checks per plugin:

#### STIG Compliance Checks

1. **Default Deny Policy (V-206694)** - Looks for explicit block/reject rules in the rule set and checks that no any/any pass rules override them. If no rules exist, assumes default deny (conservative approach).

2. **Packet Filtering (V-206674)** - Scans pass rules for overly broad source/destination addresses (any, 0.0.0.0/0, ::/0, RFC 1918 ranges) and flags rules without specific port restrictions.

3. **Service Hardening (V-206690)** - Checks for SNMP with community strings, Unbound DNS with DNSSEC stripping, more than 2 DHCP interfaces, and configured load balancer services.

4. **Logging Configuration (V-206682)** - Analyzes syslog configuration for system and auth logging. Returns comprehensive, partial, not-configured, or unable-to-determine status. Finds non-compliant when syslog is disabled, logging is only partial, or logging status cannot be determined (e.g., rules exist but syslog is not configured).

#### SANS Compliance Checks

All four SANS checks currently use placeholder logic:

1. **Default Deny Policy (SANS-FW-001)** - Placeholder: always returns compliant
2. **Explicit Rule Configuration (SANS-FW-002)** - Placeholder: always returns compliant
3. **Network Zone Separation (SANS-FW-003)** - Placeholder: always returns compliant
4. **Comprehensive Logging (SANS-FW-004)** - Placeholder: always returns compliant

#### Firewall Security Compliance Checks

1. **SSH Warning Banner (FIREWALL-001)** - Always returns Unknown. SSH banners are OS-level configs (`/etc/ssh/sshd_config`) not present in config.xml.

2. **Auto Configuration Backup (FIREWALL-002)** - Checks the `Packages` list and `Firmware.Plugins` string for the `os-acb` package.

3. **Message of the Day (FIREWALL-003)** - Always returns Unknown. MOTD is an OS-level file (`/etc/motd`) not present in config.xml.

4. **Hostname Configuration (FIREWALL-004)** - Checks the device hostname against known defaults (`opnsense`, `pfsense`, `firewall`, `localhost`). Empty hostnames are also flagged.

5. **DNS Server Configuration (FIREWALL-005)** - Checks whether `System.DNSServers` is non-empty.

6. **IPv6 Disablement (FIREWALL-006)** - Checks `System.IPv6Allow`. Finding emitted when IPv6 is enabled.

7. **DNS Rebind Check (FIREWALL-007)** - Always returns Unknown. The CommonDevice model does not yet expose this setting (tracked in [#296](https://github.com/EvilBit-Labs/opnDossier/issues/296)).

8. **HTTPS Web Management (FIREWALL-008)** - Checks `System.WebGUI.Protocol` for case-insensitive match against "https".

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

Each plugin maps its findings to the relevant compliance controls using the `Finding` type from `internal/compliance/interfaces.go`. Findings include description, recommendation, and component references. Severity is defined on the `Control`, not on individual findings.

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

### Planned Control Expansion

#### STIG Controls

Additional DISA Firewall SRG controls under consideration:

- V-206701: DoS attack prevention filters
- V-206680: Network location information logging
- V-206679: Event timestamp logging
- V-206678: Event type logging
- V-206681: Source information logging
- V-206711: DoS incident alerting

#### SANS Controls

Additional SANS Firewall Checklist controls under consideration:

- SANS-FW-005: Unnecessary Services Disabled
- SANS-FW-006: Strong Authentication
- SANS-FW-007: Encrypted Management
- SANS-FW-008: Configuration Backup
- SANS-FW-009: Regular Updates
- SANS-FW-010: Alert Configuration

#### Firewall Security Controls

Additional firewall security controls under consideration:

- FIREWALL-009: HA Configuration
- FIREWALL-010: Session Timeout
- FIREWALL-011: Central Authentication (LDAP/RADIUS)
- FIREWALL-012: Console Menu Protection
- FIREWALL-013: Default Account Management
- FIREWALL-014: Local Account Status
- FIREWALL-015: Login Protection Threshold
- FIREWALL-016: Access Block Time
- FIREWALL-017: Default Password Change
- FIREWALL-018: Destination Field Restrictions
- FIREWALL-019: Source Field Restrictions
- FIREWALL-020: Service Field Restrictions

### Planned Features

1. **Real SANS Check Logic**: Replace placeholder stubs with actual analysis
2. **Additional Standards**: NIST Cybersecurity Framework, ISO 27001
3. **Custom Controls**: Organization-specific security requirements
4. **Automated Remediation**: Generate configuration fixes
5. **Compliance Monitoring**: Track compliance over time
6. **Integration**: SIEM and ticketing system integration

## References

- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [SANS Firewall Checklist](https://www.sans.org/media/score/checklists/FirewallChecklist.pdf)
- [Firewall Security Controls Reference](firewall-security-controls-reference.md)
- [STIG Viewer](https://stigviewer.com/stigs/firewall_security_requirements_guide)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Support

For questions about compliance standards integration:

1. **Documentation**: Review this guide and API documentation
2. **Issues**: Report bugs or feature requests via GitHub
3. **Contributions**: Submit improvements to compliance mappings
4. **Standards**: Suggest additional security frameworks to support
