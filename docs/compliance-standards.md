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

The [SANS SCORE Firewall Checklist](https://www.sans.org/media/score/checklists/FirewallChecklist.pdf) (prepared by Krishni Naidu) is a practical security audit checklist containing 24 numbered security elements for firewall configuration and management. It covers ruleset management, application-layer controls, logging, patching, DMZ architecture, anti-spoofing, port security, remote access, traffic filtering, and availability.

The current SANS plugin defines 4 controls with placeholder check logic. The checklist has been fully analyzed and 16 additional controls are planned for implementation, covering the complete SANS checklist.

#### Implemented SANS Controls

| Control ID  | SANS # | Category               | Title                       | Severity | Status      |
| ----------- | ------ | ---------------------- | --------------------------- | -------- | ----------- |
| SANS-FW-001 | 1, 9   | Access Control         | Default Deny Policy         | High     | Placeholder |
| SANS-FW-002 | 1      | Rule Management        | Explicit Rule Configuration | Medium   | Placeholder |
| SANS-FW-003 | 6      | Network Segmentation   | Network Zone Separation     | High     | Placeholder |
| SANS-FW-004 | 4      | Logging and Monitoring | Comprehensive Logging       | Medium   | Placeholder |

#### Planned SANS Controls

The following controls map to specific SANS SCORE Firewall Checklist items and are planned for implementation. "Implementability" indicates whether the control can be evaluated from config.xml data alone.

##### Ruleset and Filtering (SANS Checklist #1, #2, #3)

| Control ID  | SANS # | Title                       | Severity | Implementability | Description                                                                                                              |
| ----------- | ------ | --------------------------- | -------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| SANS-FW-005 | 1      | Ruleset Ordering            | High     | Full             | Verify rules follow correct processing order: anti-spoofing filters, user permit rules, management permits, deny-and-log |
| SANS-FW-006 | 2      | Application Layer Filtering | Medium   | Partial          | Check for application-layer controls: proxy plugins, URL filtering, content inspection                                   |
| SANS-FW-007 | 3      | Stateful Inspection         | High     | Full             | Verify stateful inspection is enabled (StateType field), check state timeouts are not excessively long                   |

##### Maintenance and Compliance (SANS Checklist #5, #7, #8)

| Control ID  | SANS # | Title                           | Severity | Implementability | Description                                                                                   |
| ----------- | ------ | ------------------------------- | -------- | ---------------- | --------------------------------------------------------------------------------------------- |
| SANS-FW-008 | 5      | Firmware Currency               | High     | Partial          | Check device firmware version against known current versions; verify update mirror uses HTTPS |
| SANS-FW-010 | 7      | Vulnerability Testing Procedure | Medium   | Advisory only    | Advisory: verify that open port testing and ruleset validation procedures are documented      |
| SANS-FW-011 | 8      | Security Policy Compliance      | High     | Advisory only    | Advisory: verify ruleset compliance with organizational security policy                       |

##### Anti-Spoofing and Traffic Validation (SANS Checklist #9, #10, #18)

| Control ID  | SANS # | Title                           | Severity | Implementability | Description                                                                                                                 |
| ----------- | ------ | ------------------------------- | -------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| SANS-FW-012 | 9      | Anti-Spoofing / Bogon Filtering | Critical | Full             | Block RFC 1918, bogon, broadcast, and illegal addresses on WAN interfaces; check `BlockPrivate` and `BlockBogons` flags     |
| SANS-FW-013 | 10     | Source Routing Prevention       | High     | Full             | Verify `net.inet.ip.sourceroute=0` and `net.inet.ip.accept_sourceroute=0` in system tunables                                |
| SANS-FW-021 | 18     | Egress Filtering                | High     | Full             | Verify outbound rules restrict source addresses to internal network ranges; flag rules allowing non-internal source IPs out |

##### Port and Service Filtering (SANS Checklist #11, #12, #14, #15, #17)

| Control ID  | SANS # | Title                           | Severity | Implementability | Description                                                                                                               |
| ----------- | ------ | ------------------------------- | -------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------- |
| SANS-FW-014 | 11     | Dangerous Service Port Blocking | High     | Full             | Scan WAN pass rules for dangerous ports: NetBIOS (135-139, 445), SNMP (161-162), NFS (2049), X11 (6000-6255), Telnet (23) |
| SANS-FW-015 | 12     | Secure Remote Access            | High     | Full             | Verify SSH is used instead of Telnet; check for Telnet-related pass rules on WAN; verify `System.SSH.Enabled`             |
| SANS-FW-017 | 14     | Mail Traffic Restriction        | Medium   | Full             | Check SMTP (TCP 25) and submission (TCP 587) pass rules target specific mail relay IPs, not "any" destination             |
| SANS-FW-018 | 15     | ICMP Filtering                  | Medium   | Full             | Verify ICMP echo requests blocked on WAN; check for type-specific ICMP rules                                              |
| SANS-FW-020 | 17     | DNS Zone Transfer Restriction   | High     | Full             | Verify TCP 53 pass rules on WAN are restricted to authorized secondary DNS server IPs, not "any" source                   |

##### Network Architecture (SANS Checklist #6, #13, #16)

| Control ID  | SANS # | Title                 | Severity | Implementability | Description                                                                                                           |
| ----------- | ------ | --------------------- | -------- | ---------------- | --------------------------------------------------------------------------------------------------------------------- |
| SANS-FW-009 | 6      | DMZ Configuration     | High     | Full             | Check for DMZ interface existence; verify rules enforce DMZ-to-WAN and DMZ-to-LAN segmentation                        |
| SANS-FW-016 | 13     | FTP Server Isolation  | Medium   | Partial          | Check that FTP-related (TCP 21) pass rules route to DMZ/separate interface, not internal network                      |
| SANS-FW-019 | 16     | NAT / IP Masquerading | High     | Full             | Verify outbound NAT configured on WAN; check `NATConfig.OutboundMode`; ensure internal IPs are not exposed externally |

##### Server Protection and Availability (SANS Checklist #19, #22, #23, #24)

| Control ID  | SANS # | Title                      | Severity | Implementability | Description                                                                                                             |
| ----------- | ------ | -------------------------- | -------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| SANS-FW-022 | 19     | Critical Server Protection | High     | Partial          | Check for explicit deny rules protecting internal server IPs from WAN; flag any rules allowing direct WAN-to-LAN access |
| SANS-FW-023 | 22     | Default Credential Reset   | Critical | Partial          | Check `Users` for default/well-known usernames (admin, root); cannot verify password change from config alone           |
| SANS-FW-024 | 23     | TCP State Enforcement      | High     | Full             | Verify stateful inspection (keep state) is used on TCP rules rather than stateless filtering                            |
| SANS-FW-025 | 24     | Firewall High Availability | Medium   | Full             | Check for CARP/HA configuration in `HighAvailability`; verify pfsync peer and synchronization settings                  |

##### SANS Checklist Items Not Applicable to Config Audit

The following SANS checklist items are procedural or endpoint-focused and cannot be evaluated from a single device configuration export:

| SANS # | Title                       | Reason                                                              |
| ------ | --------------------------- | ------------------------------------------------------------------- |
| 20     | Personal Firewalls          | Endpoint security — not a network firewall configuration control    |
| 21     | Distributed Firewall Policy | Multi-device policy distribution — requires enterprise architecture |

### Firewall Security Controls

Firewall security controls provide comprehensive security guidance designed for OPNsense and pfSense firewalls, based on general cybersecurity best practices for network firewall security. They are independently developed by EvilBit Labs and draw from industry frameworks including NIST SP 800-41, PCI DSS Requirement 1, CIS Benchmarks, and NSA/CISA network infrastructure guidance.

See the [Firewall Security Controls Reference](firewall-security-controls-reference.md) for detailed per-control documentation.

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

#### Planned Firewall Security Controls

The following controls are organized by security domain and represent the full planned expansion of the firewall plugin. Controls are sourced from NIST SP 800-41, PCI DSS v4.0 Requirement 1, CIS Benchmarks, NSA/CISA guidance, and OPNsense/pfSense-specific best practices.

##### Management Plane Security

| Control ID   | Title                            | Severity | Implementability | Description                                                                    |
| ------------ | -------------------------------- | -------- | ---------------- | ------------------------------------------------------------------------------ |
| FIREWALL-009 | Non-Default Web GUI Port         | Low      | Full             | Web GUI port changed from default 443 to reduce automated scanning risk        |
| FIREWALL-010 | Management Interface Restriction | High     | Partial          | Web GUI bound to specific interfaces, not all interfaces                       |
| FIREWALL-011 | TLS Version Minimum              | High     | Partial          | Web GUI TLS minimum version >= 1.2; no SSLv3/TLS 1.0/1.1                       |
| FIREWALL-012 | Anti-Lockout Rule Awareness      | Low      | Partial          | Anti-lockout rule status is explicitly configured and intentional              |
| FIREWALL-013 | Session Timeout                  | Medium   | Partial          | Web GUI idle session timeout configured (\<= 30 minutes recommended)           |
| FIREWALL-014 | Console Menu Protection          | Medium   | Full             | Serial/console access password-protected (`DisableConsoleMenu`)                |
| FIREWALL-015 | Login Protection / Brute Force   | Medium   | Partial          | Web GUI login protection enabled with rate limiting on authentication failures |

##### Authentication and Access Control

| Control ID   | Title                         | Severity | Implementability | Description                                                                                         |
| ------------ | ----------------------------- | -------- | ---------------- | --------------------------------------------------------------------------------------------------- |
| FIREWALL-016 | Default Credential Reset      | Critical | Partial          | Default admin password changed; check for known default username patterns                           |
| FIREWALL-017 | Unique Administrator Accounts | Medium   | Full             | Each administrator has a unique named account; shared "admin" usage flagged                         |
| FIREWALL-018 | Least Privilege Access        | Medium   | Full             | Users assigned minimum necessary privileges; flag users with `page-all` or overly broad permissions |
| FIREWALL-019 | Centralized Authentication    | Medium   | Full             | LDAP/RADIUS configured for admin authentication (`System.AuthServer`)                               |
| FIREWALL-020 | Disabled Unused Accounts      | Medium   | Full             | Unused or default accounts are disabled; flag active accounts with no recent purpose                |
| FIREWALL-021 | Group-Based Privileges        | Low      | Full             | Privileges assigned via groups rather than per-user for consistent access control                   |

##### Firewall Rule Hygiene

| Control ID   | Title                          | Severity | Implementability | Description                                                                   |
| ------------ | ------------------------------ | -------- | ---------------- | ----------------------------------------------------------------------------- |
| FIREWALL-022 | No "Any-Any" Pass Rules        | High     | Full             | No rules with source=any, destination=any, port=any, protocol=any             |
| FIREWALL-023 | No "Any" Source on WAN Inbound | High     | Full             | Inbound WAN pass rules have specific source restrictions where possible       |
| FIREWALL-024 | Specific Port Rules            | Medium   | Full             | Rules specify exact ports/services, not "any" port with TCP/UDP               |
| FIREWALL-025 | Rule Documentation             | Medium   | Full             | Every firewall rule has a non-empty description (`descr` field)               |
| FIREWALL-026 | Disabled Rule Cleanup          | Low      | Full             | Flag excessive disabled rules (threshold: >10) indicating stale configuration |
| FIREWALL-027 | Protocol Specification         | Medium   | Full             | Pass rules specify protocol (TCP, UDP, ICMP), not "any"                       |
| FIREWALL-028 | Pass Rule Logging              | Medium   | Full             | Critical pass rules have logging enabled for security monitoring              |

##### Network Segmentation

| Control ID   | Title                            | Severity | Implementability | Description                                                                    |
| ------------ | -------------------------------- | -------- | ---------------- | ------------------------------------------------------------------------------ |
| FIREWALL-029 | Private Address Filtering on WAN | Critical | Full             | `BlockPrivate` enabled on WAN interface to block RFC 1918 addresses            |
| FIREWALL-030 | Bogon Filtering on WAN           | Critical | Full             | `BlockBogons` enabled on WAN interface to block unallocated/reserved addresses |
| FIREWALL-031 | Unused Interface Disablement     | Low      | Full             | Interfaces not in use are administratively disabled                            |
| FIREWALL-032 | VLAN Segmentation                | Medium   | Full             | VLANs configured for network segmentation where multiple security zones exist  |

##### Anti-Spoofing and Traffic Validation

| Control ID   | Title                   | Severity | Implementability | Description                                                                   |
| ------------ | ----------------------- | -------- | ---------------- | ----------------------------------------------------------------------------- |
| FIREWALL-033 | Source Route Rejection  | High     | Full             | IP source routing disabled via `net.inet.ip.sourceroute=0` in system tunables |
| FIREWALL-034 | SYN Flood Protection    | Medium   | Full             | SYN cookies enabled via `net.inet.tcp.syncookies=1` in system tunables        |
| FIREWALL-035 | Connection State Limits | Medium   | Full             | Maximum state table entries configured (`System.MaximumStates`)               |

##### Encryption and TLS

| Control ID   | Title                     | Severity | Implementability | Description                                                                   |
| ------------ | ------------------------- | -------- | ---------------- | ----------------------------------------------------------------------------- |
| FIREWALL-036 | Valid Web GUI Certificate | Medium   | Partial          | Web GUI uses a valid (non-self-signed or internally-trusted CA) certificate   |
| FIREWALL-037 | Certificate Expiration    | Medium   | Full             | No certificates expired or expiring within 30 days                            |
| FIREWALL-038 | Strong Key Lengths        | Medium   | Full             | RSA keys >= 2048 bits, EC keys >= 256 bits across all configured certificates |

##### Logging and Monitoring

| Control ID   | Title                        | Severity | Implementability | Description                                                                                |
| ------------ | ---------------------------- | -------- | ---------------- | ------------------------------------------------------------------------------------------ |
| FIREWALL-039 | Remote Syslog Configured     | High     | Full             | Logs forwarded to remote syslog/SIEM server (`Syslog.RemoteServer` non-empty)              |
| FIREWALL-040 | Authentication Event Logging | Medium   | Full             | Auth logging enabled (`Syslog.AuthLogging`)                                                |
| FIREWALL-041 | Firewall Filter Logging      | Medium   | Full             | Firewall filter logging enabled (`Syslog.FilterLogging`)                                   |
| FIREWALL-042 | Log Retention Configuration  | Low      | Full             | Local log rotation and size limits configured (`Syslog.LogFileSize`, `Syslog.RotateCount`) |

##### Time Synchronization

| Control ID   | Title                  | Severity | Implementability | Description                                                    |
| ------------ | ---------------------- | -------- | ---------------- | -------------------------------------------------------------- |
| FIREWALL-043 | NTP Configuration      | Medium   | Full             | At least 2 NTP time sources configured in `System.TimeServers` |
| FIREWALL-044 | Timezone Configuration | Low      | Full             | System timezone explicitly set (not empty/default)             |

##### SNMP Security

| Control ID   | Title                        | Severity | Implementability | Description                                                                   |
| ------------ | ---------------------------- | -------- | ---------------- | ----------------------------------------------------------------------------- |
| FIREWALL-045 | SNMP Disabled if Unused      | Medium   | Full             | SNMP service disabled if `ROCommunity` is empty and no operational need       |
| FIREWALL-046 | No Default Community Strings | High     | Full             | SNMP community strings changed from well-known defaults ("public", "private") |

##### VPN Configuration

| Control ID   | Title                    | Severity | Implementability | Description                                                             |
| ------------ | ------------------------ | -------- | ---------------- | ----------------------------------------------------------------------- |
| FIREWALL-047 | Strong VPN Encryption    | High     | Full             | VPN tunnels use AES-256-GCM or AES-128-GCM; no DES, 3DES, or Blowfish   |
| FIREWALL-048 | Strong VPN Integrity     | High     | Full             | VPN uses SHA-256+ for integrity; no MD5 or SHA-1                        |
| FIREWALL-049 | Perfect Forward Secrecy  | High     | Full             | PFS enabled on all IPsec Phase 2 tunnels (`PFSGroup` is set, not "off") |
| FIREWALL-050 | VPN Key Lifetime         | Medium   | Full             | IKE Phase 1 lifetime \<= 28800s, Phase 2 lifetime \<= 3600s             |
| FIREWALL-051 | No IKEv1 Aggressive Mode | High     | Full             | IKEv1 aggressive mode disabled; use main mode or IKEv2                  |
| FIREWALL-052 | IKEv2 Preferred          | Medium   | Full             | IKEv2 used instead of IKEv1 where possible (`IKEType = "ikev2"`)        |
| FIREWALL-053 | Dead Peer Detection      | Medium   | Full             | DPD enabled on IPsec Phase 1 tunnels (`DPDDelay`, `DPDMaxFail`)         |

##### NAT Security

| Control ID   | Title                    | Severity | Implementability | Description                                                                                      |
| ------------ | ------------------------ | -------- | ---------------- | ------------------------------------------------------------------------------------------------ |
| FIREWALL-054 | Documented Port Forwards | Medium   | Full             | Every inbound NAT rule has a non-empty description                                               |
| FIREWALL-055 | Outbound NAT Control     | Medium   | Full             | Outbound NAT mode is "Hybrid" or "Manual", not "Automatic" for production environments           |
| FIREWALL-056 | NAT Reflection Disabled  | Low      | Full             | NAT reflection (hairpin NAT) disabled unless explicitly required (`System.DisableNATReflection`) |

##### Service Hardening

| Control ID   | Title                           | Severity | Implementability | Description                                                               |
| ------------ | ------------------------------- | -------- | ---------------- | ------------------------------------------------------------------------- |
| FIREWALL-057 | UPnP/NAT-PMP Disabled           | High     | Partial          | UPnP and NAT-PMP disabled (automatic port forwarding is a security risk)  |
| FIREWALL-058 | DNSSEC Validation               | Medium   | Full             | Unbound DNS resolver has DNSSEC validation enabled (`DNS.Unbound.DNSSEC`) |
| FIREWALL-059 | DNS Resolver Access Restriction | Medium   | Partial          | DNS resolver serves only internal networks, not WAN-facing                |

##### Change Management and Backup

| Control ID   | Title                           | Severity | Implementability | Description                                                |
| ------------ | ------------------------------- | -------- | ---------------- | ---------------------------------------------------------- |
| FIREWALL-060 | Configuration Revision Tracking | Low      | Full             | Configuration change history and revision tracking enabled |

##### High Availability

| Control ID   | Title            | Severity | Implementability | Description                                                                   |
| ------------ | ---------------- | -------- | ---------------- | ----------------------------------------------------------------------------- |
| FIREWALL-061 | HA Configuration | Medium   | Full             | CARP/pfsync HA peer and synchronization properly configured when HA is in use |

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
    // Single-pass evaluation: returns findings AND the set of control IDs
    // the plugin was able to evaluate on this device, in one traversal.
    RunChecks(device *common.CommonDevice) (findings []Finding, evaluated []string, err error)
    // GetControls must return a defensive deep copy — callers do not clone again.
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

Each plugin maps its findings to the relevant compliance controls using the `Finding` type from `internal/compliance/interfaces.go`. Findings include description, recommendation, and component references. Each finding carries a `Severity` field copied from its originating control, enabling the audit engine to accurately tally findings by severity level (critical, high, medium, low).

### Cross-Standard Coverage

Many controls overlap across standards. The following matrix shows where SANS and Firewall controls address the same security concern:

| Security Concern          | STIG     | SANS        | Firewall     |
| ------------------------- | -------- | ----------- | ------------ |
| Default deny policy       | V-206694 | SANS-FW-001 | FIREWALL-022 |
| Specific packet filtering | V-206674 | SANS-FW-002 | FIREWALL-024 |
| Unnecessary services      | V-206690 | —           | FIREWALL-057 |
| Comprehensive logging     | V-206682 | SANS-FW-004 | FIREWALL-039 |
| Anti-spoofing / bogons    | —        | SANS-FW-012 | FIREWALL-029 |
| HTTPS management          | —        | —           | FIREWALL-008 |
| Strong VPN encryption     | —        | —           | FIREWALL-047 |
| Default credentials       | —        | SANS-FW-023 | FIREWALL-016 |
| High availability         | —        | SANS-FW-025 | FIREWALL-061 |
| NAT / IP masquerading     | —        | SANS-FW-019 | FIREWALL-055 |

## Implementation Priority

### Phase 1 — High Impact, Directly Implementable

Controls that can be fully evaluated from existing CommonDevice fields:

**SANS:** SANS-FW-012 (anti-spoofing/bogon), SANS-FW-014 (dangerous ports), SANS-FW-005 (ruleset ordering), SANS-FW-021 (egress filtering), SANS-FW-019 (NAT), SANS-FW-024 (TCP state), SANS-FW-015 (secure remote access)

**Firewall:** FIREWALL-022 (no any-any rules), FIREWALL-029 (private address filtering), FIREWALL-030 (bogon filtering), FIREWALL-025 (rule documentation), FIREWALL-039 (remote syslog), FIREWALL-043 (NTP), FIREWALL-046 (SNMP community strings), FIREWALL-047 through 053 (VPN controls)

### Phase 2 — Cross-Reference Checks

Controls requiring correlation between multiple config sections:

FIREWALL-018 (least privilege), FIREWALL-054-056 (NAT controls), FIREWALL-032 (VLAN segmentation), FIREWALL-036-038 (certificate controls), SANS-FW-017 (mail traffic), SANS-FW-020 (DNS zone transfers), SANS-FW-022 (critical server protection)

### Phase 3 — Advanced Analysis

Controls requiring deeper algorithmic analysis or external data:

SANS-FW-008 (firmware version comparison), FIREWALL-034-035 (DoS protection tunables), SANS-FW-006 (application layer filtering)

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

### Additional STIG Controls

Additional DISA Firewall SRG controls under consideration:

- V-206701: DoS attack prevention filters
- V-206680: Network location information logging
- V-206679: Event timestamp logging
- V-206678: Event type logging
- V-206681: Source information logging
- V-206711: DoS incident alerting

### Additional Standards

- **NIST Cybersecurity Framework** — Map existing controls to NIST CSF categories
- **PCI DSS v4.0** — Requirement 1 (network security controls) alignment
- **ISO 27001** — Annex A network security controls
- **CIS Benchmarks** — Community-derived firewall hardening controls
- **Custom Controls** — Organization-specific security requirements

### Planned Features

1. **Real SANS Check Logic**: Replace placeholder stubs with actual analysis
2. **Automated Remediation**: Generate configuration fixes
3. **Compliance Monitoring**: Track compliance over time
4. **Integration**: SIEM and ticketing system integration

## References

- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [DISA Firewall Security Requirements Guide](https://stigviewer.com/stigs/firewall_security_requirements_guide)
- [SANS SCORE Firewall Checklist (PDF)](https://www.sans.org/media/score/checklists/FirewallChecklist.pdf)
- [NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/pubs/sp/800/41/r1/final)
- [NIST SP 800-53 — Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [PCI DSS v4.0 — Requirement 1](https://www.pcisecuritystandards.org/)
- [NSA/CISA Network Infrastructure Security Guide](https://media.defense.gov/2022/Jun/15/2003018261/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDE_20220615.PDF)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Firewall Security Controls Reference](firewall-security-controls-reference.md)

## Support

For questions about compliance standards integration:

1. **Documentation**: Review this guide and API documentation
2. **Issues**: Report bugs or feature requests via GitHub
3. **Contributions**: Submit improvements to compliance mappings
4. **Standards**: Suggest additional security frameworks to support
