# Firewall Security Controls Reference

## Overview

This document is the authoritative reference for the firewall security controls implemented in opnDossier. These controls are independently developed by EvilBit Labs based on general cybersecurity best practices for network firewalls and are designed for OPNsense configurations. They are not affiliated with, endorsed by, or derived from any third-party benchmark organization.

For the broader compliance standards overview (including STIG and SANS), see [Compliance Standards](compliance-standards.md).

## Three-State Check Pattern

Each firewall compliance check returns one of three states:

- **Compliant**: The configuration meets the control requirement. No finding is emitted.
- **Non-Compliant**: The configuration does not meet the control requirement. A finding is emitted with remediation guidance.
- **Unknown**: The data needed to evaluate the control is not available in config.xml (OS-level setting or model gap). The check is skipped entirely to avoid false positives.

## Controls Summary

| Control ID   | Title                            | Category              | Severity | Status      |
| ------------ | -------------------------------- | --------------------- | -------- | ----------- |
| FIREWALL-001 | SSH Warning Banner Configuration | SSH Security          | Medium   | Unknown     |
| FIREWALL-002 | Auto Configuration Backup        | Backup and Recovery   | Medium   | Implemented |
| FIREWALL-003 | Message of the Day               | System Configuration  | Info     | Unknown     |
| FIREWALL-004 | Hostname Configuration           | System Configuration  | Low      | Implemented |
| FIREWALL-005 | DNS Server Configuration         | Network Configuration | Medium   | Implemented |
| FIREWALL-006 | IPv6 Disablement                 | Network Configuration | Medium   | Implemented |
| FIREWALL-007 | DNS Rebind Protection            | DNS Security          | Medium   | Implemented |
| FIREWALL-008 | HTTPS Web Management             | Management Access     | High     | Implemented |

---

## FIREWALL-001: SSH Warning Banner Configuration

| Field        | Value                                         |
| ------------ | --------------------------------------------- |
| **ID**       | FIREWALL-001                                  |
| **Category** | SSH Security                                  |
| **Severity** | Medium                                        |
| **Status**   | Unknown (OS-level setting)                    |
| **Tags**     | `ssh-security`, `banner`, `firewall-controls` |

### Description

An SSH warning banner should be configured to display before authentication. Warning banners provide legal notice to users connecting to the system and can aid in the prosecution of unauthorized access attempts.

### Rationale

SSH warning banners serve two purposes: they inform authorized users of acceptable use policies, and they establish a legal basis for prosecution of intruders by demonstrating that notice was given. Many compliance frameworks require login banners on all management interfaces.

### What opnDossier Checks

**Always returns Unknown.** SSH banners are configured at the OS level in `/etc/ssh/sshd_config` (the `Banner` directive), which is not part of the OPNsense `config.xml` export. opnDossier cannot determine whether a banner is configured from the configuration file alone.

### Recommended Action

Configure the SSH warning banner:

1. Edit `/etc/ssh/sshd_config` on the OPNsense appliance
2. Set `Banner /etc/issue.net`
3. Create `/etc/issue.net` with an appropriate legal notice
4. Restart the SSH service

---

## FIREWALL-002: Auto Configuration Backup

| Field        | Value                                          |
| ------------ | ---------------------------------------------- |
| **ID**       | FIREWALL-002                                   |
| **Category** | Backup and Recovery                            |
| **Severity** | Medium                                         |
| **Status**   | Implemented                                    |
| **Tags**     | `backup`, `configuration`, `firewall-controls` |

### Description

Automatic configuration backup should be enabled to ensure configuration changes are preserved and can be restored in case of failure or misconfiguration.

### Rationale

Automatic backups protect against configuration loss from hardware failure, accidental changes, or security incidents. The OPNsense `os-acb` (AutoConfigBackup) plugin provides automated, versioned backups that can be restored quickly.

### What opnDossier Checks

Searches for the `os-acb` package in two locations:

1. The `Packages` list on the CommonDevice (case-insensitive match on `Name` against `"os-acb"` with `Installed == true`)
2. The `System.Firmware.Plugins` comma-separated string (splits on commas, trims whitespace, case-insensitive exact match against each entry)

If neither source contains the package, a non-compliant finding is emitted.

### Recommended Action

Install and enable AutoConfigBackup:

1. Navigate to **System > Firmware > Plugins**
2. Install the `os-acb` plugin
3. Configure backup settings in **Services > Auto Config Backup**

---

## FIREWALL-003: Message of the Day

| Field        | Value                                       |
| ------------ | ------------------------------------------- |
| **ID**       | FIREWALL-003                                |
| **Category** | System Configuration                        |
| **Severity** | Info                                        |
| **Status**   | Unknown (OS-level setting)                  |
| **Tags**     | `motd`, `legal-notice`, `firewall-controls` |

### Description

The Message of the Day (MOTD) should be customized to provide legal notice and consent for monitoring to users who access the system console.

### Rationale

A custom MOTD provides a legal notice similar to the SSH banner but for console access. It informs users that the system is monitored and that unauthorized access is prohibited, supporting legal and compliance requirements.

### What opnDossier Checks

**Always returns Unknown.** The MOTD is an OS-level file (`/etc/motd`) that is not part of the OPNsense `config.xml` export. opnDossier cannot determine whether it has been customized from the configuration file alone.

### Recommended Action

Customize the MOTD:

1. SSH into the OPNsense appliance
2. Edit `/etc/motd` with an appropriate legal notice
3. Include language about authorized use, monitoring, and consent

---

## FIREWALL-004: Hostname Configuration

| Field        | Value                                                   |
| ------------ | ------------------------------------------------------- |
| **ID**       | FIREWALL-004                                            |
| **Category** | System Configuration                                    |
| **Severity** | Low                                                     |
| **Status**   | Implemented                                             |
| **Tags**     | `hostname`, `asset-identification`, `firewall-controls` |

### Description

The device hostname should be changed from factory defaults to a meaningful, custom value for proper asset identification and management.

### Rationale

A custom hostname is essential for asset identification in environments with multiple network devices. Default hostnames make it difficult to distinguish devices in logs, monitoring systems, and network management tools.

### What opnDossier Checks

Reads `System.Hostname` from the CommonDevice and checks it against known factory defaults (case-insensitive):

- `opnsense`
- `pfsense`
- `firewall`
- `localhost`

An empty hostname is also treated as non-compliant. Any other value is considered compliant.

### Recommended Action

Set a custom hostname:

1. Navigate to **System > General Setup**
2. Change the hostname to a meaningful name following your organization's naming convention
3. Save and apply changes

---

## FIREWALL-005: DNS Server Configuration

| Field        | Value                                        |
| ------------ | -------------------------------------------- |
| **ID**       | FIREWALL-005                                 |
| **Category** | Network Configuration                        |
| **Severity** | Medium                                       |
| **Status**   | Implemented                                  |
| **Tags**     | `dns`, `network-config`, `firewall-controls` |

### Description

DNS servers should be explicitly configured rather than relying on DHCP-assigned or unconfigured defaults.

### Rationale

Explicit DNS configuration ensures reliable and predictable name resolution. Without configured DNS servers, the firewall may use DHCP-assigned servers that could be controlled by an attacker, or name resolution may fail entirely, affecting firewall rules that reference hostnames.

### What opnDossier Checks

Checks whether `System.DNSServers` contains at least one entry. If the list is empty, a non-compliant finding is emitted.

### Recommended Action

Configure DNS servers:

1. Navigate to **System > General Setup**
2. Add at least one DNS server (e.g., your organization's internal DNS or a trusted resolver)
3. Uncheck "Allow DNS server list to be overridden by DHCP/PPP on WAN" if you want to enforce your configured servers
4. Save and apply changes

---

## FIREWALL-006: IPv6 Disablement

| Field        | Value                                         |
| ------------ | --------------------------------------------- |
| **ID**       | FIREWALL-006                                  |
| **Category** | Network Configuration                         |
| **Severity** | Medium                                        |
| **Status**   | Implemented                                   |
| **Tags**     | `ipv6`, `attack-surface`, `firewall-controls` |

### Description

IPv6 should be disabled if the network does not require it. Leaving IPv6 enabled when unused expands the attack surface unnecessarily.

### Rationale

IPv6 introduces additional complexity and potential attack vectors (e.g., router advertisements, neighbor discovery, dual-stack vulnerabilities). If IPv6 is not actively used in your environment, disabling it reduces the attack surface and simplifies firewall rule management.

### What opnDossier Checks

Reads `System.IPv6Allow` from the CommonDevice. A finding is emitted when IPv6 **is enabled** (`IPv6Allow == true`), since the control recommends disabling it when not required.

> **Note:** This is an advisory check. If your environment requires IPv6, this finding can be accepted as a risk.

### Recommended Action

Disable IPv6 if not required:

1. Navigate to **System > Advanced > Networking**
2. Uncheck "Allow IPv6"
3. Save and apply changes
4. Review firewall rules for any IPv6-specific entries that can be removed

---

## FIREWALL-007: DNS Rebind Protection

| Field        | Value                                         |
| ------------ | --------------------------------------------- |
| **ID**       | FIREWALL-007                                  |
| **Category** | DNS Security                                  |
| **Severity** | Medium                                        |
| **Status**   | Implemented                                   |
| **Tags**     | `dns-rebind`, `security`, `firewall-controls` |

### Description

The Unbound DNS resolver should have a non-empty `private-address` list configured. This blocks DNS responses that resolve public domain names to private IP ranges, mitigating DNS rebinding attacks against internal services.

### Rationale

DNS rebinding attacks exploit browser same-origin policy by resolving a public domain to a private IP — for example, `attacker.com` resolving to `192.168.1.1` to target a router admin interface. Unbound's `private-address` directive blocks responses that fall inside user-declared private ranges, closing this attack vector. Environments using split-horizon DNS should scope private-address entries carefully, not disable the protection entirely.

### What opnDossier Checks

opnDossier parses the OPNsense Unbound MVC configuration from `<OPNsense><unboundplus><advanced>` and extracts the `<privateaddress>` field (CIDR ranges or bare IPs). Each entry is validated via `netip.ParsePrefix`/`netip.ParseAddr`; invalid entries are dropped with a conversion warning.

The check evaluates whether DNS rebind protection is configured:

- **Pass**: Unbound is enabled AND the `privateaddress` list contains at least one valid entry
- **Fail**: Unbound is enabled but `privateaddress` is empty or absent
- **Unknown**: Unbound is disabled (the install may be using DNSMasq, which has its own rebind-protection mechanism)

A finding is emitted when the check fails (`cr.Known && !cr.Result` in `internal/plugins/firewall/firewall.go`) — i.e. when Unbound is active but rebind protection is missing.

### Recommended Action

Enable DNS rebind protection:

1. Navigate to **Services > Unbound DNS > Advanced**
2. Populate the **Private networks** list with the CIDR ranges that should never appear in public DNS responses (commonly `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and any internal public allocations)
3. Save and apply changes
4. Verify the behaviour by resolving a test hostname that would rebind to a private address — Unbound should refuse to return it

---

## FIREWALL-008: HTTPS Web Management

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| **ID**       | FIREWALL-008                               |
| **Category** | Management Access                          |
| **Severity** | High                                       |
| **Status**   | Implemented                                |
| **Tags**     | `https`, `encryption`, `firewall-controls` |

### Description

The web management interface must use HTTPS to encrypt management traffic and prevent credential interception.

### Rationale

HTTP transmits credentials and configuration data in cleartext, making it vulnerable to interception on the management network. HTTPS provides encryption and server authentication, protecting against man-in-the-middle attacks on the management interface.

### What opnDossier Checks

Reads `System.WebGUI.Protocol` from the CommonDevice and performs a case-insensitive comparison against `"https"`. If the protocol is not HTTPS (e.g., HTTP or empty), a non-compliant finding is emitted.

### Recommended Action

Enable HTTPS for web management:

1. Navigate to **System > Advanced > Admin Access**
2. Set the protocol to HTTPS
3. Ensure a valid TLS certificate is configured (self-signed at minimum, CA-signed preferred)
4. Consider restricting the management interface to a dedicated management VLAN
5. Save and apply changes

---

## Severity Levels

| Level      | Meaning                                                                                                           |
| ---------- | ----------------------------------------------------------------------------------------------------------------- |
| **High**   | Critical security controls that must be implemented. Non-compliance creates significant risk.                     |
| **Medium** | Important security controls that should be implemented. Non-compliance creates moderate risk.                     |
| **Low**    | Recommended security controls for enhanced security posture. Non-compliance is acceptable in some environments.   |
| **Info**   | Informational observations about configuration. Not a security failure; provided for awareness and documentation. |

## Future Controls

The following controls are planned for future releases, organized by security domain. They are not implemented in the current audit engine. For the full cross-standard view (including SANS and STIG), see [Compliance Standards](compliance-standards.md).

### Management Plane Security

| Control ID   | Title                            | Severity | Description                                                             |
| ------------ | -------------------------------- | -------- | ----------------------------------------------------------------------- |
| FIREWALL-009 | Non-Default Web GUI Port         | Low      | Web GUI port changed from default 443 to reduce automated scanning risk |
| FIREWALL-010 | Management Interface Restriction | High     | Web GUI bound to specific interfaces, not all interfaces                |
| FIREWALL-011 | TLS Version Minimum              | High     | Web GUI TLS minimum version >= 1.2; no SSLv3/TLS 1.0/1.1                |
| FIREWALL-012 | Anti-Lockout Rule Awareness      | Low      | Anti-lockout rule status is explicitly configured and intentional       |
| FIREWALL-013 | Session Timeout                  | Medium   | Web GUI idle session timeout \<= 30 minutes                             |
| FIREWALL-014 | Console Menu Protection          | Medium   | Serial/console access password-protected (`DisableConsoleMenu`)         |
| FIREWALL-015 | Login Protection / Brute Force   | Medium   | Web GUI login protection with rate limiting on authentication failures  |

### Authentication and Access Control

| Control ID   | Title                      | Severity | Description                                                             |
| ------------ | -------------------------- | -------- | ----------------------------------------------------------------------- |
| FIREWALL-016 | Default Credential Reset   | Critical | Default admin password changed; known default username patterns flagged |
| FIREWALL-017 | Unique Administrator Accts | Medium   | Each admin has a unique named account; shared "admin" usage flagged     |
| FIREWALL-018 | Least Privilege Access     | Medium   | Users assigned minimum necessary privileges; `page-all` flagged         |
| FIREWALL-019 | Centralized Authentication | Medium   | LDAP/RADIUS configured for admin authentication                         |
| FIREWALL-020 | Disabled Unused Accounts   | Medium   | Unused or default accounts are disabled                                 |
| FIREWALL-021 | Group-Based Privileges     | Low      | Privileges assigned via groups rather than per-user                     |

### Firewall Rule Hygiene

| Control ID   | Title                          | Severity | Description                                                        |
| ------------ | ------------------------------ | -------- | ------------------------------------------------------------------ |
| FIREWALL-022 | No "Any-Any" Pass Rules        | High     | No rules with source=any, dest=any, port=any, protocol=any         |
| FIREWALL-023 | No "Any" Source on WAN Inbound | High     | Inbound WAN pass rules have specific source restrictions           |
| FIREWALL-024 | Specific Port Rules            | Medium   | Rules specify exact ports/services, not "any" port                 |
| FIREWALL-025 | Rule Documentation             | Medium   | Every firewall rule has a non-empty description                    |
| FIREWALL-026 | Disabled Rule Cleanup          | Info     | Flag excessive disabled rules (>10) indicating stale configuration |
| FIREWALL-027 | Protocol Specification         | Medium   | Pass rules specify protocol (TCP, UDP, ICMP), not "any"            |
| FIREWALL-028 | Pass Rule Logging              | Medium   | Critical pass rules have logging enabled for security monitoring   |

### Network Segmentation

| Control ID   | Title                        | Severity | Description                                                          |
| ------------ | ---------------------------- | -------- | -------------------------------------------------------------------- |
| FIREWALL-029 | Private Address Filtering    | Critical | `BlockPrivate` enabled on WAN to block RFC 1918 addresses            |
| FIREWALL-030 | Bogon Filtering on WAN       | Critical | `BlockBogons` enabled on WAN to block unallocated/reserved addresses |
| FIREWALL-031 | Unused Interface Disablement | Low      | Interfaces not in use are administratively disabled                  |
| FIREWALL-032 | VLAN Segmentation            | Medium   | VLANs configured for network segmentation where multiple zones exist |

### Anti-Spoofing and Traffic Validation

| Control ID   | Title                   | Severity | Description                                                            |
| ------------ | ----------------------- | -------- | ---------------------------------------------------------------------- |
| FIREWALL-033 | Source Route Rejection  | High     | IP source routing disabled via `net.inet.ip.sourceroute=0` in tunables |
| FIREWALL-034 | SYN Flood Protection    | Medium   | SYN cookies enabled via `net.inet.tcp.syncookies=1` in tunables        |
| FIREWALL-035 | Connection State Limits | Medium   | Maximum state table entries configured appropriately                   |

### Encryption and TLS

| Control ID   | Title                     | Severity | Description                                                                 |
| ------------ | ------------------------- | -------- | --------------------------------------------------------------------------- |
| FIREWALL-036 | Valid Web GUI Certificate | Medium   | Web GUI uses a valid (non-self-signed or internally-trusted CA) certificate |
| FIREWALL-037 | Certificate Expiration    | Medium   | No certificates expired or expiring within 30 days                          |
| FIREWALL-038 | Strong Key Lengths        | Medium   | RSA keys >= 2048 bits, EC keys >= 256 bits across all certificates          |

### Logging and Monitoring

| Control ID   | Title                       | Severity | Description                                                            |
| ------------ | --------------------------- | -------- | ---------------------------------------------------------------------- |
| FIREWALL-039 | Remote Syslog Configured    | High     | Logs forwarded to remote syslog/SIEM (`Syslog.RemoteServer` non-empty) |
| FIREWALL-040 | Authentication Event Log    | Medium   | Auth logging enabled (`Syslog.AuthLogging`)                            |
| FIREWALL-041 | Firewall Filter Logging     | Medium   | Firewall filter logging enabled (`Syslog.FilterLogging`)               |
| FIREWALL-042 | Log Retention Configuration | Info     | Local log rotation and size limits configured                          |

### Time Synchronization

| Control ID   | Title                  | Severity | Description                                                    |
| ------------ | ---------------------- | -------- | -------------------------------------------------------------- |
| FIREWALL-043 | NTP Configuration      | Medium   | At least 2 NTP time sources configured in `System.TimeServers` |
| FIREWALL-044 | Timezone Configuration | Info     | System timezone explicitly set (not empty/default)             |

### SNMP Security

| Control ID   | Title                        | Severity | Description                                            |
| ------------ | ---------------------------- | -------- | ------------------------------------------------------ |
| FIREWALL-045 | SNMP Disabled if Unused      | Medium   | SNMP service disabled when no operational need         |
| FIREWALL-046 | No Default Community Strings | High     | SNMP community strings changed from "public"/"private" |

### VPN Configuration

| Control ID   | Title                    | Severity | Description                                             |
| ------------ | ------------------------ | -------- | ------------------------------------------------------- |
| FIREWALL-047 | Strong VPN Encryption    | High     | AES-256-GCM or AES-128-GCM; no DES, 3DES, or Blowfish   |
| FIREWALL-048 | Strong VPN Integrity     | High     | SHA-256+ for integrity; no MD5 or SHA-1                 |
| FIREWALL-049 | Perfect Forward Secrecy  | High     | PFS enabled on all IPsec Phase 2 tunnels                |
| FIREWALL-050 | VPN Key Lifetime         | Medium   | Phase 1 lifetime \<= 28800s, Phase 2 lifetime \<= 3600s |
| FIREWALL-051 | No IKEv1 Aggressive Mode | High     | IKEv1 aggressive mode disabled; use main mode or IKEv2  |
| FIREWALL-052 | IKEv2 Preferred          | Medium   | IKEv2 used instead of IKEv1 where possible              |
| FIREWALL-053 | Dead Peer Detection      | Medium   | DPD enabled on IPsec Phase 1 tunnels                    |

### NAT Security

| Control ID   | Title                    | Severity | Description                                                |
| ------------ | ------------------------ | -------- | ---------------------------------------------------------- |
| FIREWALL-054 | Documented Port Forwards | Medium   | Every inbound NAT rule has a non-empty description         |
| FIREWALL-055 | Outbound NAT Control     | Medium   | Outbound NAT mode is "Hybrid" or "Manual", not "Automatic" |
| FIREWALL-056 | NAT Reflection Disabled  | Low      | NAT reflection disabled unless explicitly required         |

### Service Hardening

| Control ID   | Title                           | Severity | Description                                                         |
| ------------ | ------------------------------- | -------- | ------------------------------------------------------------------- |
| FIREWALL-057 | UPnP/NAT-PMP Disabled           | High     | UPnP and NAT-PMP disabled (auto port forwarding is a security risk) |
| FIREWALL-058 | DNSSEC Validation               | Medium   | Unbound DNS resolver has DNSSEC validation enabled                  |
| FIREWALL-059 | DNS Resolver Access Restriction | Medium   | DNS resolver serves only internal networks, not WAN-facing          |

### Change Management

| Control ID   | Title                    | Severity | Description                                                |
| ------------ | ------------------------ | -------- | ---------------------------------------------------------- |
| FIREWALL-060 | Config Revision Tracking | Info     | Configuration change history and revision tracking enabled |

### High Availability

| Control ID   | Title            | Severity | Description                                                 |
| ------------ | ---------------- | -------- | ----------------------------------------------------------- |
| FIREWALL-061 | HA Configuration | Medium   | CARP/pfsync HA peer and synchronization properly configured |

### Configuration Inventory

| Control ID   | Title                    | Severity | Description                                                                                   |
| ------------ | ------------------------ | -------- | --------------------------------------------------------------------------------------------- |
| FIREWALL-062 | DHCP Scope Inventory     | Info     | Reports configured DHCP scopes, covering both ISC DHCP (legacy) and Kea DHCP4 (modern) scopes |
| FIREWALL-063 | Active Interface Summary | Info     | Reports enabled interfaces and their types                                                    |

**Note:** Configuration inventory controls use `Type: "inventory"` and are excluded from compliance evaluation. They are rendered in a separate "Configuration Notes" section of audit reports and do not affect pass/fail compliance status.

## References

- General network security best practices
- Industry-standard firewall security guidelines
- OPNsense documentation and security recommendations
- Network infrastructure security frameworks
