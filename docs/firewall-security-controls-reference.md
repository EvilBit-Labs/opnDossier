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
| FIREWALL-003 | Message of the Day               | System Configuration  | Low      | Unknown     |
| FIREWALL-004 | Hostname Configuration           | System Configuration  | Low      | Implemented |
| FIREWALL-005 | DNS Server Configuration         | Network Configuration | Medium   | Implemented |
| FIREWALL-006 | IPv6 Disablement                 | Network Configuration | Medium   | Implemented |
| FIREWALL-007 | DNS Rebind Check                 | DNS Security          | Low      | Unknown     |
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
| **Severity** | Low                                         |
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

## FIREWALL-007: DNS Rebind Check

| Field        | Value                                         |
| ------------ | --------------------------------------------- |
| **ID**       | FIREWALL-007                                  |
| **Category** | DNS Security                                  |
| **Severity** | Low                                           |
| **Status**   | Unknown (model gap)                           |
| **Tags**     | `dns-rebind`, `security`, `firewall-controls` |

### Description

The DNS rebind check should be disabled in environments where it interferes with legitimate DNS resolution. This control checks whether the DNS rebinding protection setting is configured appropriately.

### Rationale

DNS rebind checks can interfere with legitimate DNS resolution in environments that use split-horizon DNS or internal DNS names that resolve to private addresses from external resolvers. The appropriate setting depends on the network architecture.

### What opnDossier Checks

**Always returns Unknown.** The CommonDevice model does not yet expose the DNS rebind check setting. This is tracked in [#296](https://github.com/EvilBit-Labs/opnDossier/issues/296). Once the field is added, the check will evaluate whether the setting matches the expected configuration.

### Recommended Action

Review DNS rebind check settings:

1. Navigate to **System > Advanced > Administration** (or **System > Advanced** depending on OPNsense version)
2. Evaluate whether the DNS rebind check should be enabled or disabled based on your DNS architecture
3. If using split-horizon DNS or internal names that resolve to private IPs, consider disabling the check

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

| Level      | Meaning                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| **High**   | Critical security controls that must be implemented. Non-compliance creates significant risk.                   |
| **Medium** | Important security controls that should be implemented. Non-compliance creates moderate risk.                   |
| **Low**    | Recommended security controls for enhanced security posture. Non-compliance is acceptable in some environments. |

## Future Controls

The following controls are under consideration for future releases. They are not implemented in the current audit engine.

### System and User Management

| Control ID   | Title                      | Category          | Notes                                |
| ------------ | -------------------------- | ----------------- | ------------------------------------ |
| FIREWALL-009 | HA Configuration           | High Availability | Validate HA peer sync settings       |
| FIREWALL-010 | Session Timeout            | User Management   | Verify timeout is 10 min or less     |
| FIREWALL-011 | Central Authentication     | Authentication    | Check LDAP/RADIUS configuration      |
| FIREWALL-012 | Console Menu Protection    | Access Control    | Verify console password protection   |
| FIREWALL-013 | Default Account Management | User Management   | Check default account security       |
| FIREWALL-014 | Local Account Status       | User Management   | Verify unnecessary accounts disabled |

### Security Policy

| Control ID   | Title                      | Category        | Notes                             |
| ------------ | -------------------------- | --------------- | --------------------------------- |
| FIREWALL-015 | Login Protection Threshold | Security Policy | Verify threshold is 30 or less    |
| FIREWALL-016 | Access Block Time          | Security Policy | Verify block time is 300s or more |
| FIREWALL-017 | Default Password Change    | Security Policy | Detect default credentials        |

### Firewall Rules

| Control ID   | Title                          | Category       | Notes                      |
| ------------ | ------------------------------ | -------------- | -------------------------- |
| FIREWALL-018 | Destination Field Restrictions | Firewall Rules | Flag "Any" in destination  |
| FIREWALL-019 | Source Field Restrictions      | Firewall Rules | Flag "Any" in source       |
| FIREWALL-020 | Service Field Restrictions     | Firewall Rules | Flag "Any" in service/port |

### Service Configuration

Additional service-level controls under consideration:

- SNMP trap receiver configuration and enablement
- NTP time zone and server configuration
- DNSSEC enablement on DNS resolver
- VPN authentication and certificate management
- OpenVPN TLS and cipher configuration
- Syslog remote logging configuration

## References

- General network security best practices
- Industry-standard firewall security guidelines
- OPNsense documentation and security recommendations
- Network infrastructure security frameworks
