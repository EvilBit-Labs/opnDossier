# Security Scoring Methodology

## Overview

opnDossier's security assessment provides a standardized approach to evaluating OPNsense configuration security posture. The scoring system starts at 100 and deducts points for known misconfigurations, exposed management interfaces, and missing hardening measures. The result is a single number that gives you a quick read on how well a configuration follows security best practices.

This score is not a vulnerability scan -- it evaluates the configuration itself, not what is running on the network. A score of 100 means the configuration follows all the hardening checks opnDossier knows about, not that the network is invulnerable.

All scoring operates completely offline with no external dependencies, suitable for airgapped environments.

## Risk Label Mapping

The security assessment uses consistent risk labels across all output formats:

| Severity                 | Label         | Description                    |
| ------------------------ | ------------- | ------------------------------ |
| `critical`               | Critical Risk | Immediate attention required   |
| `high`                   | High Risk     | High priority security concern |
| `medium`                 | Medium Risk   | Moderate security concern      |
| `low`                    | Low Risk      | Low priority security issue    |
| `info` / `informational` | Informational | Informational finding          |
| Unknown/Invalid          | Unknown Risk  | Unrecognized severity level    |

## Service Risk Assessment

When opnDossier encounters services exposed through firewall rules or NAT port forwarding, it categorizes them by the inherent risk of the protocol. This helps you spot rules that expose dangerous services -- even if the rule itself looks normal.

### Critical Risk

- **Telnet** -- Transmits credentials and session data in cleartext. There is no legitimate reason to expose Telnet on a modern network. If you see this in a config, it is almost certainly a legacy oversight or a misconfiguration.

### High Risk

- **FTP** -- Transmits credentials in cleartext and uses unpredictable data ports that complicate firewall rules. Use SFTP or SCP instead.
- **VNC** -- Many VNC implementations have weak or no authentication by default. If remote desktop access is needed, tunnel it through a VPN or use a more secure alternative.

### Medium Risk

- **RDP** -- Supports encryption and network-level authentication, but is a frequent target for brute-force attacks and has had critical vulnerabilities (e.g., BlueKeep). Should never be exposed directly to the internet -- always place behind a VPN or jump host.

### Low Risk

- **SSH** -- Encrypted and well-understood, but still an attack surface. Key- based authentication and rate limiting are recommended when exposed.

### Informational

- **HTTPS** -- Encrypted web services. Generally expected to be exposed.
- **Unknown/Custom** -- Services not in the risk database are noted but not penalized.

## Security Scoring Algorithm

The security score provides a 0-100 rating based on configuration analysis. Every configuration starts at 100 points, and points are deducted for each issue found.

### Penalty System

| Security Issue           | Penalty  | Why it matters                                                                                                                                                                                                                           |
| ------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No Firewall Rules        | -20      | A firewall with no rules is either passing all traffic or blocking all traffic -- neither is a deliberate security posture. This usually indicates a misconfiguration or an incomplete backup.                                           |
| Management on WAN        | -30      | Exposing management interfaces (SSH, HTTP, HTTPS) to the internet is the single most common way firewalls get compromised. Attackers scan for these ports continuously. Even with strong credentials, the attack surface is unnecessary. |
| Insecure Sysctl Settings | -5 each  | Kernel tunables control low-level network behavior. Misconfigured tunables can allow IP spoofing, enable packet forwarding when it should be disabled, or make the firewall respond to port scans.                                       |
| Default User Accounts    | -15 each | Default accounts (`admin`, `root`, `user`) with unchanged names are predictable targets for brute-force attacks. Renaming or removing default accounts is a basic hardening step.                                                        |

### Interpreting the Score

| Score Range | General Assessment                                        |
| ----------- | --------------------------------------------------------- |
| 90-100      | Well-hardened configuration with no major issues          |
| 70-89       | Acceptable with some areas for improvement                |
| 50-69       | Multiple security concerns that should be addressed       |
| Below 50    | Significant hardening needed -- review findings carefully |

### Sysctl Security Checks

The following kernel tunables are evaluated. These are set under **System > Settings > Tunables** in OPNsense.

| Tunable                    | Expected | Why                                                                                                                                                                                                                                                                                     |
| -------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `net.inet.ip.forwarding`   | `0`      | When enabled, the firewall forwards packets between interfaces at the kernel level, bypassing firewall rules. Should only be `1` if the device is explicitly configured as a router -- and on OPNsense, the firewall's own routing handles this, so the sysctl should typically be `0`. |
| `net.inet6.ip6.forwarding` | `0`      | Same as above, but for IPv6. If you are not using IPv6 routing, this should be disabled.                                                                                                                                                                                                |
| `net.inet.tcp.blackhole`   | `2`      | When set to `2`, the kernel silently drops TCP packets to closed ports instead of responding with a RST. This makes port scanning slower and less reliable, reducing reconnaissance effectiveness.                                                                                      |
| `net.inet.udp.blackhole`   | `1`      | When set to `1`, the kernel silently drops UDP packets to closed ports instead of responding with an ICMP port unreachable message. Same benefit as the TCP blackhole -- reduces information leakage to scanners.                                                                       |

### Management Port Detection

The following ports are flagged when exposed on the WAN interface with an inbound rule. These are management ports -- they provide administrative access to the firewall itself or to systems behind it, and should not be reachable from the internet.

| Port | Service  | Why it should not be on WAN                                                                                                             |
| ---- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 22   | SSH      | Direct shell access to the firewall. Use VPN + internal SSH instead.                                                                    |
| 80   | HTTP     | Unencrypted WebGUI access. Credentials are transmitted in cleartext.                                                                    |
| 443  | HTTPS    | Encrypted WebGUI access is better than HTTP, but still exposes the admin interface to brute-force attacks and zero-day vulnerabilities. |
| 8080 | Alt HTTP | Commonly used as an alternative WebGUI or proxy port. Same risks as port 80.                                                            |

## Integration with Reports

The security score and findings appear differently depending on the audit mode used with the [convert command](commands/convert.md#audit-modes):

### Standard Reports

A balanced overview of configuration security. Includes the numeric score, a summary of deductions, and general recommendations. Best for routine documentation and periodic review.

### Blue Team Reports

Focused on defensive operations. Findings are grouped by severity with compliance mappings (STIG, SANS, firewall controls) and specific remediation steps. Best for security teams working to harden a configuration.

### Red Team Reports

Focused on what an attacker would target. Highlights exposed management interfaces, weak NAT rules, and potential pivot points. The score is less prominent -- the emphasis is on attack surface discovery.

---

For how to generate audit reports, see the [convert command](commands/convert.md#audit-modes).
