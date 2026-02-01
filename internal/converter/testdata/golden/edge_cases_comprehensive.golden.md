# OPNsense Configuration Summary
## System Information
- **Hostname**: edge-case-test!@#$%^&*()
- **Domain**: domain*with*asterisks
- **Platform**: OPNsense 
- **Generated On**: [TIMESTAMP]
- **Parsed By**: opnDossier v[VERSION]
## Table of Contents
- [System Configuration](#system-configuration)
- [Interfaces](#interfaces)
- [VLANs](#vlan-configuration)
- [Static Routes](#static-routes)
- [Firewall Rules](#firewall-rules)
- [NAT Configuration](#nat-configuration)
- [IPsec VPN](#ipsec-vpn-configuration)
- [OpenVPN](#openvpn-configuration)
- [High Availability](#high-availability--carp)
- [DHCP Services](#dhcp-services)
- [DNS Resolver](#dns-resolver)
- [System Users](#system-users)
- [System Groups](#system-groups)
- [Services & Daemons](#services--daemons)
- [System Tunables](#system-tunables)
## System Configuration
### Basic Information
**Hostname**: edge-case-test!@#$%^&*()
**Domain**: domain*with*asterisks
**Timezone**: GMT+12:45
**Language**: invalid_locale
### System Settings
**DNS Allow Override**: ✗
**Next UID**: 0
**Next GID**: 0
### Hardware Offloading
**Disable NAT Reflection**: ✗
**Use Virtual Terminal**: ✗
**Disable Console Menu**: ✓
**Disable VLAN HW Filter**: ✗
**Disable Checksum Offloading**: ✗
**Disable Segmentation Offloading**: ✗
**Disable Large Receive Offloading**: ✗
**IPv6 Allow**: ✗
### Power Management
**Powerd AC Mode**: 
**Powerd Battery Mode**: 
**Powerd Normal Mode**: 
### System Features
**PF Share Forward**: ✗
**LB Use Sticky**: ✗
**RRD Backup**: unset
**Netflow Backup**: unset
### System Tunables
| Tunable | Value | Description |
|---------|---------|---------|
|  |  |  |
| invalid.tunable.with.pipes\|and\|newlines | value with newlines |  |
| tunable\*with\*asterisks | value\_with\_underscores |  |
| tunable\[with\]brackets | value\<with\>angles |  |
| tunable\`with\`backticks | value\\with\\backslashes |  |

## Network Configuration
### Interfaces
| Name | Description | IP Address | CIDR | Enabled |
|---------|---------|---------|---------|---------|

### VLAN Configuration
| VLAN Interface | Physical Interface | VLAN Tag | Description | Created | Updated |
|---------|---------|---------|---------|---------|---------|
| - | - | - | No VLANs configured | - | - |

### Static Routes
| Destination Network | Gateway | Description | Status | Created | Updated |
|---------|---------|---------|---------|---------|---------|
| - | - | No static routes configured | - | - | - |

## Security Configuration
### NAT Configuration
#### Outbound NAT (Source Translation)
| # | Direction | Interface | Source | Destination | Target | Protocol | Description | Status |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| - | - | - | - | - | - | - | No outbound NAT rules configured | - |

#### Inbound NAT (Port Forwarding)
| # | Direction | Interface | External Port | Target IP | Target Port | Protocol | Description | Priority | Status |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| - | - | - | - | - | - | - | No inbound NAT rules configured | - | - |

### Firewall Rules
| # | Interface | Action | IP Ver | Proto | Source | Destination | Target | Source Port | Enabled | Description |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| 1 |  |  |  |  | any | any |  |  | ✓ |  |
| 2 |  | unknown | invalid | unknown | invalid-network | another|invalid|network |  |  | ✓ | Rule with \| pipes \| and   newlines 	 tabs |
| 3 | [wan](#wan-interface) | pass | inet | tcp | source[with]brackets | dest<with>angles |  |  | ✓ | Rule with \*bold\* and \_italic\_ text |
| 4 | [lan](#lan-interface) | block | inet | udp | source\with\backslashes | dest`with`backticks |  |  | ✓ | Rule with \`code\` and \\backslash\\ characters |

### IPsec VPN Configuration
*No IPsec configuration present*
### OpenVPN Configuration
#### OpenVPN Servers
*No OpenVPN servers configured*
#### OpenVPN Clients
*No OpenVPN clients configured*
#### Client-Specific Overrides
*No client-specific overrides configured*
### High Availability & CARP
#### Virtual IP Addresses (CARP)
*No virtual IPs configured*
#### HA Synchronization Settings
*No HA synchronization configured*
## Service Configuration
### DHCP Server
### DNS Resolver (Unbound)
### SNMP
### NTP