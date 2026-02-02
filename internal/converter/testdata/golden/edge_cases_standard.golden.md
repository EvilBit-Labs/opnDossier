# OPNsense Configuration Summary
## System Information
- **Hostname**: edge-case-test!@#$%^&*()
- **Domain**: domain*with*asterisks
- **Platform**: OPNsense 
- **Generated On**: 2026-02-01T21:26:06-05:00
- **Parsed By**: opnDossier v1.0.0
## Table of Contents
- [System Configuration](#system-configuration)
- [Interfaces](#interfaces)
- [Firewall Rules](#firewall-rules)
- [NAT Configuration](#nat-configuration)
- [DHCP Services](#dhcp-services)
- [DNS Resolver](#dns-resolver)
- [System Users](#system-users)
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
## Network Configuration
### Interfaces
| Name | Description | IP Address | CIDR | Enabled |
|---------|---------|---------|---------|---------|

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

## Service Configuration
### DHCP Server
### DNS Resolver (Unbound)
### SNMP
### NTP
## System Tunables
| Tunable | Value | Description |
|---------|---------|---------|
|  |  |  |
| invalid.tunable.with.pipes\|and\|newlines | value with newlines |  |
| tunable\*with\*asterisks | value\_with\_underscores |  |
| tunable\[with\]brackets | value\<with\>angles |  |
| tunable\`with\`backticks | value\\with\\backslashes |  |
