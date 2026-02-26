# OPNsense Configuration Summary
## System Information
- **Hostname**: edge-case-test!@#$%^&*()
- **Domain**: domain*with*asterisks
- **Platform**: OPNsense 
- **Generated On**: 2026-02-25T23:02:10-05:00
- **Parsed By**: opnDossier vdev
## Table of Contents
- [System Configuration](#system-configuration)
- [Interfaces](#interfaces)
- [VLANs](#vlan-configuration)
- [Static Routes](#static-routes)
- [Firewall Rules](#firewall-rules)
- [NAT Configuration](#nat-configuration)
- [Intrusion Detection System](#intrusion-detection-system-idssuricata)
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
  
**Disable Console Menu**: ✗
  
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
  
**RRD Backup**: ✗
  
**Netflow Backup**: ✗
### System Users
| Name | Description | Group | Scope |
|---------|---------|---------|---------|
|  | User with empty name |  |  |
| user-with-special-chars!@# | User with newlines and	tabs | group\|with\|pipes | unknown |
| user\_with\_underscores | User with \*bold\* and \_italic\_ text | group\[with\]brackets | scope\<with\>angles |
| user\`with\`backticks | User with \`code\` and \\backslash\\ characters | group\\with\\backslashes | scope\|with\|pipes |

### System Groups
| Name | Description | Scope |
|---------|---------|---------|
|  |  |  |
| group\*with\*asterisks | Group with \_underscores\_ and \`backticks\` | scope\[with\]brackets |

## Network Configuration
### Interfaces
| Name | Description | IP Address | CIDR | Enabled |
|---------|---------|---------|---------|---------|
| `` | `` | `` |  | ✗ |
| `invalid-interface` | `Interface with \| pipes \| and   newlines` | `999.999.999.999` | /999 | ✗ |
| `interface*with*chars` | `Interface with \*asterisks\* and \_underscores\_` | `192.168.1.100` | /24 | ✓ |
| `interface`with`backticks` | `Interface with \`code\` and \\backslashes\\` | `192.168.2.100` | /24 | ✓ |

### Unnamed Interface
**Enabled**: ✗
  
**Block Private Networks**: ✗
  
**Block Bogon Networks**: ✗
### Invalid-interface Interface
**Physical Interface**: nonexistent0
  
**Enabled**: ✗
  
**IPv4 Address**: 999.999.999.999
  
**IPv4 Subnet**: 999
  
**Block Private Networks**: ✗
  
**Block Bogon Networks**: ✗
### Interface*with*chars Interface
**Physical Interface**: eth0
  
**Enabled**: ✓
  
**IPv4 Address**: 192.168.1.100
  
**IPv4 Subnet**: 24
  
**Block Private Networks**: ✗
  
**Block Bogon Networks**: ✗
### Interface`with`backticks Interface
**Physical Interface**: eth1
  
**Enabled**: ✓
  
**IPv4 Address**: 192.168.2.100
  
**IPv4 Subnet**: 24
  
**Block Private Networks**: ✗
  
**Block Bogon Networks**: ✗
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
| # | Interface | Action | IP Ver | Proto | Source | Destination | Target | Source Port | Dest Port | Enabled | Description |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| 1 |  |  |  |  | any | any |  |  |  | ✓ |  |
| 2 |  | unknown | invalid | unknown | invalid-network | another|invalid|network |  |  |  | ✓ | Rule with \| pipes \| and   newlines 	 tabs |
| 3 | [wan](#wan-interface) | pass | inet | tcp | source[with]brackets | dest<with>angles |  |  |  | ✓ | Rule with \*bold\* and \_italic\_ text |
| 4 | [lan](#lan-interface) | block | inet | udp | source\with\backslashes | dest`with`backticks |  |  |  | ✓ | Rule with \`code\` and \\backslash\\ characters |

### IPsec VPN Configuration
*No IPsec configuration present*
### OpenVPN Configuration
#### OpenVPN Servers
*No OpenVPN servers configured*
#### OpenVPN Clients
*No OpenVPN clients configured*
### High Availability & CARP
#### Virtual IP Addresses (CARP)
*No virtual IPs configured*
#### HA Synchronization Settings
*No HA synchronization configured*
## Service Configuration
### DHCP Server
| Interface | Enabled | Gateway | Range Start | Range End | DNS | WINS | NTP |
|---------|---------|---------|---------|---------|---------|---------|---------|
| - | - | - | - | - | - | - | No DHCP scopes configured |

### DNS Resolver (Unbound)
### SNMP
### NTP
## System Tunables
| Tunable | Value | Description |
|---------|---------|---------|
|  |  |  |
| invalid.tunable.with.pipes\|and\|newlines | value with newlines | Description with \| pipes \| and   newlines 	 tabs |
| tunable\*with\*asterisks | value\_with\_underscores | Description with \*bold\* and \_italic\_ text |
| tunable\[with\]brackets | value\<with\>angles | Description with \[brackets\] and \<angles\> |
| tunable\`with\`backticks | value\\with\\backslashes | Description with \`code\` and \\backslash\\ characters |
