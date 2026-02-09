# OPNsense Configuration Summary
## System Information
- **Hostname**: minimal-host
- **Domain**: minimal.local
- **Platform**: OPNsense 23.1.1
- **Generated On**: 2026-02-06T00:25:28-05:00
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
**Hostname**: minimal-host
  
**Domain**: minimal.local
  
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
### Firmware Information
**Version**: 23.1.1
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

## Service Configuration
### DHCP Server
| Interface | Enabled | Gateway | Range Start | Range End | DNS | WINS | NTP | DDNS Algorithm |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| - | - | - | - | - | - | - | - | No DHCP scopes configured |

### DNS Resolver (Unbound)
### SNMP
### NTP