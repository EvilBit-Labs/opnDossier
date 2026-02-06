# OPNsense Configuration Summary
## System Information
- **Hostname**: comprehensive-firewall
- **Domain**: security.local
- **Platform**: OPNsense 24.1.2
- **Generated On**: 2026-02-06T00:25:28-05:00
- **Parsed By**: opnDossier v1.0.0
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
**Hostname**: comprehensive-firewall
  
**Domain**: security.local
  
**Optimization**: aggressive
**Timezone**: America/New_York
**Language**: en_US
### Web GUI Configuration
**Protocol**: https
### System Settings
**DNS Allow Override**: ✓
  
**Next UID**: 2000
  
**Next GID**: 2000
  
**Time Servers**: time.nist.gov pool.ntp.org
**DNS Server**: 1.1.1.1 8.8.8.8
### Hardware Offloading
**Disable NAT Reflection**: ✓
  
**Use Virtual Terminal**: ✓
  
**Disable Console Menu**: ✓
  
**Disable VLAN HW Filter**: ✗
  
**Disable Checksum Offloading**: ✗
  
**Disable Segmentation Offloading**: ✗
  
**Disable Large Receive Offloading**: ✗
  
**IPv6 Allow**: ✓
  
### Power Management
**Powerd AC Mode**: Maximum Performance (maximum)
  
**Powerd Battery Mode**: Adaptive (adaptive)
  
**Powerd Normal Mode**: Maximum Performance (maximum)
  
### System Features
**PF Share Forward**: ✓
  
**LB Use Sticky**: ✓
  
**RRD Backup**: ✓
  
**Netflow Backup**: ✓
### Bogons Configuration
**Interval**: weekly
### SSH Configuration
**Group**: wheel
### Firmware Information
**Version**: 24.1.2
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
#### NAT Summary
**NAT Mode**: automatic
  
**NAT Reflection**: ✗
  
**Port Forward State Sharing**: ✓
  
**Outbound Rules**: 0
  
**Inbound Rules**: 0
> [!WARNING]  
> NAT reflection is enabled, which may allow internal clients to access internal services via external IP addresses. Consider disabling if not needed.
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
| 1 | [wan](#wan-interface) | block | inet | any | any | any |  |  | ✓ | Default deny all |
| 2 | [wan](#wan-interface) | pass | inet | tcp | any | wan |  |  | ✓ | Allow HTTP/HTTPS |
| 3 | [lan](#lan-interface) | pass | inet | any | lan | any |  |  | ✓ | Allow LAN to any |
| 4 | [dmz](#dmz-interface) | pass | inet | tcp | dmz | !lan,!dmz,!guest |  |  | ✓ | Allow DMZ to Internet |
| 5 | [guest](#guest-interface) | block | inet | any | guest | lan,dmz |  |  | ✓ | Block Guest to LAN |
| 6 | [guest](#guest-interface) | pass | inet | tcp | guest | !lan,!dmz,!guest |  | 80,443,53 | ✓ | Allow Guest Internet |

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
| Interface | Enabled | Gateway | Range Start | Range End | DNS | WINS | NTP | DDNS Algorithm |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| - | - | - | - | - | - | - | - | No DHCP scopes configured |

### DNS Resolver (Unbound)
**Enabled**: ✓
  
### SNMP
**System Location**: Primary Data Center - Rack 42
  
**System Contact**: security-team@company.com
  
**Read-Only Community**: public_readonly_v3
  
### NTP
**Preferred Server**: time.nist.gov
  
### Load Balancer Monitors
| Name | Type | Description |
|---------|---------|---------|
| http-health | http | HTTP Health Check |
| tcp-connect | tcp | TCP Connection Check |
| icmp-ping | icmp | ICMP Ping Check |

## System Tunables
| Tunable | Value | Description |
|---------|---------|---------|
| net.inet.ip.forwarding | 1 |  |
| net.inet6.ip6.forwarding | 1 |  |
| net.inet.tcp.blackhole | 2 |  |
| net.inet.udp.blackhole | 1 |  |
| security.bsd.see\_other\_uids | 0 |  |
| security.bsd.see\_other\_gids | 0 |  |
| kern.securelevel | 1 |  |
| net.inet.tcp.syncookies | 1 |  |
| net.inet.icmp.icmplim | 50 |  |
| net.inet.tcp.always\_keepalive | 1 |  |
