# OPNsense Configuration Summary
## System Information
- **Hostname**: comprehensive-firewall
- **Domain**: security.local
- **Platform**: OPNsense 24.1.2
- **Generated On**: 2026-02-25T23:02:10-05:00
- **Parsed By**: opnDossier vdev
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
**Hostname**: comprehensive-firewall
  
**Domain**: security.local
  
**Optimization**: aggressive
**Timezone**: America/New_York
**Language**: en_US
### Web GUI Configuration
**Protocol**: https
### System Settings
**DNS Allow Override**: ✓
  
**Next UID**: 0
  
**Next GID**: 0
  
**Time Servers**: time.nist.gov, pool.ntp.org
**DNS Server**: 1.1.1.1, 8.8.8.8
### Hardware Offloading
**Disable NAT Reflection**: ✗
  
**Use Virtual Terminal**: ✗
  
**Disable Console Menu**: ✗
  
**Disable VLAN HW Filter**: ✗
  
**Disable Checksum Offloading**: ✗
  
**Disable Segmentation Offloading**: ✗
  
**Disable Large Receive Offloading**: ✗
  
**IPv6 Allow**: ✓
  
### Power Management
**Powerd AC Mode**: 
  
**Powerd Battery Mode**: 
  
**Powerd Normal Mode**: 
  
### System Features
**PF Share Forward**: ✗
  
**LB Use Sticky**: ✗
  
**RRD Backup**: ✗
  
**Netflow Backup**: ✗
### Bogons Configuration
**Interval**: weekly
### SSH Configuration
**Group**: wheel
### Firmware Information
**Version**: 24.1.2
### System Users
| Name | Description | Group | Scope |
|---------|---------|---------|---------|
| admin | System Administrator | wheel | system |
| operator | Network Operator | admins | local |
| auditor | Security Auditor | readonly | local |

### System Groups
| Name | Description | Scope |
|---------|---------|---------|
| wheel | System Administrators | system |
| admins | Network Administrators | local |
| readonly | Read-only Users | local |

## Network Configuration
### Interfaces
| Name | Description | IP Address | CIDR | Enabled |
|---------|---------|---------|---------|---------|
| `wan` | `WAN (Internet)` | `203.0.113.10` | /28 | ✓ |
| `lan` | `LAN (Internal)` | `192.168.100.1` | /24 | ✓ |
| `dmz` | `DMZ (Servers)` | `10.0.100.1` | /24 | ✓ |
| `guest` | `Guest Network` | `172.16.1.1` | /24 | ✓ |

### Wan Interface
**Physical Interface**: igb0
  
**Enabled**: ✓
  
**IPv4 Address**: 203.0.113.10
  
**IPv4 Subnet**: 28
  
**Gateway**: 203.0.113.1
  
**MTU**: 1500
  
**Block Private Networks**: ✓
  
**Block Bogon Networks**: ✓
### Lan Interface
**Physical Interface**: igb1
  
**Enabled**: ✓
  
**IPv4 Address**: 192.168.100.1
  
**IPv4 Subnet**: 24
  
**MTU**: 1500
  
**Block Private Networks**: ✗
  
**Block Bogon Networks**: ✗
### Dmz Interface
**Physical Interface**: igb2
  
**Enabled**: ✓
  
**IPv4 Address**: 10.0.100.1
  
**IPv4 Subnet**: 24
  
**MTU**: 1500
  
**Block Private Networks**: ✓
  
**Block Bogon Networks**: ✓
### Guest Interface
**Physical Interface**: igb3
  
**Enabled**: ✓
  
**IPv4 Address**: 172.16.1.1
  
**IPv4 Subnet**: 24
  
**MTU**: 1500
  
**Block Private Networks**: ✓
  
**Block Bogon Networks**: ✓
## Security Configuration
### NAT Configuration
#### NAT Summary
**NAT Mode**: automatic
  
**NAT Reflection**: ✗
  
**Port Forward State Sharing**: ✗
  
**Outbound Rules**: 1
  
**Inbound Rules**: 2
> [!WARNING]  
> NAT reflection is enabled, which may allow internal clients to access internal services via external IP addresses. Consider disabling if not needed.
#### Outbound NAT (Source Translation)
| # | Direction | Interface | Source | Destination | Target | Protocol | Description | Status |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| 1 | ⬆️ Outbound | [wan](#wan-interface) | lan | any | `wan` | any | Auto NAT for LAN | **Active** |

#### Inbound NAT (Port Forwarding)
| # | Direction | Interface | External Port | Target IP | Target Port | Protocol | Description | Priority | Status |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| 1 | ⬇️ Inbound | [wan](#wan-interface) |  | `10.0.100.10` |  | tcp | HTTP to Web Server | 0 | **Active** |
| 2 | ⬇️ Inbound | [wan](#wan-interface) |  | `10.0.100.10` |  | tcp | HTTPS to Web Server | 0 | **Active** |

> [!WARNING]  
> Inbound NAT rules (port forwarding) increase the attack surface by exposing internal services to external networks. Ensure these rules are necessary and properly secured.
### Firewall Rules
| # | Interface | Action | IP Ver | Proto | Source | Destination | Target | Source Port | Dest Port | Enabled | Description |
|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|
| 1 | [wan](#wan-interface) | block | inet | any | any | any |  |  |  | ✓ | Default deny all |
| 2 | [wan](#wan-interface) | pass | inet | tcp | any | wan |  |  | 80,443 | ✓ | Allow HTTP/HTTPS |
| 3 | [lan](#lan-interface) | pass | inet | any | lan | any |  |  |  | ✓ | Allow LAN to any |
| 4 | [dmz](#dmz-interface) | pass | inet | tcp | dmz | !lan,!dmz,!guest |  |  |  | ✓ | Allow DMZ to Internet |
| 5 | [guest](#guest-interface) | block | inet | any | guest | lan,dmz |  |  |  | ✓ | Block Guest to LAN |
| 6 | [guest](#guest-interface) | pass | inet | tcp | guest | !lan,!dmz,!guest |  |  |  | ✓ | Allow Guest Internet |

## Service Configuration
### DHCP Server
| Interface | Enabled | Gateway | Range Start | Range End | DNS | WINS | NTP |
|---------|---------|---------|---------|---------|---------|---------|---------|
| lan | ✓ | 192.168.100.1 | 192.168.100.50 | 192.168.100.199 | 192.168.100.1 |  |  |
| guest | ✓ | 172.16.1.1 | 172.16.1.50 | 172.16.1.199 | 1.1.1.1 |  |  |

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
| net.inet.ip.forwarding | 1 | Enable IP forwarding for routing |
| net.inet6.ip6.forwarding | 1 | Enable IPv6 forwarding |
| net.inet.tcp.blackhole | 2 | Drop TCP packets to closed ports |
| net.inet.udp.blackhole | 1 | Drop UDP packets to closed ports |
| security.bsd.see\_other\_uids | 0 | Hide processes from other users |
| security.bsd.see\_other\_gids | 0 | Hide processes from other groups |
| kern.securelevel | 1 | Enable secure level 1 |
| net.inet.tcp.syncookies | 1 | Enable SYN cookies for DDoS protection |
| net.inet.icmp.icmplim | 50 | Limit ICMP response rate |
| net.inet.tcp.always\_keepalive | 1 | Enable TCP keepalive |
