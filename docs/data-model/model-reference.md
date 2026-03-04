# Model Reference

> **Auto-generated documentation** - Do not edit manually. Regenerate with `just generate-docs`.

This document provides a complete reference of all data fields available in the opnDossier **CommonDevice** export model. This is the model used for JSON and YAML exports. It normalizes the raw OPNsense XML schema into clean, platform-agnostic types.

## Table of Contents

- [CommonDevice (Root)](#commondevice-root)
- [System Configuration](#system-configuration)
- [Network Interfaces](#network-interfaces)
- [Firewall and Security](#firewall-and-security)
- [NAT Configuration](#nat-configuration)
- [Services](#services)
- [VPN Configuration](#vpn-configuration)
- [Routing](#routing)
- [Users and Groups](#users-and-groups)
- [Certificates](#certificates)

---

## CommonDevice (Root)

The root export object representing a normalized device configuration.

| Field              | Type                     | JSON Key           | Description                                    |
| ------------------ | ------------------------ | ------------------ | ---------------------------------------------- |
| `DeviceType`       | `string`                 | `device_type`      | Platform identifier (e.g., "opnsense")         |
| `Version`          | `string`                 | `version`          | Firmware/configuration version                 |
| `Theme`            | `string`                 | `theme`            | Web GUI theme name                             |
| `System`           | `System`                 | `system`           | System-level settings                          |
| `Interfaces`       | `[]Interface`            | `interfaces`       | Network interface configurations (flat array)  |
| `VLANs`            | `[]VLAN`                 | `vlans`            | VLAN configurations                            |
| `Bridges`          | `[]Bridge`               | `bridges`          | Network bridge configurations                  |
| `PPPs`             | `[]PPP`                  | `ppps`             | PPP connection configurations                  |
| `GIFs`             | `[]GIF`                  | `gifs`             | GIF tunnel configurations                      |
| `GREs`             | `[]GRE`                  | `gres`             | GRE tunnel configurations                      |
| `LAGGs`            | `[]LAGG`                 | `laggs`            | Link aggregation configurations                |
| `VirtualIPs`       | `[]VirtualIP`            | `virtualIps`       | CARP, IP alias, and proxy ARP configurations   |
| `InterfaceGroups`  | `[]InterfaceGroup`       | `interfaceGroups`  | Logical interface group configurations         |
| `FirewallRules`    | `[]FirewallRule`         | `firewallRules`    | Normalized firewall filter rules               |
| `NAT`              | `NATConfig`              | `nat`              | NAT configuration (inbound and outbound)       |
| `DHCP`             | `[]DHCPScope`            | `dhcp`             | DHCP server scopes, one per interface          |
| `DNS`              | `DNSConfig`              | `dns`              | DNS resolver and forwarder configuration       |
| `NTP`              | `NTPConfig`              | `ntp`              | NTP time synchronization settings              |
| `SNMP`             | `SNMPConfig`             | `snmp`             | SNMP service configuration                     |
| `LoadBalancer`     | `LoadBalancerConfig`     | `loadBalancer`     | Load balancer and health monitor configuration |
| `VPN`              | `VPN`                    | `vpn`              | VPN subsystem configurations                   |
| `Routing`          | `Routing`                | `routing`          | Gateways, gateway groups, and static routes    |
| `Certificates`     | `[]Certificate`          | `certificates`     | TLS/SSL certificates                           |
| `CAs`              | `[]CertificateAuthority` | `cas`              | Certificate authorities                        |
| `HighAvailability` | `HighAvailability`       | `highAvailability` | CARP/pfsync HA settings                        |
| `IDS`              | `*IDSConfig`             | `ids`              | Intrusion detection/prevention configuration   |
| `Syslog`           | `SyslogConfig`           | `syslog`           | Remote syslog forwarding configuration         |
| `Users`            | `[]User`                 | `users`            | System user accounts                           |
| `Groups`           | `[]Group`                | `groups`           | System groups                                  |
| `Sysctl`           | `[]SysctlItem`           | `sysctl`           | Kernel tunable parameters                      |
| `Packages`         | `[]Package`              | `packages`         | Installed software packages                    |
| `Revision`         | `Revision`               | `revision`         | Configuration revision metadata                |

**Enrichment fields** (populated during export, not present in raw parse):

| Field                | Type                  | JSON Key             | Description                         |
| -------------------- | --------------------- | -------------------- | ----------------------------------- |
| `Statistics`         | `*Statistics`         | `statistics`         | Calculated configuration statistics |
| `Analysis`           | `*Analysis`           | `analysis`           | Analysis findings and insights      |
| `SecurityAssessment` | `*SecurityAssessment` | `securityAssessment` | Security scores and recommendations |
| `PerformanceMetrics` | `*PerformanceMetrics` | `performanceMetrics` | Performance-related metrics         |
| `ComplianceChecks`   | `*ComplianceChecks`   | `complianceChecks`   | Compliance check results            |

---

## System Configuration

Core system settings including hostname, DNS, web GUI, and SSH.

### System

| Field                  | Type       | JSON Key                      | Description                          |
| ---------------------- | ---------- | ----------------------------- | ------------------------------------ |
| `Hostname`             | `string`   | `system.hostname`             | Device hostname                      |
| `Domain`               | `string`   | `system.domain`               | DNS domain name                      |
| `Optimization`         | `string`   | `system.optimization`         | TCP/IP optimization profile          |
| `Language`             | `string`   | `system.language`             | Web GUI language code                |
| `Timezone`             | `string`   | `system.timezone`             | System timezone (Region/City)        |
| `TimeServers`          | `[]string` | `system.timeServers`          | Configured NTP server addresses      |
| `DNSServers`           | `[]string` | `system.dnsServers`           | Configured DNS resolver addresses    |
| `DNSAllowOverride`     | `bool`     | `system.dnsAllowOverride`     | Allow DHCP/PPP DNS override          |
| `WebGUI`               | `WebGUI`   | `system.webGui`               | Web GUI access configuration         |
| `SSH`                  | `SSH`      | `system.ssh`                  | SSH service configuration            |
| `Firmware`             | `Firmware` | `system.firmware`             | Firmware version and update settings |
| `DisableNATReflection` | `bool`     | `system.disableNatReflection` | Disable hairpin NAT                  |
| `DisableConsoleMenu`   | `bool`     | `system.disableConsoleMenu`   | Disable console menu                 |
| `IPv6Allow`            | `bool`     | `system.ipv6Allow`            | Enable IPv6 traffic                  |
| `Notes`                | `[]string` | `system.notes`                | Operator notes                       |

### SSH

| Field     | Type     | JSON Key             | Description              |
| --------- | -------- | -------------------- | ------------------------ |
| `Enabled` | `bool`   | `system.ssh.enabled` | Whether SSH is active    |
| `Port`    | `string` | `system.ssh.port`    | SSH listening port       |
| `Group`   | `string` | `system.ssh.group`   | Group allowed SSH access |

### WebGUI

| Field               | Type     | JSON Key                          | Description                   |
| ------------------- | -------- | --------------------------------- | ----------------------------- |
| `Protocol`          | `string` | `system.webGui.protocol`          | Web GUI protocol (http/https) |
| `SSLCertRef`        | `string` | `system.webGui.sslCertRef`        | SSL certificate reference ID  |
| `LoginAutocomplete` | `bool`   | `system.webGui.loginAutocomplete` | Browser autocomplete on login |
| `MaxProcesses`      | `string` | `system.webGui.maxProcesses`      | Max web server processes      |

### Firmware

| Field     | Type     | JSON Key                  | Description                         |
| --------- | -------- | ------------------------- | ----------------------------------- |
| `Version` | `string` | `system.firmware.version` | Firmware version string             |
| `Mirror`  | `string` | `system.firmware.mirror`  | Update mirror URL                   |
| `Flavour` | `string` | `system.firmware.flavour` | Firmware flavour (OpenSSL/LibreSSL) |
| `Plugins` | `string` | `system.firmware.plugins` | Comma-separated plugin list         |

---

## Network Interfaces

Network interface configurations are exported as a **flat array**, not a map.

### Interface

| Field          | Type     | JSON Key                    | Description                               |
| -------------- | -------- | --------------------------- | ----------------------------------------- |
| `Name`         | `string` | `interfaces[].name`         | Logical name (e.g., "lan", "wan", "opt1") |
| `PhysicalIf`   | `string` | `interfaces[].physicalIf`   | Physical device (e.g., "igb0", "em0")     |
| `Description`  | `string` | `interfaces[].description`  | Human-readable label                      |
| `Enabled`      | `bool`   | `interfaces[].enabled`      | Administratively up                       |
| `IPAddress`    | `string` | `interfaces[].ipAddress`    | IPv4 address                              |
| `IPv6Address`  | `string` | `interfaces[].ipv6Address`  | IPv6 address                              |
| `Subnet`       | `string` | `interfaces[].subnet`       | IPv4 subnet prefix length                 |
| `SubnetV6`     | `string` | `interfaces[].subnetV6`     | IPv6 subnet prefix length                 |
| `Gateway`      | `string` | `interfaces[].gateway`      | IPv4 gateway                              |
| `GatewayV6`    | `string` | `interfaces[].gatewayV6`    | IPv6 gateway                              |
| `BlockPrivate` | `bool`   | `interfaces[].blockPrivate` | Block RFC 1918 traffic                    |
| `BlockBogons`  | `bool`   | `interfaces[].blockBogons`  | Block bogon traffic                       |
| `Type`         | `string` | `interfaces[].type`         | Interface type (dhcp, static, none)       |
| `MTU`          | `string` | `interfaces[].mtu`          | Maximum transmission unit                 |
| `SpoofMAC`     | `string` | `interfaces[].spoofMac`     | Overridden MAC address                    |
| `Virtual`      | `bool`   | `interfaces[].virtual`      | Virtual interface flag                    |

### VLAN

| Field         | Type     | JSON Key              | Description               |
| ------------- | -------- | --------------------- | ------------------------- |
| `VLANIf`      | `string` | `vlans[].vlanIf`      | VLAN interface name       |
| `PhysicalIf`  | `string` | `vlans[].physicalIf`  | Parent physical interface |
| `Tag`         | `string` | `vlans[].tag`         | 802.1Q VLAN tag           |
| `Description` | `string` | `vlans[].description` | Description               |

### Gateway

| Field            | Type     | JSON Key                            | Description                   |
| ---------------- | -------- | ----------------------------------- | ----------------------------- |
| `Name`           | `string` | `routing.gateways[].name`           | Gateway name                  |
| `Interface`      | `string` | `routing.gateways[].interface`      | Reachable interface           |
| `Address`        | `string` | `routing.gateways[].address`        | Gateway IP address            |
| `IPProtocol`     | `string` | `routing.gateways[].ipProtocol`     | Address family (inet/inet6)   |
| `Weight`         | `string` | `routing.gateways[].weight`         | Priority weight for multi-WAN |
| `Description`    | `string` | `routing.gateways[].description`    | Description                   |
| `Monitor`        | `string` | `routing.gateways[].monitor`        | Health monitoring IP          |
| `Disabled`       | `bool`   | `routing.gateways[].disabled`       | Administratively disabled     |
| `DefaultGW`      | `string` | `routing.gateways[].defaultGw`      | Default route marker          |
| `MonitorDisable` | `string` | `routing.gateways[].monitorDisable` | Disable health monitoring     |

---

## Firewall and Security

Firewall rules are normalized with clean boolean types and resolved endpoint addresses.

### FirewallRule

| Field         | Type           | JSON Key                      | Description                         |
| ------------- | -------------- | ----------------------------- | ----------------------------------- |
| `UUID`        | `string`       | `firewallRules[].uuid`        | Unique rule identifier              |
| `Type`        | `string`       | `firewallRules[].type`        | Action: "pass", "block", "reject"   |
| `Description` | `string`       | `firewallRules[].description` | Human-readable description          |
| `Interfaces`  | `[]string`     | `firewallRules[].interfaces`  | Applied interface names             |
| `IPProtocol`  | `string`       | `firewallRules[].ipProtocol`  | Address family (inet/inet6)         |
| `Protocol`    | `string`       | `firewallRules[].protocol`    | Layer-4 protocol (tcp, udp, icmp)   |
| `Source`      | `RuleEndpoint` | `firewallRules[].source`      | Source endpoint                     |
| `Destination` | `RuleEndpoint` | `firewallRules[].destination` | Destination endpoint                |
| `Direction`   | `string`       | `firewallRules[].direction`   | Traffic direction (in, out, any)    |
| `Floating`    | `bool`         | `firewallRules[].floating`    | Floating rule (not interface-bound) |
| `Quick`       | `bool`         | `firewallRules[].quick`       | Quick matching (first match wins)   |
| `Gateway`     | `string`       | `firewallRules[].gateway`     | Policy-based routing gateway        |
| `Log`         | `bool`         | `firewallRules[].log`         | Log matched packets                 |
| `Disabled`    | `bool`         | `firewallRules[].disabled`    | Administratively disabled           |
| `Tracker`     | `string`       | `firewallRules[].tracker`     | Tracking identifier                 |
| `StateType`   | `string`       | `firewallRules[].stateType`   | State tracking type                 |

### RuleEndpoint

Used for both `source` and `destination` in firewall and NAT rules.

| Field     | Type     | JSON Key  | Description                              |
| --------- | -------- | --------- | ---------------------------------------- |
| `Address` | `string` | `address` | Resolved address ("any", CIDR, hostname) |
| `Port`    | `string` | `port`    | Port or port range                       |
| `Negated` | `bool`   | `negated` | Inverted match (NOT logic)               |

---

## NAT Configuration

### NATConfig

| Field                | Type               | JSON Key                 | Description                       |
| -------------------- | ------------------ | ------------------------ | --------------------------------- |
| `OutboundMode`       | `string`           | `nat.outboundMode`       | Mode: automatic, hybrid, advanced |
| `ReflectionDisabled` | `bool`             | `nat.reflectionDisabled` | NAT reflection turned off         |
| `OutboundRules`      | `[]NATRule`        | `nat.outboundRules`      | Outbound NAT rules                |
| `InboundRules`       | `[]InboundNATRule` | `nat.inboundRules`       | Port-forward NAT rules            |

### NATRule (Outbound)

| Field         | Type           | JSON Key                          | Description                 |
| ------------- | -------------- | --------------------------------- | --------------------------- |
| `UUID`        | `string`       | `nat.outboundRules[].uuid`        | Unique identifier           |
| `Interfaces`  | `[]string`     | `nat.outboundRules[].interfaces`  | Applied interfaces          |
| `Protocol`    | `string`       | `nat.outboundRules[].protocol`    | Layer-4 protocol            |
| `Source`      | `RuleEndpoint` | `nat.outboundRules[].source`      | Source endpoint             |
| `Destination` | `RuleEndpoint` | `nat.outboundRules[].destination` | Destination endpoint        |
| `Target`      | `string`       | `nat.outboundRules[].target`      | Translation target address  |
| `NatPort`     | `string`       | `nat.outboundRules[].natPort`     | Translated destination port |
| `Disabled`    | `bool`         | `nat.outboundRules[].disabled`    | Administratively disabled   |
| `Log`         | `bool`         | `nat.outboundRules[].log`         | Log matched packets         |
| `Description` | `string`       | `nat.outboundRules[].description` | Description                 |

### InboundNATRule (Port Forward)

| Field          | Type           | JSON Key                          | Description               |
| -------------- | -------------- | --------------------------------- | ------------------------- |
| `UUID`         | `string`       | `nat.inboundRules[].uuid`         | Unique identifier         |
| `Interfaces`   | `[]string`     | `nat.inboundRules[].interfaces`   | Applied interfaces        |
| `Protocol`     | `string`       | `nat.inboundRules[].protocol`     | Layer-4 protocol          |
| `Source`       | `RuleEndpoint` | `nat.inboundRules[].source`       | Source endpoint           |
| `Destination`  | `RuleEndpoint` | `nat.inboundRules[].destination`  | Destination endpoint      |
| `ExternalPort` | `string`       | `nat.inboundRules[].externalPort` | External port to forward  |
| `InternalIP`   | `string`       | `nat.inboundRules[].internalIp`   | Internal target IP        |
| `InternalPort` | `string`       | `nat.inboundRules[].internalPort` | Internal target port      |
| `Disabled`     | `bool`         | `nat.inboundRules[].disabled`     | Administratively disabled |
| `Log`          | `bool`         | `nat.inboundRules[].log`          | Log matched packets       |
| `Description`  | `string`       | `nat.inboundRules[].description`  | Description               |

---

## Services

### DHCPScope

DHCP scopes are a flat array with one entry per interface.

| Field          | Type                | JSON Key              | Description                     |
| -------------- | ------------------- | --------------------- | ------------------------------- |
| `Interface`    | `string`            | `dhcp[].interface`    | Bound interface name            |
| `Enabled`      | `bool`              | `dhcp[].enabled`      | DHCP server active on interface |
| `Range`        | `DHCPRange`         | `dhcp[].range`        | Address pool range              |
| `Gateway`      | `string`            | `dhcp[].gateway`      | Default gateway for clients     |
| `DNSServer`    | `string`            | `dhcp[].dnsServer`    | DNS server for clients          |
| `NTPServer`    | `string`            | `dhcp[].ntpServer`    | NTP server for clients          |
| `WINSServer`   | `string`            | `dhcp[].winsServer`   | WINS server for clients         |
| `StaticLeases` | `[]DHCPStaticLease` | `dhcp[].staticLeases` | Fixed MAC-to-IP mappings        |

### DHCPRange

| Field  | Type     | JSON Key            | Description      |
| ------ | -------- | ------------------- | ---------------- |
| `From` | `string` | `dhcp[].range.from` | First IP in pool |
| `To`   | `string` | `dhcp[].range.to`   | Last IP in pool  |

### DHCPStaticLease

| Field         | Type     | JSON Key                            | Description          |
| ------------- | -------- | ----------------------------------- | -------------------- |
| `MAC`         | `string` | `dhcp[].staticLeases[].mac`         | Hardware MAC address |
| `IPAddress`   | `string` | `dhcp[].staticLeases[].ipAddress`   | Fixed IP address     |
| `Hostname`    | `string` | `dhcp[].staticLeases[].hostname`    | Assigned hostname    |
| `Description` | `string` | `dhcp[].staticLeases[].description` | Description          |

### DNS (Unbound)

| Field            | Type   | JSON Key                     | Description               |
| ---------------- | ------ | ---------------------------- | ------------------------- |
| `Enabled`        | `bool` | `dns.unbound.enabled`        | Unbound resolver active   |
| `DNSSEC`         | `bool` | `dns.unbound.dnssec`         | DNSSEC validation enabled |
| `DNSSECStripped` | `bool` | `dns.unbound.dnssecStripped` | DNSSEC stripped mode      |

### DNS (dnsmasq)

| Field     | Type   | JSON Key              | Description              |
| --------- | ------ | --------------------- | ------------------------ |
| `Enabled` | `bool` | `dns.dnsMasq.enabled` | dnsmasq forwarder active |

---

## VPN Configuration

### VPN (Root)

| Field       | Type              | JSON Key        | Description              |
| ----------- | ----------------- | --------------- | ------------------------ |
| `OpenVPN`   | `OpenVPNConfig`   | `vpn.openVpn`   | OpenVPN configurations   |
| `WireGuard` | `WireGuardConfig` | `vpn.wireGuard` | WireGuard configurations |
| `IPsec`     | `IPsecConfig`     | `vpn.ipsec`     | IPsec configurations     |

### OpenVPN Server

| Field             | Type     | JSON Key                                | Description                      |
| ----------------- | -------- | --------------------------------------- | -------------------------------- |
| `VPNID`           | `string` | `vpn.openVpn.servers[].vpnId`           | Unique VPN instance ID           |
| `Mode`            | `string` | `vpn.openVpn.servers[].mode`            | Server mode                      |
| `Protocol`        | `string` | `vpn.openVpn.servers[].protocol`        | Transport protocol (UDP4/TCP4)   |
| `Interface`       | `string` | `vpn.openVpn.servers[].interface`       | Listening interface              |
| `LocalPort`       | `string` | `vpn.openVpn.servers[].localPort`       | Listening port                   |
| `Description`     | `string` | `vpn.openVpn.servers[].description`     | Description                      |
| `TunnelNetwork`   | `string` | `vpn.openVpn.servers[].tunnelNetwork`   | IPv4 tunnel network CIDR         |
| `TunnelNetworkV6` | `string` | `vpn.openVpn.servers[].tunnelNetworkV6` | IPv6 tunnel network CIDR         |
| `LocalNetwork`    | `string` | `vpn.openVpn.servers[].localNetwork`    | Local network pushed to clients  |
| `MaxClients`      | `string` | `vpn.openVpn.servers[].maxClients`      | Max simultaneous connections     |
| `Compression`     | `string` | `vpn.openVpn.servers[].compression`     | Compression algorithm            |
| `StrictUserCN`    | `bool`   | `vpn.openVpn.servers[].strictUserCn`    | Enforce CN-to-username matching  |
| `GWRedir`         | `bool`   | `vpn.openVpn.servers[].gwRedir`         | Redirect all traffic through VPN |

### OpenVPN Client

| Field         | Type     | JSON Key                            | Description            |
| ------------- | -------- | ----------------------------------- | ---------------------- |
| `VPNID`       | `string` | `vpn.openVpn.clients[].vpnId`       | Unique VPN instance ID |
| `Mode`        | `string` | `vpn.openVpn.clients[].mode`        | Client mode            |
| `Protocol`    | `string` | `vpn.openVpn.clients[].protocol`    | Transport protocol     |
| `Interface`   | `string` | `vpn.openVpn.clients[].interface`   | Bound interface        |
| `ServerAddr`  | `string` | `vpn.openVpn.clients[].serverAddr`  | Remote server address  |
| `ServerPort`  | `string` | `vpn.openVpn.clients[].serverPort`  | Remote server port     |
| `Description` | `string` | `vpn.openVpn.clients[].description` | Description            |

### WireGuard Server

| Field           | Type     | JSON Key                                | Description           |
| --------------- | -------- | --------------------------------------- | --------------------- |
| `UUID`          | `string` | `vpn.wireGuard.servers[].uuid`          | Unique identifier     |
| `Enabled`       | `bool`   | `vpn.wireGuard.servers[].enabled`       | Instance active       |
| `Name`          | `string` | `vpn.wireGuard.servers[].name`          | Server name           |
| `PublicKey`     | `string` | `vpn.wireGuard.servers[].publicKey`     | WireGuard public key  |
| `Port`          | `string` | `vpn.wireGuard.servers[].port`          | UDP listening port    |
| `MTU`           | `string` | `vpn.wireGuard.servers[].mtu`           | Tunnel MTU            |
| `TunnelAddress` | `string` | `vpn.wireGuard.servers[].tunnelAddress` | Tunnel IP with prefix |
| `DNS`           | `string` | `vpn.wireGuard.servers[].dns`           | DNS server for tunnel |

### WireGuard Client (Peer)

| Field           | Type     | JSON Key                                | Description                 |
| --------------- | -------- | --------------------------------------- | --------------------------- |
| `UUID`          | `string` | `vpn.wireGuard.clients[].uuid`          | Unique identifier           |
| `Enabled`       | `bool`   | `vpn.wireGuard.clients[].enabled`       | Peer active                 |
| `Name`          | `string` | `vpn.wireGuard.clients[].name`          | Peer name                   |
| `PublicKey`     | `string` | `vpn.wireGuard.clients[].publicKey`     | Peer public key             |
| `TunnelAddress` | `string` | `vpn.wireGuard.clients[].tunnelAddress` | Allowed IP address          |
| `ServerAddress` | `string` | `vpn.wireGuard.clients[].serverAddress` | Endpoint address            |
| `ServerPort`    | `string` | `vpn.wireGuard.clients[].serverPort`    | Endpoint port               |
| `Keepalive`     | `string` | `vpn.wireGuard.clients[].keepalive`     | Persistent keepalive (secs) |

### IPsec

| Field             | Type   | JSON Key                    | Description                      |
| ----------------- | ------ | --------------------------- | -------------------------------- |
| `Enabled`         | `bool` | `vpn.ipsec.enabled`         | IPsec subsystem active           |
| `PreferredOldSA`  | `bool` | `vpn.ipsec.preferredOldSa`  | Prefer old security associations |
| `DisableVPNRules` | `bool` | `vpn.ipsec.disableVpnRules` | Disable auto firewall rules      |

---

## Routing

### Routing (Root)

| Field           | Type             | JSON Key                | Description                 |
| --------------- | ---------------- | ----------------------- | --------------------------- |
| `Gateways`      | `[]Gateway`      | `routing.gateways`      | Network gateways            |
| `GatewayGroups` | `[]GatewayGroup` | `routing.gatewayGroups` | Gateway groups for failover |
| `StaticRoutes`  | `[]StaticRoute`  | `routing.staticRoutes`  | Manually configured routes  |

### StaticRoute

| Field         | Type     | JSON Key                             | Description               |
| ------------- | -------- | ------------------------------------ | ------------------------- |
| `Network`     | `string` | `routing.staticRoutes[].network`     | Destination CIDR          |
| `Gateway`     | `string` | `routing.staticRoutes[].gateway`     | Next-hop gateway name     |
| `Description` | `string` | `routing.staticRoutes[].description` | Description               |
| `Disabled`    | `bool`   | `routing.staticRoutes[].disabled`    | Administratively disabled |

### GatewayGroup

| Field         | Type       | JSON Key                              | Description                |
| ------------- | ---------- | ------------------------------------- | -------------------------- |
| `Name`        | `string`   | `routing.gatewayGroups[].name`        | Group name                 |
| `Items`       | `[]string` | `routing.gatewayGroups[].items`       | Member gateways with tiers |
| `Trigger`     | `string`   | `routing.gatewayGroups[].trigger`     | Failover condition         |
| `Description` | `string`   | `routing.gatewayGroups[].description` | Description                |

---

## Users and Groups

Users and groups are **top-level arrays**, not nested under `system`.

### User

| Field         | Type       | JSON Key              | Description           |
| ------------- | ---------- | --------------------- | --------------------- |
| `Name`        | `string`   | `users[].name`        | Login username        |
| `Disabled`    | `bool`     | `users[].disabled`    | Account locked        |
| `Description` | `string`   | `users[].description` | Description           |
| `Scope`       | `string`   | `users[].scope`       | Scope (system, local) |
| `GroupName`   | `string`   | `users[].groupName`   | Primary group         |
| `UID`         | `string`   | `users[].uid`         | Numeric user ID       |
| `APIKeys`     | `[]APIKey` | `users[].apiKeys`     | API key credentials   |

### Group

| Field         | Type     | JSON Key               | Description                |
| ------------- | -------- | ---------------------- | -------------------------- |
| `Name`        | `string` | `groups[].name`        | Group name                 |
| `Description` | `string` | `groups[].description` | Description                |
| `Scope`       | `string` | `groups[].scope`       | Scope (system, local)      |
| `GID`         | `string` | `groups[].gid`         | Numeric group ID           |
| `Member`      | `string` | `groups[].member`      | Comma-separated user UIDs  |
| `Privileges`  | `string` | `groups[].privileges`  | Comma-separated privileges |

---

## Certificates

### Certificate

| Field         | Type     | JSON Key                     | Description                     |
| ------------- | -------- | ---------------------------- | ------------------------------- |
| `RefID`       | `string` | `certificates[].refId`       | Unique reference ID             |
| `Description` | `string` | `certificates[].description` | Description                     |
| `Type`        | `string` | `certificates[].type`        | Certificate type (server, user) |
| `CARef`       | `string` | `certificates[].caRef`       | Issuing CA reference ID         |
| `Certificate` | `string` | `certificates[].certificate` | PEM-encoded certificate         |
| `PrivateKey`  | `string` | `certificates[].privateKey`  | PEM-encoded private key         |

### CertificateAuthority

| Field         | Type     | JSON Key            | Description                    |
| ------------- | -------- | ------------------- | ------------------------------ |
| `RefID`       | `string` | `cas[].refId`       | Unique reference ID            |
| `Description` | `string` | `cas[].description` | Description                    |
| `Certificate` | `string` | `cas[].certificate` | PEM-encoded CA certificate     |
| `PrivateKey`  | `string` | `cas[].privateKey`  | PEM-encoded CA private key     |
| `Serial`      | `string` | `cas[].serial`      | Next certificate serial number |
