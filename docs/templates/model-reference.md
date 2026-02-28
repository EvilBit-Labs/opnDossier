# Model Reference

> **Auto-generated documentation** - Do not edit manually. Generated: 2026-02-27 00:55:57

This document provides a complete reference of all data fields available in the opnDossier configuration model. Use this reference when working with JSON/YAML exports or building custom integrations.

## Table of Contents

- [OpnSenseDocument (Root)](#opnsensedocument-root)
- [System Configuration](#system-configuration)
- [Network Interfaces](#network-interfaces)
- [Firewall & Security](#firewall--security)
- [Services](#services)
- [VPN Configuration](#vpn-configuration)

---

## OpnSenseDocument (Root)

The root configuration object parsed from OPNsense XML.

| Field                  | Type                     | JSON Path              | Description       |
| ---------------------- | ------------------------ | ---------------------- | ----------------- |
| `Version`              | `string`                 | `version`              | Optional          |
| `TriggerInitialWizard` | `BoolFlag`               | `triggerInitialWizard` | -                 |
| `Theme`                | `string`                 | `theme`                | Options: opnsense |
| `Sysctl`               | `[]SysctlItem`           | `sysctl`               | Optional          |
| `System`               | `System`                 | `system`               | Required          |
| `Interfaces`           | `Interfaces`             | `interfaces`           | Required          |
| `Dhcpd`                | `Dhcpd`                  | `dhcpd`                | -                 |
| `Unbound`              | `Unbound`                | `unbound`              | -                 |
| `Snmpd`                | `Snmpd`                  | `snmpd`                | -                 |
| `Nat`                  | `Nat`                    | `nat`                  | -                 |
| `Filter`               | `Filter`                 | `filter`               | -                 |
| `Rrd`                  | `Rrd`                    | `rrd`                  | -                 |
| `LoadBalancer`         | `LoadBalancer`           | `loadBalancer`         | -                 |
| `Ntpd`                 | `Ntpd`                   | `ntpd`                 | -                 |
| `Widgets`              | `Widgets`                | `widgets`              | -                 |
| `Revision`             | `Revision`               | `revision`             | -                 |
| `Gateways`             | `Gateways`               | `gateways`             | -                 |
| `HighAvailabilitySync` | `HighAvailabilitySync`   | `hasync`               | -                 |
| `InterfaceGroups`      | `InterfaceGroups`        | `ifgroups`             | -                 |
| `GIFInterfaces`        | `GIFInterfaces`          | `gifs`                 | -                 |
| `GREInterfaces`        | `GREInterfaces`          | `gres`                 | -                 |
| `LAGGInterfaces`       | `LAGGInterfaces`         | `laggs`                | -                 |
| `VirtualIP`            | `VirtualIP`              | `virtualip`            | -                 |
| `VLANs`                | `VLANs`                  | `vlans`                | -                 |
| `OpenVPN`              | `OpenVPN`                | `openvpn`              | -                 |
| `StaticRoutes`         | `StaticRoutes`           | `staticroutes`         | -                 |
| `Bridges`              | `Bridges`                | `bridges`              | -                 |
| `PPPInterfaces`        | `PPPInterfaces`          | `ppps`                 | -                 |
| `Wireless`             | `Wireless`               | `wireless`             | -                 |
| `CAs`                  | `[]CertificateAuthority` | `ca`                   | Optional          |
| `DHCPv6Server`         | `DHCPv6Server`           | `dhcpdv6`              | -                 |
| `Certs`                | `[]Cert`                 | `cert`                 | Optional          |
| `DNSMasquerade`        | `DNSMasq`                | `dnsmasq`              | -                 |
| `Syslog`               | `Syslog`                 | `syslog`               | -                 |
| `OPNsense`             | `OPNsense`               | `opnsense`             | -                 |

---

## System Configuration

Core system settings including hostname, users, and SSH configuration.

### System

| Field                           | Type           | JSON Path                              | Description     |
| ------------------------------- | -------------- | -------------------------------------- | --------------- |
| `Optimization`                  | `string`       | `system.optimization`                  | Options: normal |
| `Hostname`                      | `string`       | `system.hostname`                      | Required        |
| `Domain`                        | `string`       | `system.domain`                        | Required        |
| `DNSAllowOverride`              | `int`          | `system.dnsAllowOverride`              | Optional        |
| `DNSServer`                     | `string`       | `system.dnsServer`                     | Optional        |
| `Language`                      | `string`       | `system.language`                      | Optional        |
| `Firmware`                      | `Firmware`     | `system.firmware`                      | -               |
| `Group`                         | `[]Group`      | `system.groups`                        | Optional        |
| `User`                          | `[]User`       | `system.users`                         | Optional        |
| `WebGUI`                        | `WebGUIConfig` | `system.webgui`                        | -               |
| `SSH`                           | `SSHConfig`    | `system.ssh`                           | -               |
| `Timezone`                      | `string`       | `system.timezone`                      | Optional        |
| `TimeServers`                   | `string`       | `system.timeServers`                   | Optional        |
| `UseVirtualTerminal`            | `int`          | `system.useVirtualTerminal`            | Optional        |
| `DisableVLANHWFilter`           | `int`          | `system.disableVlanHwFilter`           | Optional        |
| `DisableChecksumOffloading`     | `int`          | `system.disableChecksumOffloading`     | Optional        |
| `DisableSegmentationOffloading` | `int`          | `system.disableSegmentationOffloading` | Optional        |
| `DisableLargeReceiveOffloading` | `int`          | `system.disableLargeReceiveOffloading` | Optional        |
| `IPv6Allow`                     | `string`       | `system.ipv6Allow`                     | Optional        |
| `DisableNATReflection`          | `string`       | `system.disableNatReflection`          | Optional        |
| `DisableConsoleMenu`            | `BoolFlag`     | `system.disableConsoleMenu`            | -               |
| `NextUID`                       | `int`          | `system.nextUid`                       | Optional        |
| `NextGID`                       | `int`          | `system.nextGid`                       | Optional        |
| `PowerdACMode`                  | `string`       | `system.powerdAcMode`                  | Options: hadp   |
| `PowerdBatteryMode`             | `string`       | `system.powerdBatteryMode`             | Options: hadp   |
| `PowerdNormalMode`              | `string`       | `system.powerdNormalMode`              | Options: hadp   |
| `Bogons`                        | `struct`       | `system.bogons`                        | -               |
| `PfShareForward`                | `int`          | `system.pfShareForward`                | Optional        |
| `LbUseSticky`                   | `int`          | `system.lbUseSticky`                   | Optional        |
| `RrdBackup`                     | `int`          | `system.rrdBackup`                     | Optional        |
| `NetflowBackup`                 | `int`          | `system.netflowBackup`                 | Optional        |
| `NTPD`                          | `struct`       | `system.ntpd`                          | -               |
| `SNMPD`                         | `struct`       | `system.snmpd`                         | -               |
| `RRD`                           | `struct`       | `system.rrd`                           | -               |
| `LoadBalancer`                  | `struct`       | `system.loadBalancer`                  | -               |
| `Unbound`                       | `Unbound`      | `system.unbound`                       | -               |
| `Notes`                         | `[]string`     | `system.notes`                         | Optional        |

### User

| Field            | Type       | JSON Path                       | Description               |
| ---------------- | ---------- | ------------------------------- | ------------------------- |
| `Name`           | `string`   | `system.users[].name`           | Required                  |
| `Disabled`       | `BoolFlag` | `system.users[].disabled`       | -                         |
| `Descr`          | `string`   | `system.users[].description`    | Optional                  |
| `Scope`          | `string`   | `system.users[].scope`          | Required; Options: system |
| `Groupname`      | `string`   | `system.users[].groupname`      | Required                  |
| `Password`       | `string`   | `system.users[].password`       | Required                  |
| `UID`            | `string`   | `system.users[].uid`            | Required                  |
| `APIKeys`        | `[]APIKey` | `system.users[].apiKeys`        | Optional                  |
| `Expires`        | `BoolFlag` | `system.users[].expires`        | -                         |
| `AuthorizedKeys` | `BoolFlag` | `system.users[].authorizedKeys` | -                         |
| `IPSecPSK`       | `BoolFlag` | `system.users[].ipsecPsk`       | -                         |
| `OTPSeed`        | `BoolFlag` | `system.users[].otpSeed`        | -                         |

### Group

| Field         | Type     | JSON Path                     | Description               |
| ------------- | -------- | ----------------------------- | ------------------------- |
| `Name`        | `string` | `system.groups[].name`        | Required                  |
| `Description` | `string` | `system.groups[].description` | Optional                  |
| `Scope`       | `string` | `system.groups[].scope`       | Required; Options: system |
| `Gid`         | `string` | `system.groups[].gid`         | Required                  |
| `Member`      | `string` | `system.groups[].member`      | Optional                  |
| `Priv`        | `string` | `system.groups[].privileges`  | Optional                  |

---

## Network Interfaces

Network interface configuration including VLANs and gateways.

### Interface

| Field                                      | Type           | JSON Path                                                    | Description |
| ------------------------------------------ | -------------- | ------------------------------------------------------------ | ----------- |
| `Enable`                                   | `string`       | `interfaces.<name>.enable`                                   | Optional    |
| `If`                                       | `string`       | `interfaces.<name>.if`                                       | Optional    |
| `Descr`                                    | `string`       | `interfaces.<name>.descr`                                    | Optional    |
| `Spoofmac`                                 | `string`       | `interfaces.<name>.spoofmac`                                 | Optional    |
| `InternalDynamic`                          | `int`          | `interfaces.<name>.internalDynamic`                          | Optional    |
| `Type`                                     | `string`       | `interfaces.<name>.type`                                     | Optional    |
| `Virtual`                                  | `int`          | `interfaces.<name>.virtual`                                  | Optional    |
| `Lock`                                     | `int`          | `interfaces.<name>.lock`                                     | Optional    |
| `MTU`                                      | `string`       | `interfaces.<name>.mtu`                                      | Optional    |
| `IPAddr`                                   | `string`       | `interfaces.<name>.ipaddr`                                   | Optional    |
| `IPAddrv6`                                 | `string`       | `interfaces.<name>.ipaddrv6`                                 | Optional    |
| `Subnet`                                   | `string`       | `interfaces.<name>.subnet`                                   | Optional    |
| `Subnetv6`                                 | `string`       | `interfaces.<name>.subnetv6`                                 | Optional    |
| `Gateway`                                  | `string`       | `interfaces.<name>.gateway`                                  | Optional    |
| `Gatewayv6`                                | `string`       | `interfaces.<name>.gatewayv6`                                | Optional    |
| `BlockPriv`                                | `string`       | `interfaces.<name>.blockpriv`                                | Optional    |
| `BlockBogons`                              | `string`       | `interfaces.<name>.blockbogons`                              | Optional    |
| `DHCPHostname`                             | `string`       | `interfaces.<name>.dhcphostname`                             | Optional    |
| `Media`                                    | `string`       | `interfaces.<name>.media`                                    | Optional    |
| `MediaOpt`                                 | `string`       | `interfaces.<name>.mediaopt`                                 | Optional    |
| `DHCP6IaPdLen`                             | `int`          | `interfaces.<name>.dhcp6IaPdLen`                             | Optional    |
| `Track6Interface`                          | `string`       | `interfaces.<name>.track6Interface`                          | Optional    |
| `Track6PrefixID`                           | `string`       | `interfaces.<name>.track6PrefixId`                           | Optional    |
| `AliasAddress`                             | `string`       | `interfaces.<name>.aliasAddress`                             | Optional    |
| `AliasSubnet`                              | `string`       | `interfaces.<name>.aliasSubnet`                              | Optional    |
| `DHCPRejectFrom`                           | `string`       | `interfaces.<name>.dhcprejectfrom`                           | Optional    |
| `DDNSDomainAlgorithm`                      | `string`       | `interfaces.<name>.ddnsdomainalgorithm`                      | Optional    |
| `NumberOptions`                            | `[]DhcpOption` | `interfaces.<name>.numberoptions`                            | Optional    |
| `Range`                                    | `DhcpRange`    | `interfaces.<name>.range`                                    | -           |
| `Winsserver`                               | `string`       | `interfaces.<name>.winsserver`                               | Optional    |
| `Dnsserver`                                | `string`       | `interfaces.<name>.dnsserver`                                | Optional    |
| `Ntpserver`                                | `string`       | `interfaces.<name>.ntpserver`                                | Optional    |
| `AdvDHCPRequestOptions`                    | `string`       | `interfaces.<name>.advDhcpRequestOptions`                    | Optional    |
| `AdvDHCPRequiredOptions`                   | `string`       | `interfaces.<name>.advDhcpRequiredOptions`                   | Optional    |
| `AdvDHCP6InterfaceStatementRequestOptions` | `string`       | `interfaces.<name>.advDhcp6InterfaceStatementRequestOptions` | Optional    |
| `AdvDHCP6ConfigFileOverride`               | `string`       | `interfaces.<name>.advDhcp6ConfigFileOverride`               | Optional    |
| `AdvDHCP6IDAssocStatementPrefixPLTime`     | `string`       | `interfaces.<name>.advDhcp6IdAssocStatementPrefixPltime`     | Optional    |

### Gateway

| Field            | Type       | JSON Path                        | Description |
| ---------------- | ---------- | -------------------------------- | ----------- |
| `XMLName`        | `Name`     | `gateways.item[].xmlname`        | -           |
| `Interface`      | `string`   | `gateways.item[].interface`      | -           |
| `Gateway`        | `string`   | `gateways.item[].gateway`        | -           |
| `Name`           | `string`   | `gateways.item[].name`           | -           |
| `Weight`         | `string`   | `gateways.item[].weight`         | -           |
| `IPProtocol`     | `string`   | `gateways.item[].ipprotocol`     | -           |
| `Interval`       | `string`   | `gateways.item[].interval`       | -           |
| `Descr`          | `string`   | `gateways.item[].descr`          | -           |
| `Monitor`        | `string`   | `gateways.item[].monitor`        | -           |
| `Disabled`       | `BoolFlag` | `gateways.item[].disabled`       | -           |
| `Created`        | `string`   | `gateways.item[].created`        | -           |
| `Updated`        | `string`   | `gateways.item[].updated`        | -           |
| `DefaultGW`      | `string`   | `gateways.item[].defaultgw`      | -           |
| `MonitorDisable` | `string`   | `gateways.item[].monitordisable` | -           |
| `FarGW`          | `string`   | `gateways.item[].fargw`          | -           |

---

## Firewall & Security

Firewall rules and NAT configuration.

### Rule (Firewall)

| Field             | Type          | JSON Path                       | Description |
| ----------------- | ------------- | ------------------------------- | ----------- |
| `XMLName`         | `Name`        | `filter.rule[].xmlname`         | -           |
| `Type`            | `string`      | `filter.rule[].type`            | -           |
| `Descr`           | `string`      | `filter.rule[].descr`           | -           |
| `Interface`       | `[]string`    | `filter.rule[].interface`       | -           |
| `IPProtocol`      | `string`      | `filter.rule[].ipprotocol`      | -           |
| `StateType`       | `string`      | `filter.rule[].statetype`       | -           |
| `Direction`       | `string`      | `filter.rule[].direction`       | -           |
| `Floating`        | `string`      | `filter.rule[].floating`        | -           |
| `Quick`           | `BoolFlag`    | `filter.rule[].quick`           | -           |
| `Protocol`        | `string`      | `filter.rule[].protocol`        | -           |
| `Source`          | `Source`      | `filter.rule[].source`          | -           |
| `Destination`     | `Destination` | `filter.rule[].destination`     | -           |
| `Target`          | `string`      | `filter.rule[].target`          | -           |
| `Gateway`         | `string`      | `filter.rule[].gateway`         | -           |
| `SourcePort`      | `string`      | `filter.rule[].sourceport`      | -           |
| `Log`             | `BoolFlag`    | `filter.rule[].log`             | -           |
| `Disabled`        | `BoolFlag`    | `filter.rule[].disabled`        | -           |
| `Tracker`         | `string`      | `filter.rule[].tracker`         | -           |
| `MaxSrcNodes`     | `string`      | `filter.rule[].maxsrcnodes`     | -           |
| `MaxSrcConn`      | `string`      | `filter.rule[].maxsrcconn`      | -           |
| `MaxSrcConnRate`  | `string`      | `filter.rule[].maxsrcconnrate`  | -           |
| `MaxSrcConnRates` | `string`      | `filter.rule[].maxsrcconnrates` | -           |
| `TCPFlags1`       | `string`      | `filter.rule[].tcpflags1`       | -           |
| `TCPFlags2`       | `string`      | `filter.rule[].tcpflags2`       | -           |
| `TCPFlagsAny`     | `BoolFlag`    | `filter.rule[].tcpflagsany`     | -           |
| `ICMPType`        | `string`      | `filter.rule[].icmptype`        | -           |
| `ICMP6Type`       | `string`      | `filter.rule[].icmp6type`       | -           |
| `StateTimeout`    | `string`      | `filter.rule[].statetimeout`    | -           |
| `AllowOpts`       | `BoolFlag`    | `filter.rule[].allowopts`       | -           |
| `DisableReplyTo`  | `BoolFlag`    | `filter.rule[].disablereplyto`  | -           |
| `NoPfSync`        | `BoolFlag`    | `filter.rule[].nopfsync`        | -           |
| `NoSync`          | `BoolFlag`    | `filter.rule[].nosync`          | -           |
| `Updated`         | `*Updated`    | `filter.rule[].updated`         | -           |
| `Created`         | `*Created`    | `filter.rule[].created`         | -           |
| `UUID`            | `string`      | `filter.rule[].uuid`            | -           |

### NATRule (Outbound)

| Field                | Type          | JSON Path                                | Description |
| -------------------- | ------------- | ---------------------------------------- | ----------- |
| `XMLName`            | `Name`        | `nat.outbound.rule[].xmlname`            | -           |
| `Interface`          | `[]string`    | `nat.outbound.rule[].interface`          | Optional    |
| `IPProtocol`         | `string`      | `nat.outbound.rule[].ipProtocol`         | Optional    |
| `Protocol`           | `string`      | `nat.outbound.rule[].protocol`           | Optional    |
| `Source`             | `Source`      | `nat.outbound.rule[].source`             | -           |
| `Destination`        | `Destination` | `nat.outbound.rule[].destination`        | -           |
| `Target`             | `string`      | `nat.outbound.rule[].target`             | Optional    |
| `SourcePort`         | `string`      | `nat.outbound.rule[].sourcePort`         | Optional    |
| `NatPort`            | `string`      | `nat.outbound.rule[].natPort`            | Optional    |
| `PoolOpts`           | `string`      | `nat.outbound.rule[].poolOpts`           | Optional    |
| `PoolOptsSrcHashKey` | `string`      | `nat.outbound.rule[].poolOptsSrcHashKey` | Optional    |
| `StaticNatPort`      | `BoolFlag`    | `nat.outbound.rule[].staticNatPort`      | Optional    |
| `NoNat`              | `BoolFlag`    | `nat.outbound.rule[].noNat`              | Optional    |
| `Disabled`           | `BoolFlag`    | `nat.outbound.rule[].disabled`           | Optional    |
| `Log`                | `BoolFlag`    | `nat.outbound.rule[].log`                | Optional    |
| `Descr`              | `string`      | `nat.outbound.rule[].description`        | Optional    |
| `Category`           | `string`      | `nat.outbound.rule[].category`           | Optional    |
| `Tag`                | `string`      | `nat.outbound.rule[].tag`                | Optional    |
| `Tagged`             | `string`      | `nat.outbound.rule[].tagged`             | Optional    |
| `Updated`            | `*Updated`    | `nat.outbound.rule[].updated`            | Optional    |
| `Created`            | `*Created`    | `nat.outbound.rule[].created`            | Optional    |
| `UUID`               | `string`      | `nat.outbound.rule[].uuid`               | Optional    |

---

## Services

System services configuration.

### Unbound (DNS)

| Field            | Type     | JSON Path                | Description |
| ---------------- | -------- | ------------------------ | ----------- |
| `Enable`         | `string` | `unbound.enable`         | -           |
| `Dnssec`         | `string` | `unbound.dnssec`         | Optional    |
| `Dnssecstripped` | `string` | `unbound.dnssecstripped` | Optional    |

### DHCP Interface

| Field                                             | Type                 | JSON Path                                                           | Description |
| ------------------------------------------------- | -------------------- | ------------------------------------------------------------------- | ----------- |
| `Enable`                                          | `string`             | `dhcpd.<interface>.enable`                                          | -           |
| `Range`                                           | `Range`              | `dhcpd.<interface>.range`                                           | -           |
| `Gateway`                                         | `string`             | `dhcpd.<interface>.gateway`                                         | -           |
| `DdnsDomainAlgorithm`                             | `string`             | `dhcpd.<interface>.ddnsdomainalgorithm`                             | -           |
| `NumberOptions`                                   | `[]DHCPNumberOption` | `dhcpd.<interface>.numberoptions`                                   | -           |
| `Winsserver`                                      | `string`             | `dhcpd.<interface>.winsserver`                                      | -           |
| `Dnsserver`                                       | `string`             | `dhcpd.<interface>.dnsserver`                                       | -           |
| `Ntpserver`                                       | `string`             | `dhcpd.<interface>.ntpserver`                                       | -           |
| `Staticmap`                                       | `[]DHCPStaticLease`  | `dhcpd.<interface>.staticmap`                                       | -           |
| `AliasAddress`                                    | `string`             | `dhcpd.<interface>.aliasaddress`                                    | -           |
| `AliasSubnet`                                     | `string`             | `dhcpd.<interface>.aliassubnet`                                     | -           |
| `DHCPRejectFrom`                                  | `string`             | `dhcpd.<interface>.dhcprejectfrom`                                  | -           |
| `AdvDHCPPTTimeout`                                | `string`             | `dhcpd.<interface>.advdhcppttimeout`                                | -           |
| `AdvDHCPPTRetry`                                  | `string`             | `dhcpd.<interface>.advdhcpptretry`                                  | -           |
| `AdvDHCPPTSelectTimeout`                          | `string`             | `dhcpd.<interface>.advdhcpptselecttimeout`                          | -           |
| `AdvDHCPPTReboot`                                 | `string`             | `dhcpd.<interface>.advdhcpptreboot`                                 | -           |
| `AdvDHCPPTBackoffCutoff`                          | `string`             | `dhcpd.<interface>.advdhcpptbackoffcutoff`                          | -           |
| `AdvDHCPPTInitialInterval`                        | `string`             | `dhcpd.<interface>.advdhcpptinitialinterval`                        | -           |
| `AdvDHCPPTValues`                                 | `string`             | `dhcpd.<interface>.advdhcpptvalues`                                 | -           |
| `AdvDHCPSendOptions`                              | `string`             | `dhcpd.<interface>.advdhcpsendoptions`                              | -           |
| `AdvDHCPRequestOptions`                           | `string`             | `dhcpd.<interface>.advdhcprequestoptions`                           | -           |
| `AdvDHCPRequiredOptions`                          | `string`             | `dhcpd.<interface>.advdhcprequiredoptions`                          | -           |
| `AdvDHCPOptionModifiers`                          | `string`             | `dhcpd.<interface>.advdhcpoptionmodifiers`                          | -           |
| `AdvDHCPConfigAdvanced`                           | `string`             | `dhcpd.<interface>.advdhcpconfigadvanced`                           | -           |
| `AdvDHCPConfigFileOverride`                       | `string`             | `dhcpd.<interface>.advdhcpconfigfileoverride`                       | -           |
| `AdvDHCPConfigFileOverridePath`                   | `string`             | `dhcpd.<interface>.advdhcpconfigfileoverridepath`                   | -           |
| `Track6Interface`                                 | `string`             | `dhcpd.<interface>.track6interface`                                 | -           |
| `Track6PrefixID`                                  | `string`             | `dhcpd.<interface>.track6prefixid`                                  | -           |
| `AdvDHCP6InterfaceStatementSendOptions`           | `string`             | `dhcpd.<interface>.advdhcp6interfacestatementsendoptions`           | -           |
| `AdvDHCP6InterfaceStatementRequestOptions`        | `string`             | `dhcpd.<interface>.advdhcp6interfacestatementrequestoptions`        | -           |
| `AdvDHCP6InterfaceStatementInformationOnlyEnable` | `string`             | `dhcpd.<interface>.advdhcp6interfacestatementinformationonlyenable` | -           |
| `AdvDHCP6InterfaceStatementScript`                | `string`             | `dhcpd.<interface>.advdhcp6interfacestatementscript`                | -           |
| `AdvDHCP6IDAssocStatementAddressEnable`           | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementaddressenable`           | -           |
| `AdvDHCP6IDAssocStatementAddress`                 | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementaddress`                 | -           |
| `AdvDHCP6IDAssocStatementAddressID`               | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementaddressid`               | -           |
| `AdvDHCP6IDAssocStatementAddressPLTime`           | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementaddresspltime`           | -           |
| `AdvDHCP6IDAssocStatementAddressVLTime`           | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementaddressvltime`           | -           |
| `AdvDHCP6IDAssocStatementPrefixEnable`            | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementprefixenable`            | -           |
| `AdvDHCP6IDAssocStatementPrefix`                  | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementprefix`                  | -           |
| `AdvDHCP6IDAssocStatementPrefixID`                | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementprefixid`                | -           |
| `AdvDHCP6IDAssocStatementPrefixPLTime`            | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementprefixpltime`            | -           |
| `AdvDHCP6IDAssocStatementPrefixVLTime`            | `string`             | `dhcpd.<interface>.advdhcp6idassocstatementprefixvltime`            | -           |
| `AdvDHCP6PrefixInterfaceStatementSLALen`          | `string`             | `dhcpd.<interface>.advdhcp6prefixinterfacestatementslalen`          | -           |
| `AdvDHCP6AuthenticationStatementAuthName`         | `string`             | `dhcpd.<interface>.advdhcp6authenticationstatementauthname`         | -           |
| `AdvDHCP6AuthenticationStatementProtocol`         | `string`             | `dhcpd.<interface>.advdhcp6authenticationstatementprotocol`         | -           |
| `AdvDHCP6AuthenticationStatementAlgorithm`        | `string`             | `dhcpd.<interface>.advdhcp6authenticationstatementalgorithm`        | -           |
| `AdvDHCP6AuthenticationStatementRDM`              | `string`             | `dhcpd.<interface>.advdhcp6authenticationstatementrdm`              | -           |
| `AdvDHCP6KeyInfoStatementKeyName`                 | `string`             | `dhcpd.<interface>.advdhcp6keyinfostatementkeyname`                 | -           |
| `AdvDHCP6KeyInfoStatementRealm`                   | `string`             | `dhcpd.<interface>.advdhcp6keyinfostatementrealm`                   | -           |
| `AdvDHCP6KeyInfoStatementKeyID`                   | `string`             | `dhcpd.<interface>.advdhcp6keyinfostatementkeyid`                   | -           |
| `AdvDHCP6KeyInfoStatementSecret`                  | `string`             | `dhcpd.<interface>.advdhcp6keyinfostatementsecret`                  | -           |
| `AdvDHCP6KeyInfoStatementExpire`                  | `string`             | `dhcpd.<interface>.advdhcp6keyinfostatementexpire`                  | -           |
| `AdvDHCP6ConfigAdvanced`                          | `string`             | `dhcpd.<interface>.advdhcp6configadvanced`                          | -           |
| `AdvDHCP6ConfigFileOverride`                      | `string`             | `dhcpd.<interface>.advdhcp6configfileoverride`                      | -           |
| `AdvDHCP6ConfigFileOverridePath`                  | `string`             | `dhcpd.<interface>.advdhcp6configfileoverridepath`                  | -           |

---

## VPN Configuration

VPN service configuration including OpenVPN and WireGuard.

### OpenVPN Server

| Field               | Type       | JSON Path                            | Description |
| ------------------- | ---------- | ------------------------------------ | ----------- |
| `XMLName`           | `Name`     | `openvpn.server[].xmlname`           | -           |
| `VPN_ID`            | `string`   | `openvpn.server[].vpn_id`            | -           |
| `Mode`              | `string`   | `openvpn.server[].mode`              | -           |
| `Protocol`          | `string`   | `openvpn.server[].protocol`          | -           |
| `Dev_mode`          | `string`   | `openvpn.server[].dev_mode`          | -           |
| `Interface`         | `string`   | `openvpn.server[].interface`         | -           |
| `Local_port`        | `string`   | `openvpn.server[].local_port`        | -           |
| `Description`       | `string`   | `openvpn.server[].description`       | -           |
| `Custom_options`    | `string`   | `openvpn.server[].custom_options`    | -           |
| `TLS`               | `string`   | `openvpn.server[].tls`               | -           |
| `TLS_type`          | `string`   | `openvpn.server[].tls_type`          | -           |
| `Cert_ref`          | `string`   | `openvpn.server[].cert_ref`          | -           |
| `CA_ref`            | `string`   | `openvpn.server[].ca_ref`            | -           |
| `CRL_ref`           | `string`   | `openvpn.server[].crl_ref`           | -           |
| `DH_length`         | `string`   | `openvpn.server[].dh_length`         | -           |
| `Ecdh_curve`        | `string`   | `openvpn.server[].ecdh_curve`        | -           |
| `Cert_depth`        | `string`   | `openvpn.server[].cert_depth`        | -           |
| `Strictusercn`      | `BoolFlag` | `openvpn.server[].strictusercn`      | -           |
| `Tunnel_network`    | `string`   | `openvpn.server[].tunnel_network`    | -           |
| `Tunnel_networkv6`  | `string`   | `openvpn.server[].tunnel_networkv6`  | -           |
| `Remote_network`    | `string`   | `openvpn.server[].remote_network`    | -           |
| `Remote_networkv6`  | `string`   | `openvpn.server[].remote_networkv6`  | -           |
| `Gwredir`           | `BoolFlag` | `openvpn.server[].gwredir`           | -           |
| `Local_network`     | `string`   | `openvpn.server[].local_network`     | -           |
| `Local_networkv6`   | `string`   | `openvpn.server[].local_networkv6`   | -           |
| `Maxclients`        | `string`   | `openvpn.server[].maxclients`        | -           |
| `Compression`       | `string`   | `openvpn.server[].compression`       | -           |
| `Passtos`           | `BoolFlag` | `openvpn.server[].passtos`           | -           |
| `Client2client`     | `BoolFlag` | `openvpn.server[].client2client`     | -           |
| `Dynamic_ip`        | `BoolFlag` | `openvpn.server[].dynamic_ip`        | -           |
| `Topology`          | `string`   | `openvpn.server[].topology`          | -           |
| `Serverbridge_dhcp` | `BoolFlag` | `openvpn.server[].serverbridge_dhcp` | -           |
| `DNS_domain`        | `string`   | `openvpn.server[].dns_domain`        | -           |
| `DNS_server1`       | `string`   | `openvpn.server[].dns_server1`       | -           |
| `DNS_server2`       | `string`   | `openvpn.server[].dns_server2`       | -           |
| `DNS_server3`       | `string`   | `openvpn.server[].dns_server3`       | -           |
| `DNS_server4`       | `string`   | `openvpn.server[].dns_server4`       | -           |
| `Push_register_dns` | `BoolFlag` | `openvpn.server[].push_register_dns` | -           |
| `NTP_server1`       | `string`   | `openvpn.server[].ntp_server1`       | -           |
| `NTP_server2`       | `string`   | `openvpn.server[].ntp_server2`       | -           |
| `Netbios_enable`    | `BoolFlag` | `openvpn.server[].netbios_enable`    | -           |
| `Netbios_ntype`     | `string`   | `openvpn.server[].netbios_ntype`     | -           |
| `Netbios_scope`     | `string`   | `openvpn.server[].netbios_scope`     | -           |
| `Verbosity_level`   | `string`   | `openvpn.server[].verbosity_level`   | -           |
| `Created`           | `string`   | `openvpn.server[].created`           | -           |
| `Updated`           | `string`   | `openvpn.server[].updated`           | -           |

### OpenVPN Client

| Field             | Type     | JSON Path                          | Description |
| ----------------- | -------- | ---------------------------------- | ----------- |
| `XMLName`         | `Name`   | `openvpn.client[].xmlname`         | -           |
| `VPN_ID`          | `string` | `openvpn.client[].vpn_id`          | -           |
| `Mode`            | `string` | `openvpn.client[].mode`            | -           |
| `Protocol`        | `string` | `openvpn.client[].protocol`        | -           |
| `Dev_mode`        | `string` | `openvpn.client[].dev_mode`        | -           |
| `Interface`       | `string` | `openvpn.client[].interface`       | -           |
| `Server_addr`     | `string` | `openvpn.client[].server_addr`     | -           |
| `Server_port`     | `string` | `openvpn.client[].server_port`     | -           |
| `Description`     | `string` | `openvpn.client[].description`     | -           |
| `Custom_options`  | `string` | `openvpn.client[].custom_options`  | -           |
| `Cert_ref`        | `string` | `openvpn.client[].cert_ref`        | -           |
| `CA_ref`          | `string` | `openvpn.client[].ca_ref`          | -           |
| `Compression`     | `string` | `openvpn.client[].compression`     | -           |
| `Verbosity_level` | `string` | `openvpn.client[].verbosity_level` | -           |
| `Created`         | `string` | `openvpn.client[].created`         | -           |
| `Updated`         | `string` | `openvpn.client[].updated`         | -           |

---

## Usage Examples

### Accessing Fields in JSON Export

```bash
# Export configuration to JSON
opndossier convert config.xml --format json -o config.json

# Extract hostname using jq
jq '.system.hostname' config.json

# List all interfaces
jq '.interfaces | keys' config.json

# Get firewall rules
jq '.filter.rule[]' config.json
```

### Accessing Fields in YAML Export

```bash
# Export configuration to YAML
opndossier convert config.xml --format yaml -o config.yaml

# Extract hostname using yq
yq '.system.hostname' config.yaml
```
