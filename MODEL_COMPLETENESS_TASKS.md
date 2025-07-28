# OPNsense Model Completeness Tasks

## Overview

This document outlines the prioritized tasks needed to complete the OPNsense Go model based on the `just completeness-check` results. The completeness check identified **1,145 missing fields** across 5 sample configuration files.

**Note**: Many "missing" fields are false positives due to dynamic interface names (wan, lan, opt0, etc.) that are handled by our map-based interface model. This document focuses on actual structural gaps.

## 📊 Completeness Check Summary

| File | Missing Fields | Priority |
|------|----------------|----------|
| sample.config.1.xml | 99 fields | High |
| sample.config.2.xml | 230 fields | High |
| sample.config.3.xml | 99 fields | High |
| sample.config.4.xml | 230 fields | High |
| sample.config.5.xml | 487 fields | Medium |

**Total Missing Fields: 1,145**

---

## 🔥 HIGH PRIORITY - Core System Fields

### 1. System Configuration (`internal/model/system.go`)

**Missing fields in System struct:**

```go
type System struct {
    // Core system fields - MOSTLY IMPLEMENTED
    Hostname string `xml:"hostname"`
    Domain string `xml:"domain"`
    DNSAllowOverride int `xml:"dnsallowoverride"`
    NextUID int `xml:"nextuid"`
    NextGID int `xml:"nextgid"`
    Timezone string `xml:"timezone"`
    TimeServers string `xml:"timeservers"`
    UseVirtualTerminal int `xml:"usevirtualterminal"`
    DisableVLANHWFilter int `xml:"disablevlanhwfilter"`
    DisableChecksumOffloading int `xml:"disablechecksumoffloading"`
    DisableSegmentationOffloading int `xml:"disablesegmentationoffloading"`
    DisableLargeReceiveOffloading int `xml:"disablelargereceiveoffloading"`
    IPv6Allow string `xml:"ipv6allow"`
    DisableNATReflection string `xml:"disablenatreflection"`
    DisableConsoleMenu struct `xml:"disableconsolemenu"`
    PFShareForward int `xml:"pf_share_forward"`
    LBUseSticky int `xml:"lb_use_sticky"`
    RRDBackup int `xml:"rrdbackup"`
    NetflowBackup int `xml:"netflowbackup"`
    Optimization string `xml:"optimization"`
    Bogons struct `xml:"bogons"`
    PowerdACMode string `xml:"powerd_ac_mode"`
    PowerdBatteryMode string `xml:"powerd_battery_mode"`
    PowerdNormalMode string `xml:"powerd_normal_mode"`

    // Missing service configurations
    NTPD NTPD `xml:"ntpd"`
    SNMPD SNMPD `xml:"snmpd"`
    RRD RRD `xml:"rrd"`
    LoadBalancer LoadBalancer `xml:"load_balancer"`
    Widgets Widgets `xml:"widgets"`
    Unbound Unbound `xml:"unbound"`
}
```

### 2. User Management (`internal/model/system.go`)

**Missing fields in User struct:**

```go
type User struct {
    Name string `xml:"name"`
    Description string `xml:"descr"`
    Scope string `xml:"scope"`
    GroupName string `xml:"groupname"`
    Password string `xml:"password"`
    UID int `xml:"uid"`
    APIKeys APIKeys `xml:"apikeys,omitempty"`
    Expires struct `xml:"expires,omitempty"`
    AuthorizedKeys struct `xml:"authorizedkeys,omitempty"`
    IPSecPSK struct `xml:"ipsecpsk,omitempty"`
    OTPSeed struct `xml:"otp_seed,omitempty"`
}

type APIKeys struct {
    Items []APIKeyItem `xml:"item"`
}

type APIKeyItem struct {
    Key string `xml:"key"`
    Secret string `xml:"secret"`
    Privileges string `xml:"privileges,omitempty"`
    Priv string `xml:"priv,omitempty"`
    Scope string `xml:"scope,omitempty"`
    UID int `xml:"uid,omitempty"`
    GID int `xml:"gid,omitempty"`
    Description string `xml:"descr,omitempty"`
    CTime int64 `xml:"ctime,omitempty"`
    MTime int64 `xml:"mtime,omitempty"`
    CTimeUSec int `xml:"ctime_usec,omitempty"`
    MTimeUSec int `xml:"mtime_usec,omitempty"`
    CTimeNSec int `xml:"ctime_nsec,omitempty"`
    MTimeNSec int `xml:"mtime_nsec,omitempty"`
    CTimeSec int64 `xml:"ctime_sec,omitempty"`
    MTimeSec int64 `xml:"mtime_sec,omitempty"`
}
```

### 3. Group Management (`internal/model/system.go`)

**Missing fields in Group struct:**

```go
type Group struct {
    Name string `xml:"name"`
    Description string `xml:"description"`
    Scope string `xml:"scope"`
    GID int `xml:"gid"`
    Member int `xml:"member"`
    Priv string `xml:"priv"`
}
```

### 4. WebGUI Configuration (`internal/model/system.go`)

**Missing WebGUI struct:**

```go
type WebGUI struct {
    Protocol string `xml:"protocol"`
    SSLCertRef string `xml:"ssl-certref,omitempty"`
}
```

### 5. SSH Configuration (`internal/model/system.go`)

**Missing SSH struct:**

```go
type SSH struct {
    Group struct `xml:"group"`
}
```

### 6. Firmware Configuration (`internal/model/system.go`)

**Missing Firmware struct:**

```go
type Firmware struct {
    Mirror struct `xml:"mirror"`
    Flavour struct `xml:"flavour"`
    Plugins string `xml:"plugins"`
    Type struct `xml:"type,omitempty"`
    Subscription struct `xml:"subscription,omitempty"`
    Reboot struct `xml:"reboot,omitempty"`
    Version string `xml:"version,attr"`
}
```

---

## 🔥 HIGH PRIORITY - Core Services

### 7. Sysctl Configuration (`internal/model/system.go`)

**Missing Sysctl struct:**

```go
type Sysctl struct {
    Items []SysctlItem `xml:"item"`
}

type SysctlItem struct {
    Description string `xml:"descr"`
    Tunable string `xml:"tunable"`
    Value string `xml:"value"`
    Key string `xml:"key"`
    Secret string `xml:"secret"`
}
```

### 8. SNMP Configuration (`internal/model/system.go`)

**Missing SNMPD struct:**

```go
type SNMPD struct {
    SysLocation struct `xml:"syslocation"`
    SysContact struct `xml:"syscontact"`
    ROCommunity string `xml:"rocommunity"`
}
```

### 9. NTP Configuration (`internal/model/system.go`)

**Missing NTPD struct:**

```go
type NTPD struct {
    Prefer string `xml:"prefer"`
}
```

### 10. RRD Configuration (`internal/model/system.go`)

**Missing RRD struct:**

```go
type RRD struct {
    Enable string `xml:"enable"`
}
```

### 11. Load Balancer Configuration (`internal/model/system.go`)

**Missing LoadBalancer struct:**

```go
type LoadBalancer struct {
    MonitorTypes []MonitorType `xml:"monitor_type"`
}

type MonitorType struct {
    Name string `xml:"name"`
    Type string `xml:"type"`
    Description string `xml:"descr"`
    Options MonitorOptions `xml:"options"`
}

type MonitorOptions struct {
    Path string `xml:"path,omitempty"`
    Host struct `xml:"host,omitempty"`
    Code int `xml:"code,omitempty"`
    Send struct `xml:"send,omitempty"`
    Expect string `xml:"expect,omitempty"`
}
```

### 12. Widgets Configuration (`internal/model/system.go`)

**Missing Widgets struct:**

```go
type Widgets struct {
    Sequence string `xml:"sequence"`
    ColumnCount int `xml:"column_count"`
}
```

---

## 🔥 HIGH PRIORITY - Security & Network

### 13. Filter Configuration (`internal/model/security.go`)

**Missing Filter struct:**

```go
type Filter struct {
    Rules []FilterRule `xml:"rule"`
}

type FilterRule struct {
    Type string `xml:"type"`
    Description string `xml:"descr"`
    Interface string `xml:"interface"`
    IPProtocol string `xml:"ipprotocol"`
    StateType string `xml:"statetype"`
    Direction string `xml:"direction"`
    Quick int `xml:"quick"`
    Protocol string `xml:"protocol"`
    Source FilterSource `xml:"source"`
    Destination FilterDestination `xml:"destination"`
    Updated FilterUpdate `xml:"updated,omitempty"`
    Created FilterUpdate `xml:"created,omitempty"`
    UUID string `xml:"uuid,attr"`
}

type FilterSource struct {
    Any string `xml:"any,omitempty"`
    Network string `xml:"network,omitempty"`
}

type FilterDestination struct {
    Any string `xml:"any,omitempty"`
    Network string `xml:"network,omitempty"`
    Port int `xml:"port,omitempty"`
}

type FilterUpdate struct {
    Username string `xml:"username"`
    Time float64 `xml:"time"`
    Description string `xml:"description"`
}
```

### 14. NAT Configuration (`internal/model/security.go`)

**Missing NAT struct:**

```go
type NAT struct {
    Outbound NATOutbound `xml:"outbound"`
}

type NATOutbound struct {
    Mode string `xml:"mode"`
}
```

### 15. Gateways Configuration (`internal/model/network.go`)

**Missing Gateway fields:**

```go
type GatewayItem struct {
    Description string `xml:"descr"`
    DefaultGW int `xml:"defaultgw"`
    IPProtocol string `xml:"ipprotocol"`
    Interface string `xml:"interface"`
    Gateway string `xml:"gateway"`
    MonitorDisable int `xml:"monitor_disable"`
    Name string `xml:"name"`
    Interval string `xml:"interval"`
    Weight int `xml:"weight"`
    FarGW int `xml:"fargw"`
}
```

---

## 🟡 MEDIUM PRIORITY - OPNsense Advanced Features

### 16. OPNsense Core Features (`internal/model/opnsense.go`)

**Missing OPNsense struct fields:**

```go
type OPNsense struct {
    CaptivePortal struct `xml:"captiveportal"`
    Cron struct `xml:"cron"`
    Firewall struct `xml:"Firewall"`
    Netflow struct `xml:"Netflow"`
    IDS struct `xml:"IDS"`
    IPsec struct `xml:"IPsec"`
    Swanctl struct `xml:"Swanctl"`
    Interfaces struct `xml:"Interfaces"`
    Kea struct `xml:"Kea"`
    Monit struct `xml:"monit"`
    OpenVPNExport struct `xml:"OpenVPNExport"`
    OpenVPN struct `xml:"OpenVPN"`
    Gateways struct `xml:"Gateways"`
    Syslog struct `xml:"Syslog"`
    TrafficShaper struct `xml:"TrafficShaper"`
    Trust struct `xml:"trust"`
    UnboundPlus struct `xml:"unboundplus"`
    WireGuard WireGuard `xml:"wireguard"`
}
```

### 17. WireGuard Configuration (`internal/model/vpn.go`)

**Missing WireGuard structs:**

```go
type WireGuard struct {
    General WireGuardGeneral `xml:"general"`
    Servers WireGuardServers `xml:"server"`
    Clients WireGuardClients `xml:"client"`
}

type WireGuardGeneral struct {
    Enabled string `xml:"enabled"`
}

type WireGuardServers struct {
    Servers []WireGuardServer `xml:"server"`
}

type WireGuardServer struct {
    Enabled string `xml:"enabled"`
    Name string `xml:"name"`
    Instance int `xml:"instance"`
    PubKey string `xml:"pubkey"`
    PrivKey string `xml:"privkey"`
    Port int `xml:"port"`
    MTU struct `xml:"mtu"`
    DNS struct `xml:"dns"`
    TunnelAddress string `xml:"tunneladdress"`
    DisableRoutes int `xml:"disableroutes"`
    Gateway string `xml:"gateway"`
    Peers string `xml:"peers"`
    UUID string `xml:"uuid,attr"`
    Version string `xml:"version,attr"`
}

type WireGuardClients struct {
    Clients []WireGuardClient `xml:"client"`
}

type WireGuardClient struct {
    Enabled string `xml:"enabled"`
    Name string `xml:"name"`
    PubKey string `xml:"pubkey"`
    PSK struct `xml:"psk"`
    TunnelAddress string `xml:"tunneladdress"`
    ServerAddress struct `xml:"serveraddress"`
    ServerPort struct `xml:"serverport"`
    KeepAlive struct `xml:"keepalive"`
    UUID string `xml:"uuid,attr"`
    Version string `xml:"version,attr"`
}
```

### 18. Unbound Configuration (`internal/model/system.go`)

**Missing Unbound struct:**

```go
type Unbound struct {
    Enable string `xml:"enable"`
    DNSSEC string `xml:"dnssec,omitempty"`
    DNSSECStripped string `xml:"dnssecstripped,omitempty"`
}
```

---

## 🟢 LOW PRIORITY - Advanced Features

### 19. Advanced DHCP Configuration (`internal/model/dhcp.go`)

**Missing advanced DHCP fields:**

```go
type DHCPLAN struct {
    // ... existing fields ...

    // Advanced DHCP fields
    AliasAddress struct `xml:"alias-address,omitempty"`
    AliasSubnet int `xml:"alias-subnet,omitempty"`
    DHCPRejectFrom struct `xml:"dhcprejectfrom,omitempty"`

    // Advanced DHCP options
    AdvDHCPPTTimeout struct `xml:"adv_dhcp_pt_timeout,omitempty"`
    AdvDHCPPTRetry struct `xml:"adv_dhcp_pt_retry,omitempty"`
    AdvDHCPPTSelectTimeout struct `xml:"adv_dhcp_pt_select_timeout,omitempty"`
    AdvDHCPPTReboot struct `xml:"adv_dhcp_pt_reboot,omitempty"`
    AdvDHCPPTBackoffCutoff struct `xml:"adv_dhcp_pt_backoff_cutoff,omitempty"`
    AdvDHCPPTInitialInterval struct `xml:"adv_dhcp_pt_initial_interval,omitempty"`
    AdvDHCPPTValues string `xml:"adv_dhcp_pt_values,omitempty"`
    AdvDHCPSendOptions struct `xml:"adv_dhcp_send_options,omitempty"`
    AdvDHCPRequestOptions struct `xml:"adv_dhcp_request_options,omitempty"`
    AdvDHCPRequiredOptions struct `xml:"adv_dhcp_required_options,omitempty"`
    AdvDHCPOptionModifiers struct `xml:"adv_dhcp_option_modifiers,omitempty"`
    AdvDHCPConfigAdvanced struct `xml:"adv_dhcp_config_advanced,omitempty"`
    AdvDHCPConfigFileOverride struct `xml:"adv_dhcp_config_file_override,omitempty"`
    AdvDHCPConfigFileOverridePath struct `xml:"adv_dhcp_config_file_override_path,omitempty"`

    // Advanced DHCPv6 fields
    Track6Interface string `xml:"track6-interface,omitempty"`
    Track6PrefixID int `xml:"track6-prefix-id,omitempty"`
    AdvDHCP6InterfaceStatementSendOptions struct `xml:"adv_dhcp6_interface_statement_send_options,omitempty"`
    AdvDHCP6InterfaceStatementRequestOptions struct `xml:"adv_dhcp6_interface_statement_request_options,omitempty"`
    AdvDHCP6InterfaceStatementInformationOnlyEnable struct `xml:"adv_dhcp6_interface_statement_information_only_enable,omitempty"`
    AdvDHCP6InterfaceStatementScript struct `xml:"adv_dhcp6_interface_statement_script,omitempty"`
    AdvDHCP6IDAssocStatementAddressEnable struct `xml:"adv_dhcp6_id_assoc_statement_address_enable,omitempty"`
    AdvDHCP6IDAssocStatementAddress struct `xml:"adv_dhcp6_id_assoc_statement_address,omitempty"`
    AdvDHCP6IDAssocStatementAddressID struct `xml:"adv_dhcp6_id_assoc_statement_address_id,omitempty"`
    AdvDHCP6IDAssocStatementAddressPLTime struct `xml:"adv_dhcp6_id_assoc_statement_address_pltime,omitempty"`
    AdvDHCP6IDAssocStatementAddressVLTime struct `xml:"adv_dhcp6_id_assoc_statement_address_vltime,omitempty"`
    AdvDHCP6IDAssocStatementPrefixEnable struct `xml:"adv_dhcp6_id_assoc_statement_prefix_enable,omitempty"`
    AdvDHCP6IDAssocStatementPrefix struct `xml:"adv_dhcp6_id_assoc_statement_prefix,omitempty"`
    AdvDHCP6IDAssocStatementPrefixID struct `xml:"adv_dhcp6_id_assoc_statement_prefix_id,omitempty"`
    AdvDHCP6IDAssocStatementPrefixPLTime struct `xml:"adv_dhcp6_id_assoc_statement_prefix_pltime,omitempty"`
    AdvDHCP6IDAssocStatementPrefixVLTime struct `xml:"adv_dhcp6_id_assoc_statement_prefix_vltime,omitempty"`
    AdvDHCP6PrefixInterfaceStatementSLALen struct `xml:"adv_dhcp6_prefix_interface_statement_sla_len,omitempty"`
    AdvDHCP6AuthenticationStatementAuthName struct `xml:"adv_dhcp6_authentication_statement_authname,omitempty"`
    AdvDHCP6AuthenticationStatementProtocol struct `xml:"adv_dhcp6_authentication_statement_protocol,omitempty"`
    AdvDHCP6AuthenticationStatementAlgorithm struct `xml:"adv_dhcp6_authentication_statement_algorithm,omitempty"`
    AdvDHCP6AuthenticationStatementRDM struct `xml:"adv_dhcp6_authentication_statement_rdm,omitempty"`
    AdvDHCP6KeyInfoStatementKeyName struct `xml:"adv_dhcp6_key_info_statement_keyname,omitempty"`
    AdvDHCP6KeyInfoStatementRealm struct `xml:"adv_dhcp6_key_info_statement_realm,omitempty"`
    AdvDHCP6KeyInfoStatementKeyID struct `xml:"adv_dhcp6_key_info_statement_keyid,omitempty"`
    AdvDHCP6KeyInfoStatementSecret struct `xml:"adv_dhcp6_key_info_statement_secret,omitempty"`
    AdvDHCP6KeyInfoStatementExpire struct `xml:"adv_dhcp6_key_info_statement_expire,omitempty"`
    AdvDHCP6ConfigAdvanced struct `xml:"adv_dhcp6_config_advanced,omitempty"`
    AdvDHCP6ConfigFileOverride struct `xml:"adv_dhcp6_config_file_override,omitempty"`
    AdvDHCP6ConfigFileOverridePath struct `xml:"adv_dhcp6_config_file_override_path,omitempty"`
}
```

### 20. Revision Tracking (`internal/model/revision.go`)

**Missing Revision struct:**

```go
type Revision struct {
    Username string `xml:"username"`
    Time float64 `xml:"time"`
    Description string `xml:"description"`
}
```

---

## 📋 Implementation Strategy

### Phase 1: Core System (Weeks 1-2)

1. **System Configuration** - Add hostname, domain, timezone, etc.
2. **User Management** - Complete user and group structures
3. **Core Services** - Add missing service configurations (NTPD, SNMPD, RRD, etc.)

### Phase 2: Security & Network (Weeks 3-4)

1. **Filter Configuration** - Firewall rules
2. **NAT Configuration** - Network address translation
3. **Gateways Configuration** - Routing configuration
4. **Widgets Configuration** - Dashboard widgets

### Phase 3: Advanced Features (Weeks 5-6)

1. **OPNsense Core Features** - Advanced firewall features
2. **WireGuard Configuration** - VPN configuration
3. **Unbound Configuration** - DNS resolver
4. **Revision Tracking** - Configuration history

### Phase 4: Advanced DHCP (Weeks 7-8)

1. **Advanced DHCP Configuration** - Complex DHCP options
2. **Advanced DHCPv6 Configuration** - IPv6 DHCP options

---

## 🎯 Success Metrics

- **Phase 1**: Reduce missing fields by 60% (from 1,145 to ~458)
- **Phase 2**: Reduce missing fields by 80% (from 1,145 to ~229)
- **Phase 3**: Reduce missing fields by 90% (from 1,145 to ~115)
- **Phase 4**: Complete model (0 missing fields)

---

## 🔧 Implementation Guidelines

### Code Quality Standards

- Follow existing Go naming conventions
- Maintain XML tag compatibility
- Add proper validation tags
- Include comprehensive documentation
- Write unit tests for new structs

### Testing Requirements

- Run `just completeness-check` after each phase
- Ensure `just ci-check` passes
- Verify XML marshaling/unmarshaling works
- Test with sample configuration files

### Documentation Requirements

- Add field descriptions in comments
- Update README with new features
- Document validation rules
- Provide usage examples

---

## 📝 Notes

- **XML Compatibility**: All XML tags must remain unchanged for backward compatibility
- **Validation**: Add appropriate validation tags for required fields
- **Testing**: Each phase should be tested independently
- **Documentation**: Update documentation as new fields are added
- **Performance**: Monitor impact on parsing performance
- **Dynamic Interfaces**: The model uses map-based interfaces for dynamic interface names (wan, lan, opt0, etc.)

This task list prioritizes the most commonly missing fields based on the completeness check results, focusing on core system functionality first, then expanding to advanced features.
