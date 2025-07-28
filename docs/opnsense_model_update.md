# OPNsense Model Update Design

This document outlines the design for updating OPNsense configuration models to support comprehensive firewall configuration management.

## Go Additions Design

### Overview

This section details the new Go structs, field additions, and helper types needed to support comprehensive OPNsense configuration parsing and management. The design follows Go naming conventions and XML marshaling best practices.

### New Root-Level Structs

#### Network Infrastructure Structs

```go
// Vlans represents VLAN configuration
type Vlans struct {
    XMLName xml.Name `xml:"vlans"`
    Vlan    []Vlan   `xml:"vlan,omitempty"`
}

type Vlan struct {
    XMLName     xml.Name `xml:"vlan"`
    If          string   `xml:"if,omitempty"`
    Tag         string   `xml:"tag,omitempty"`
    Descr       string   `xml:"descr,omitempty"`
    Vlanif      string   `xml:"vlanif,omitempty"`
    Created     string   `xml:"created,omitempty"`
    Updated     string   `xml:"updated,omitempty"`
}

// Bridges represents bridge interface configuration
type Bridges struct {
    XMLName xml.Name `xml:"bridges"`
    Bridge  []Bridge `xml:"bridge,omitempty"`
}

type Bridge struct {
    XMLName     xml.Name `xml:"bridge"`
    Members     string   `xml:"members,omitempty"`
    Descr       string   `xml:"descr,omitempty"`
    Bridgeif    string   `xml:"bridgeif,omitempty"`
    STP         BoolFlag `xml:"stp,omitempty"`
    Created     string   `xml:"created,omitempty"`
    Updated     string   `xml:"updated,omitempty"`
}

// Gateways represents gateway configuration
type Gateways struct {
    XMLName     xml.Name       `xml:"gateways"`
    Gateway     []Gateway      `xml:"gateway_item,omitempty"`
    Groups      []GatewayGroup `xml:"gateway_group,omitempty"`
}

type Gateway struct {
    XMLName     xml.Name `xml:"gateway_item"`
    Interface   string   `xml:"interface,omitempty"`
    Gateway     string   `xml:"gateway,omitempty"`
    Name        string   `xml:"name,omitempty"`
    Weight      string   `xml:"weight,omitempty"`
    IPProtocol  string   `xml:"ipprotocol,omitempty"`
    Interval    string   `xml:"interval,omitempty"`
    Descr       string   `xml:"descr,omitempty"`
    Monitor     string   `xml:"monitor,omitempty"`
    Disabled    BoolFlag `xml:"disabled,omitempty"`
    Created     string   `xml:"created,omitempty"`
    Updated     string   `xml:"updated,omitempty"`
}

type GatewayGroup struct {
    XMLName  xml.Name `xml:"gateway_group"`
    Name     string   `xml:"name,omitempty"`
    Item     []string `xml:"item,omitempty"`
    Trigger  string   `xml:"trigger,omitempty"`
    Descr    string   `xml:"descr,omitempty"`
}

// StaticRoutes represents static routing configuration
type StaticRoutes struct {
    XMLName xml.Name      `xml:"staticroutes"`
    Route   []StaticRoute `xml:"route,omitempty"`
}

type StaticRoute struct {
    XMLName     xml.Name `xml:"route"`
    Network     string   `xml:"network,omitempty"`
    Gateway     string   `xml:"gateway,omitempty"`
    Descr       string   `xml:"descr,omitempty"`
    Disabled    BoolFlag `xml:"disabled,omitempty"`
    Created     string   `xml:"created,omitempty"`
    Updated     string   `xml:"updated,omitempty"`
}
```

#### System Service Structs

```go
// OPNsense represents the main OPNsense system configuration
type OPNsense struct {
    XMLName         xml.Name         `xml:"opnsense"`
    Captiveportal   *Captiveportal   `xml:"captiveportal,omitempty"`
    Cron            *Cron            `xml:"cron,omitempty"`
    Firmware        *Firmware        `xml:"firmware,omitempty"`
    IDS             *IDS             `xml:"ids,omitempty"`
    Interfaces      *Interfaces      `xml:"interfaces,omitempty"`
    IPsec           *IPsec           `xml:"ipsec,omitempty"`
    Monit           *Monit           `xml:"monit,omitempty"`
    OpenVPN         *OpenVPN         `xml:"openvpn,omitempty"`
    Routes          *Routes          `xml:"routes,omitempty"`
    TrafficShaper   *TrafficShaper   `xml:"trafficshaper,omitempty"`
    UnboundDNS      *UnboundDNS      `xml:"unbound,omitempty"`
    Created         string           `xml:"created,omitempty"`
    Updated         string           `xml:"updated,omitempty"`
}

// DNSMasq represents DNS masquerading configuration
type DNSMasq struct {
    XMLName         xml.Name        `xml:"dnsmasq"`
    Enable          BoolFlag        `xml:"enable,omitempty"`
    Regdhcp         BoolFlag        `xml:"regdhcp,omitempty"`
    Regdhcpstatic   BoolFlag        `xml:"regdhcpstatic,omitempty"`
    Dhcpfirst       BoolFlag        `xml:"dhcpfirst,omitempty"`
    Strict_order    BoolFlag        `xml:"strict_order,omitempty"`
    Domain_needed   BoolFlag        `xml:"domain_needed,omitempty"`
    No_private_reverse BoolFlag     `xml:"no_private_reverse,omitempty"`
    Port            string          `xml:"port,omitempty"`
    Custom_options  string          `xml:"custom_options,omitempty"`
    Hosts           []DNSMasqHost   `xml:"hosts>host,omitempty"`
    DomainOverrides []DomainOverride `xml:"domainoverrides>domainoverride,omitempty"`
    Created         string          `xml:"created,omitempty"`
    Updated         string          `xml:"updated,omitempty"`
}

type DNSMasqHost struct {
    XMLName xml.Name `xml:"host"`
    Host    string   `xml:"host,omitempty"`
    Domain  string   `xml:"domain,omitempty"`
    IP      string   `xml:"ip,omitempty"`
    Descr   string   `xml:"descr,omitempty"`
    Aliases []string `xml:"aliases,omitempty"`
}

type DomainOverride struct {
    XMLName xml.Name `xml:"domainoverride"`
    Domain  string   `xml:"domain,omitempty"`
    IP      string   `xml:"ip,omitempty"`
    Descr   string   `xml:"descr,omitempty"`
}

// OpenVPN represents OpenVPN configuration
type OpenVPN struct {
    XMLName      xml.Name          `xml:"openvpn"`
    Servers      []OpenVPNServer   `xml:"openvpn-server,omitempty"`
    Clients      []OpenVPNClient   `xml:"openvpn-client,omitempty"`
    ClientExport *ClientExport     `xml:"openvpn-client-export,omitempty"`
    CSC          []OpenVPNCSC      `xml:"openvpn-csc,omitempty"`
    Created      string            `xml:"created,omitempty"`
    Updated      string            `xml:"updated,omitempty"`
}

type OpenVPNServer struct {
    XMLName         xml.Name `xml:"openvpn-server"`
    VPN_ID          string   `xml:"vpnid,omitempty"`
    Mode            string   `xml:"mode,omitempty"`
    Protocol        string   `xml:"protocol,omitempty"`
    Dev_mode        string   `xml:"dev_mode,omitempty"`
    Interface       string   `xml:"interface,omitempty"`
    Local_port      string   `xml:"local_port,omitempty"`
    Description     string   `xml:"description,omitempty"`
    Custom_options  string   `xml:"custom_options,omitempty"`
    TLS             string   `xml:"tls,omitempty"`
    TLS_type        string   `xml:"tls_type,omitempty"`
    Cert_ref        string   `xml:"certref,omitempty"`
    CA_ref          string   `xml:"caref,omitempty"`
    CRL_ref         string   `xml:"crlref,omitempty"`
    DH_length       string   `xml:"dh_length,omitempty"`
    Ecdh_curve      string   `xml:"ecdh_curve,omitempty"`
    Cert_depth      string   `xml:"cert_depth,omitempty"`
    Strictusercn    BoolFlag `xml:"strictusercn,omitempty"`
    Tunnel_network  string   `xml:"tunnel_network,omitempty"`
    Tunnel_networkv6 string  `xml:"tunnel_networkv6,omitempty"`
    Remote_network  string   `xml:"remote_network,omitempty"`
    Remote_networkv6 string  `xml:"remote_networkv6,omitempty"`
    Gwredir         BoolFlag `xml:"gwredir,omitempty"`
    Local_network   string   `xml:"local_network,omitempty"`
    Local_networkv6 string   `xml:"local_networkv6,omitempty"`
    Maxclients      string   `xml:"maxclients,omitempty"`
    Compression     string   `xml:"compression,omitempty"`
    Passtos         BoolFlag `xml:"passtos,omitempty"`
    Client2client   BoolFlag `xml:"client2client,omitempty"`
    Dynamic_ip      BoolFlag `xml:"dynamic_ip,omitempty"`
    Topology        string   `xml:"topology,omitempty"`
    Serverbridge_dhcp BoolFlag `xml:"serverbridge_dhcp,omitempty"`
    DNS_domain      string   `xml:"dns_domain,omitempty"`
    DNS_server1     string   `xml:"dns_server1,omitempty"`
    DNS_server2     string   `xml:"dns_server2,omitempty"`
    DNS_server3     string   `xml:"dns_server3,omitempty"`
    DNS_server4     string   `xml:"dns_server4,omitempty"`
    Push_register_dns BoolFlag `xml:"push_register_dns,omitempty"`
    NTP_server1     string   `xml:"ntp_server1,omitempty"`
    NTP_server2     string   `xml:"ntp_server2,omitempty"`
    Netbios_enable  BoolFlag `xml:"netbios_enable,omitempty"`
    Netbios_ntype   string   `xml:"netbios_ntype,omitempty"`
    Netbios_scope   string   `xml:"netbios_scope,omitempty"`
    Verbosity_level string   `xml:"verbosity_level,omitempty"`
    Created         string   `xml:"created,omitempty"`
    Updated         string   `xml:"updated,omitempty"`
}

type OpenVPNClient struct {
    XMLName         xml.Name `xml:"openvpn-client"`
    VPN_ID          string   `xml:"vpnid,omitempty"`
    Mode            string   `xml:"mode,omitempty"`
    Protocol        string   `xml:"protocol,omitempty"`
    Dev_mode        string   `xml:"dev_mode,omitempty"`
    Interface       string   `xml:"interface,omitempty"`
    Server_addr     string   `xml:"server_addr,omitempty"`
    Server_port     string   `xml:"server_port,omitempty"`
    Description     string   `xml:"description,omitempty"`
    Custom_options  string   `xml:"custom_options,omitempty"`
    Cert_ref        string   `xml:"certref,omitempty"`
    CA_ref          string   `xml:"caref,omitempty"`
    Compression     string   `xml:"compression,omitempty"`
    Verbosity_level string   `xml:"verbosity_level,omitempty"`
    Created         string   `xml:"created,omitempty"`
    Updated         string   `xml:"updated,omitempty"`
}

type ClientExport struct {
    XMLName                 xml.Name `xml:"openvpn-client-export"`
    Server_list             []string `xml:"server_list,omitempty"`
    Hostname                string   `xml:"hostname,omitempty"`
    Random_local_port       BoolFlag `xml:"random_local_port,omitempty"`
    Silent_install          BoolFlag `xml:"silent_install,omitempty"`
    Use_token               BoolFlag `xml:"use_token,omitempty"`
}

type OpenVPNCSC struct {
    XMLName         xml.Name `xml:"openvpn-csc"`
    Common_name     string   `xml:"common_name,omitempty"`
    Description     string   `xml:"description,omitempty"`
    Block           BoolFlag `xml:"block,omitempty"`
    Tunnel_network  string   `xml:"tunnel_network,omitempty"`
    Tunnel_networkv6 string  `xml:"tunnel_networkv6,omitempty"`
    Local_network   string   `xml:"local_network,omitempty"`
    Local_networkv6 string   `xml:"local_networkv6,omitempty"`
    Remote_network  string   `xml:"remote_network,omitempty"`
    Remote_networkv6 string  `xml:"remote_networkv6,omitempty"`
    Gwredir         BoolFlag `xml:"gwredir,omitempty"`
    Push_reset      BoolFlag `xml:"push_reset,omitempty"`
    Remove_route    BoolFlag `xml:"remove_route,omitempty"`
    DNS_domain      string   `xml:"dns_domain,omitempty"`
    DNS_server1     string   `xml:"dns_server1,omitempty"`
    DNS_server2     string   `xml:"dns_server2,omitempty"`
    DNS_server3     string   `xml:"dns_server3,omitempty"`
    DNS_server4     string   `xml:"dns_server4,omitempty"`
    NTP_server1     string   `xml:"ntp_server1,omitempty"`
    NTP_server2     string   `xml:"ntp_server2,omitempty"`
    Custom_options  string   `xml:"custom_options,omitempty"`
    Created         string   `xml:"created,omitempty"`
    Updated         string   `xml:"updated,omitempty"`
}

// Syslog represents system logging configuration
type Syslog struct {
    XMLName         xml.Name      `xml:"syslog"`
    Reverse         []string      `xml:"reverse,omitempty"`
    Nentries        string        `xml:"nentries,omitempty"`
    Remoteserver    string        `xml:"remoteserver,omitempty"`
    Remoteserver2   string        `xml:"remoteserver2,omitempty"`
    Remoteserver3   string        `xml:"remoteserver3,omitempty"`
    Sourceip        string        `xml:"sourceip,omitempty"`
    IPProtocol      string        `xml:"ipprotocol,omitempty"`
    Filter          BoolFlag      `xml:"filter,omitempty"`
    Dhcp            BoolFlag      `xml:"dhcp,omitempty"`
    Auth            BoolFlag      `xml:"auth,omitempty"`
    Portalauth      BoolFlag      `xml:"portalauth,omitempty"`
    VPN             BoolFlag      `xml:"vpn,omitempty"`
    DPinger         BoolFlag      `xml:"dpinger,omitempty"`
    Hostapd         BoolFlag      `xml:"hostapd,omitempty"`
    System          BoolFlag      `xml:"system,omitempty"`
    Resolver        BoolFlag      `xml:"resolver,omitempty"`
    PPP             BoolFlag      `xml:"ppp,omitempty"`
    Enable          BoolFlag      `xml:"enable,omitempty"`
    LogFilesize     string        `xml:"logfilesize,omitempty"`
    RotateCount     string        `xml:"rotatecount,omitempty"`
    Format          string        `xml:"format,omitempty"`
    IgmpProxy       BoolFlag      `xml:"igmpproxy,omitempty"`
    Created         string        `xml:"created,omitempty"`
    Updated         string        `xml:"updated,omitempty"`
}
```

### Field Additions to Existing Structs

#### System Struct Additions

```go
// Additional fields for System struct
type System struct {
    // ... existing fields ...

    // Timezone and locale
    Timezone            string      `xml:"timezone,omitempty"`
    Language            string      `xml:"language,omitempty"`

    // Advanced system settings
    Serialspeed         string      `xml:"serialspeed,omitempty"`
    Primaryconsole      string      `xml:"primaryconsole,omitempty"`
    Secondaryconsole    string      `xml:"secondaryconsole,omitempty"`

    // Network optimization
    Optimization        string      `xml:"optimization,omitempty"`
    MaxProcesses        string      `xml:"maximumprocesses,omitempty"`
    MaxStates           string      `xml:"maximumstates,omitempty"`
    MaxFragments        string      `xml:"maximumfrags,omitempty"`

    // Power management
    PowerdEnable        BoolFlag    `xml:"powerd_enable,omitempty"`
    PowerdOnAC          string      `xml:"powerd_ac_mode,omitempty"`
    PowerdOnBattery     string      `xml:"powerd_battery_mode,omitempty"`
    PowerdOnUnknown     string      `xml:"powerd_unknown_mode,omitempty"`

    // Hardware settings
    CryptoHardware      string      `xml:"crypto_hardware,omitempty"`
    ThermalHardware     string      `xml:"thermal_hardware,omitempty"`

    // SSH Configuration
    SSH                 *SSH        `xml:"ssh,omitempty"`

    // Change tracking
    ChangeMeta          ChangeMeta  `xml:",inline"`
}

type SSH struct {
    XMLName     xml.Name `xml:"ssh"`
    Enable      BoolFlag `xml:"enable,omitempty"`
    Port        string   `xml:"port,omitempty"`
    Interfaces  []string `xml:"interfaces>interface,omitempty"`
    Permit_root BoolFlag `xml:"permitrootlogin,omitempty"`
    PasswordAuth BoolFlag `xml:"passwordauth,omitempty"`
    Group       string   `xml:"group,omitempty"`
}
```

#### FilterRule Struct Additions

```go
// Additional fields for FilterRule struct
type FilterRule struct {
    // ... existing fields ...

    // Enhanced rule metadata
    Tracker             string          `xml:"tracker,omitempty"`
    Associated_rule_id  string          `xml:"associated-rule-id,omitempty"`
    Max_states          string          `xml:"max-states,omitempty"`
    Max_src_states      string          `xml:"max-src-states,omitempty"`
    Max_src_conn        string          `xml:"max-src-conn,omitempty"`
    Max_src_conn_rate   string          `xml:"max-src-conn-rate,omitempty"`
    Max_src_conn_rates  string          `xml:"max-src-conn-rates,omitempty"`
    Statetimeout        string          `xml:"statetimeout,omitempty"`

    // Advanced rule options
    Statetype           string          `xml:"statetype,omitempty"`
    Os                  string          `xml:"os,omitempty"`
    Gateway             string          `xml:"gateway,omitempty"`
    Sched               string          `xml:"sched,omitempty"`
    Floating            BoolFlag        `xml:"floating,omitempty"`
    Direction           string          `xml:"direction,omitempty"`
    Quick               BoolFlag        `xml:"quick,omitempty"`

    // Enhanced location specification
    SourceLocation      RuleLocation    `xml:"source"`
    DestinationLocation RuleLocation    `xml:"destination"`

    // Rule creation/modification tracking
    ChangeMeta          ChangeMeta      `xml:",inline"`
}
```

#### NAT Struct Additions

```go
// Additional fields for NAT struct
type Nat struct {
    // ... existing fields ...

    // Advanced NAT options
    Associated_rule_id  string          `xml:"associated-rule-id,omitempty"`
    No_rdr              BoolFlag        `xml:"nordr,omitempty"`
    Nosync              BoolFlag        `xml:"nosync,omitempty"`
    Poolopts            string          `xml:"poolopts,omitempty"`
    Source_hash_key     string          `xml:"source_hash_key,omitempty"`
    Static_nat_port     BoolFlag        `xml:"staticnatport,omitempty"`

    // Enhanced location specification
    SourceLocation      RuleLocation    `xml:"source"`
    DestinationLocation RuleLocation    `xml:"destination"`

    // Change tracking
    ChangeMeta          ChangeMeta      `xml:",inline"`
}
```

#### DHCP Struct Additions

```go
// Additional fields for DHCP structs
type Dhcp struct {
    // ... existing fields ...

    // DHCP Server advanced options
    Ignore_client_uids      BoolFlag        `xml:"ignoreclientuids,omitempty"`
    Ignore_bootp            BoolFlag        `xml:"ignorebootp,omitempty"`
    No_ping_check           BoolFlag        `xml:"nopingcheck,omitempty"`
    Dhcp_lease_time         string          `xml:"dhcpleaseinlocaltime,omitempty"`
    Always_broadcast        BoolFlag        `xml:"alwaysbroadcast,omitempty"`
    Static_arp              BoolFlag        `xml:"staticarp,omitempty"`

    // DNS and WINS settings
    DNS_servers             []string        `xml:"dnsserver,omitempty"`
    Wins_servers            []string        `xml:"winsserver,omitempty"`
    NTP_servers             []string        `xml:"ntpserver,omitempty"`
    TFTP_server             string          `xml:"tftpserver,omitempty"`
    LDAP_server             string          `xml:"ldapserver,omitempty"`

    // Custom DHCP options
    NumberOptions           []DHCPOption    `xml:"numberoptions>item,omitempty"`

    // Change tracking
    ChangeMeta              ChangeMeta      `xml:",inline"`
}

type DHCPOption struct {
    XMLName xml.Name `xml:"item"`
    Number  string   `xml:"number,omitempty"`
    Type    string   `xml:"type,omitempty"`
    Value   string   `xml:"value,omitempty"`
}

type DHCPStaticMapping struct {
    // ... existing fields ...

    // Advanced static mapping options
    ARP_table_static_entry  BoolFlag    `xml:"arp-table-static-entry,omitempty"`

    // Change tracking
    ChangeMeta              ChangeMeta  `xml:",inline"`
}

type DHCPv6 struct {
    // ... existing fields ...

    // DHCPv6 specific options
    Mode                    string      `xml:"mode,omitempty"`
    Range_from              string      `xml:"range>from,omitempty"`
    Range_to                string      `xml:"range>to,omitempty"`
    Prefix_range_from       string      `xml:"prefixrange>from,omitempty"`
    Prefix_range_to         string      `xml:"prefixrange>to,omitempty"`
    Prefix_range_length     string      `xml:"prefixrange>prefixlength,omitempty"`

    // Change tracking
    ChangeMeta              ChangeMeta  `xml:",inline"`
}
```

### New Helper Types

#### ChangeMeta Type

```go
// ChangeMeta tracks creation and modification metadata for configuration items
type ChangeMeta struct {
    Created  string `xml:"created,omitempty"`
    Updated  string `xml:"updated,omitempty"`
    Username string `xml:"username,omitempty"`
}

// NewChangeMeta creates a new ChangeMeta with current timestamp
func NewChangeMeta(username string) ChangeMeta {
    now := time.Now().Unix()
    timestamp := strconv.FormatInt(now, 10)

    return ChangeMeta{
        Created:  timestamp,
        Updated:  timestamp,
        Username: username,
    }
}

// UpdateMeta updates the modification timestamp and username
func (cm *ChangeMeta) UpdateMeta(username string) {
    now := time.Now().Unix()
    cm.Updated = strconv.FormatInt(now, 10)
    cm.Username = username
}
```

#### RuleLocation Type

```go
// RuleLocation provides granular source/destination address and port specification
type RuleLocation struct {
    XMLName xml.Name `xml:",omitempty"`

    // Network specification
    Network     string   `xml:"network,omitempty"`     // any, (self), lan, wan, optX, etc.
    Address     string   `xml:"address,omitempty"`     // IP address or hostname
    Subnet      string   `xml:"subnet,omitempty"`      // subnet mask or CIDR

    // Port specification
    Port        string   `xml:"port,omitempty"`        // single port, range, or alias

    // Advanced options
    Not         BoolFlag `xml:"not,omitempty"`         // invert/negate this location
}

// IsAny returns true if this location represents "any"
func (rl *RuleLocation) IsAny() bool {
    return rl.Network == "any" || (rl.Network == "" && rl.Address == "" && rl.Port == "")
}

// String returns a human-readable representation of the rule location
func (rl *RuleLocation) String() string {
    var parts []string

    if rl.Not {
        parts = append(parts, "NOT")
    }

    if rl.Network != "" {
        parts = append(parts, rl.Network)
    } else if rl.Address != "" {
        addr := rl.Address
        if rl.Subnet != "" {
            addr += "/" + rl.Subnet
        }
        parts = append(parts, addr)
    }

    if rl.Port != "" {
        parts = append(parts, ":"+rl.Port)
    }

    if len(parts) == 0 {
        return "any"
    }

    return strings.Join(parts, " ")
}
```

#### BoolFlag Type

```go
// BoolFlag provides custom XML marshaling for OPNsense boolean values
// OPNsense uses empty elements to represent "true" and omits elements for "false"
type BoolFlag bool

// MarshalXML implements custom XML marshaling for boolean flags
// Empty element = true, omitted element = false
func (bf BoolFlag) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
    if bf {
        // For true values, create an empty element
        return e.EncodeElement("", start)
    }
    // For false values, omit the element entirely (handled by omitempty tag)
    return nil
}

// UnmarshalXML implements custom XML unmarshaling for boolean flags
func (bf *BoolFlag) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
    // If the element exists, it's true regardless of content
    *bf = true

    // Consume the element content (may be empty)
    var content string
    if err := d.DecodeElement(&content, &start); err != nil {
        return err
    }

    return nil
}

// String returns string representation of the boolean flag
func (bf BoolFlag) String() string {
    if bf {
        return "true"
    }
    return "false"
}

// Bool returns the underlying boolean value
func (bf BoolFlag) Bool() bool {
    return bool(bf)
}

// Set sets the boolean flag value
func (bf *BoolFlag) Set(value bool) {
    *bf = BoolFlag(value)
}
```

### XML Tag Conventions

#### Naming Convention

- **Element Names**: Use snake_case for XML element names to match OPNsense conventions
- **Go Field Names**: Use PascalCase following Go conventions
- **XML Tags**: Always include appropriate XML tags with snake_case element names

#### Tag Usage Patterns

```go
// Standard field with omitempty
Field string `xml:"field_name,omitempty"`

// Boolean flag (omits when false, empty element when true)
Enable BoolFlag `xml:"enable,omitempty"`

// Slice/array elements
Items []Item `xml:"items>item,omitempty"`

// Inline embedding (no wrapper element)
ChangeMeta ChangeMeta `xml:",inline"`

// Character data (for elements containing only text)
Content string `xml:",chardata"`

// Attributes (rarely used in OPNsense)
ID string `xml:"id,attr,omitempty"`
```

#### Best Practices

1. **Always use `omitempty`**: Prevents empty fields from appearing in XML output
2. **Snake case elements**: Match OPNsense's XML naming convention
3. **Consistent BoolFlag usage**: Use BoolFlag for all boolean fields that follow OPNsense's empty-element-for-true pattern
4. **Proper slice handling**: Use wrapper elements when appropriate (e.g., `items>item`)
5. **ChangeMeta embedding**: Use inline embedding to avoid unnecessary wrapper elements
6. **XMLName specification**: Include XMLName fields for proper element naming in complex structs

### Integration Examples

#### Usage in Main Configuration Struct

```go
type Config struct {
    XMLName      xml.Name      `xml:"opnsense"`

    // Core configuration sections
    System       System        `xml:"system"`
    Interfaces   Interfaces    `xml:"interfaces"`

    // New root-level sections
    Vlans        *Vlans        `xml:"vlans,omitempty"`
    Bridges      *Bridges      `xml:"bridges,omitempty"`
    Gateways     *Gateways     `xml:"gateways,omitempty"`
    StaticRoutes *StaticRoutes `xml:"staticroutes,omitempty"`
    DNSMasq      *DNSMasq      `xml:"dnsmasq,omitempty"`
    OpenVPN      *OpenVPN      `xml:"openvpn,omitempty"`
    Syslog       *Syslog       `xml:"syslog,omitempty"`
    OPNsense     *OPNsense     `xml:"opnsense,omitempty"`

    // Existing sections with enhancements
    Filter       Filter        `xml:"filter"`
    NAT          NAT           `xml:"nat"`
    DHCP         DHCP          `xml:"dhcpd"`
    DHCPv6       DHCPv6        `xml:"dhcpdv6,omitempty"`
}
```

This design provides comprehensive coverage of OPNsense configuration elements while maintaining clean Go code structure and proper XML marshaling/unmarshaling capabilities.
