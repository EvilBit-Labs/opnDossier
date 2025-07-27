# Template Analysis: opnsense_report.md.tmpl

This document analyzes the template fields and maps them to the correct model properties in `internal/model/opnsense.go`.

## Template Field Mapping

### Header Section

```go
// Template: {{ .Hostname }}
// Model: opnsense.System.Hostname

// Template: {{ .Version }}
// Model: opnsense.Version

// Template: {{ .Generated }}
// Model: This should be a timestamp field added by the template processor

// Template: {{ .ToolVersion }}
// Model: This should be the application version added by the template processor
```

### Interfaces Section

```go
// Template: {{- range .Interfaces }}
// Model: opnsense.Interfaces.Items (map[string]Interface)

// Template: {{ .Name }}
// Model: $name (the map key - e.g., "wan", "lan", "opt0")

// Template: {{ .Description }}
// Model: $iface.If (physical interface name)

// Template: {{ .IPAddress }}
// Model: $iface.IPAddr

// Template: {{ .CIDR }}
// Model: $iface.Subnet

// Template: {{ .Enabled }}
// Model: $iface.Enable
```

### Firewall Rules Section

```go
// Template: {{- range .Firewall.WAN }}
// Model: This expects separate WAN and LAN rule arrays, but model has:
// opnsense.Filter.Rule (single array of all rules)

// Template: {{ .ID }}
// Model: Should be calculated index (e.g., $index + 1)

// Template: {{ .Action }}
// Model: $rule.Type

// Template: {{ .Protocol }}
// Model: $rule.IPProtocol

// Template: {{ .Source }}
// Model: $rule.Source.Network

// Template: {{ .Destination }}
// Model: $rule.Destination.Network

// Template: {{ .Description }}
// Model: $rule.Descr
```

### NAT Rules Section

```go
// Template: {{- range .NATRules }}
// Model: This expects an array of NAT rules, but model has:
// opnsense.Nat.Outbound.Mode (string)

// Template: {{ .Interface }}
// Model: Not available in current model

// Template: {{ .Protocol }}
// Model: Not available in current model

// Template: {{ .Source }}
// Model: Not available in current model

// Template: {{ .Destination }}
// Model: Not available in current model

// Template: {{ .NATIP }}
// Model: Not available in current model

// Template: {{ .Description }}
// Model: Not available in current model
```

### DHCP Services Section

```go
// Template: {{- range .DHCP.Servers }}
// Model: opnsense.Dhcpd.Items (map[string]DhcpdInterface)

// Template: {{ .Interface }}
// Model: $name (the map key - e.g., "wan", "lan")

// Template: {{ .RangeStart }}
// Model: $dhcp.Range.From

// Template: {{ .RangeEnd }}
// Model: $dhcp.Range.To

// Template: {{ .Domain }}
// Model: opnsense.System.Domain

// Template: {{ join .DNSServers ", " }}
// Model: Not available in current model

// Template: {{- range .DHCP.StaticLeases }}
// Model: Not available in current model - no static leases in current structure
```

### DNS Resolver Section

```go
// Template: {{ .DNS.Enabled }}
// Model: opnsense.Unbound.Enable

// Template: {{ .DNS.DNSSEC }}
// Model: Not available in current model

// Template: {{ .DNS.CustomOptions }}
// Model: Not available in current model
```

### OpenVPN Section

```go
// Template: {{- range .OpenVPN }}
// Model: Not available in current model - no OpenVPN configuration in current structure

// Template: {{ .Name }}
// Model: Not available

// Template: {{ .Mode }}
// Model: Not available

// Template: {{ .LocalIP }}
// Model: Not available

// Template: {{ .RemoteNet }}
// Model: Not available

// Template: {{ .Enabled }}
// Model: Not available
```

### System Users Section

```go
// Template: {{- range .SystemUsers }}
// Model: opnsense.System.User ([]User)

// Template: {{ .Username }}
// Model: $user.Name

// Template: {{ .UID }}
// Model: $user.UID

// Template: {{ .Group }}
// Model: $user.Groupname

// Template: {{ .Shell }}
// Model: Not available in current model

// Template: {{ .Disabled }}
// Model: Not available in current model
```

### Services & Daemons Section

```go
// Template: {{- range .Services }}
// Model: Not available in current model - no services array in current structure

// Template: {{ .Name }}
// Model: Not available

// Template: {{ .Enabled }}
// Model: Not available

// Template: {{ .Description }}
// Model: Not available
```

### System Tunables Section

```go
// Template: {{- range .Tunables }}
// Model: opnsense.Sysctl ([]SysctlItem)

// Template: {{ .Name }}
// Model: $sysctl.Tunable

// Template: {{ .Value }}
// Model: $sysctl.Value

// Template: {{ .Description }}
// Model: $sysctl.Descr
```

### System Notes Section

```go
// Template: {{ .SystemNotes }}
// Model: Not available in current model - no system notes field in current structure
```

## Missing Properties Found in Testdata

After analyzing the testdata files, the following properties are present in the XML but missing from the current model:

### Interface Properties (missing from Interface struct)

```go
// Missing from Interface struct:
- Descr string `xml:"descr,omitempty"`           // Interface description
- Spoofmac string `xml:"spoofmac,omitempty"`     // Spoof MAC address
- InternalDynamic string `xml:"internal_dynamic,omitempty"` // Internal dynamic flag
- Type string `xml:"type,omitempty"`             // Interface type (none, group, etc.)
- Virtual string `xml:"virtual,omitempty"`       // Virtual interface flag
- Lock string `xml:"lock,omitempty"`             // Interface lock flag
- Gateway string `xml:"gateway,omitempty"`       // Gateway for interface
- Gatewayv6 string `xml:"gatewayv6,omitempty"`   // IPv6 gateway for interface
- Subnetv6 string `xml:"subnetv6,omitempty"`     // IPv6 subnet mask
- Track6Interface string `xml:"track6-interface,omitempty"` // IPv6 track interface
- Track6PrefixID string `xml:"track6-prefix-id,omitempty"` // IPv6 track prefix ID
```

### DHCP Properties (missing from DhcpdInterface struct)

```go
// Missing from DhcpdInterface struct:
- Gateway string `xml:"gateway,omitempty"`       // DHCP gateway
- DdnsDomainAlgorithm string `xml:"ddnsdomainalgorithm,omitempty"` // DDNS algorithm
- NumberOptions []struct{} `xml:"numberoptions,omitempty"` // DHCP options
- Winsserver string `xml:"winsserver,omitempty"` // WINS server
- Dnsserver string `xml:"dnsserver,omitempty"`   // DNS server
- Ntpserver string `xml:"ntpserver,omitempty"`   // NTP server
```

### Firewall Rule Properties (missing from Rule struct)

```go
// Missing from Rule struct:
- Statetype string `xml:"statetype,omitempty"`   // State type (keep state, etc.)
- Direction string `xml:"direction,omitempty"`   // Direction (in, out)
- Quick string `xml:"quick,omitempty"`           // Quick rule flag
- Protocol string `xml:"protocol,omitempty"`     // Protocol (tcp, udp, etc.)
- Source struct {
    Any string `xml:"any,omitempty"`             // Any source flag
    Network string `xml:"network,omitempty"`     // Source network
    Port string `xml:"port,omitempty"`           // Source port
} `xml:"source"`
- Destination struct {
    Any string `xml:"any,omitempty"`             // Any destination flag
    Network string `xml:"network,omitempty"`     // Destination network
    Port string `xml:"port,omitempty"`           // Destination port
} `xml:"destination"`
```

### System Properties (missing from System struct)

```go
// Missing from System struct:
- Dnsallowoverride string `xml:"dnsallowoverride,omitempty"` // DNS allow override
- NextUID string `xml:"nextuid,omitempty"`       // Next UID
- NextGID string `xml:"nextgid,omitempty"`       // Next GID
- Timeservers string `xml:"timeservers,omitempty"` // Time servers
- DisableNATReflection string `xml:"disablenatreflection,omitempty"` // Disable NAT reflection
- UseVirtualTerminal string `xml:"usevirtualterminal,omitempty"` // Use virtual terminal
- DisableConsoleMenu struct{} `xml:"disableconsolemenu,omitempty"` // Disable console menu
- DisableVLANHWFilter string `xml:"disablevlanhwfilter,omitempty"` // Disable VLAN HW filter
- DisableChecksumOffloading string `xml:"disablechecksumoffloading,omitempty"` // Disable checksum offloading
- DisableSegmentationOffloading string `xml:"disablesegmentationoffloading,omitempty"` // Disable segmentation offloading
- DisableLargeReceiveOffloading string `xml:"disablelargereceiveoffloading,omitempty"` // Disable large receive offloading
- IPv6Allow struct{} `xml:"ipv6allow,omitempty"` // IPv6 allow
- PowerdAcMode string `xml:"powerd_ac_mode,omitempty"` // Power daemon AC mode
- PowerdBatteryMode string `xml:"powerd_battery_mode,omitempty"` // Power daemon battery mode
- PowerdNormalMode string `xml:"powerd_normal_mode,omitempty"` // Power daemon normal mode
- PfShareForward string `xml:"pf_share_forward,omitempty"` // PF share forward
- LbUseSticky string `xml:"lb_use_sticky,omitempty"` // Load balancer use sticky
- RrdBackup string `xml:"rrdbackup,omitempty"` // RRD backup
- NetflowBackup string `xml:"netflowbackup,omitempty"` // Netflow backup
- Firmware struct {
    Version string `xml:"version,attr,omitempty"`
    Mirror string `xml:"mirror,omitempty"`
    Flavour string `xml:"flavour,omitempty"`
    Plugins string `xml:"plugins,omitempty"`
} `xml:"firmware,omitempty"`
- Dnsserver string `xml:"dnsserver,omitempty"` // DNS server
- Language string `xml:"language,omitempty"` // Language
```

### User Properties (missing from User struct)

```go
// Missing from User struct:
- Apikeys []struct {
    Key string `xml:"key,omitempty"`
    Secret string `xml:"secret,omitempty"`
} `xml:"apikeys,omitempty"`
- Expires string `xml:"expires,omitempty"`       // User expiration
- Authorizedkeys string `xml:"authorizedkeys,omitempty"` // Authorized SSH keys
- Ipsecpsk string `xml:"ipsecpsk,omitempty"`     // IPsec PSK
- OtpSeed string `xml:"otp_seed,omitempty"`      // OTP seed
```

### DNS/Unbound Properties (missing from Unbound struct)

```go
// Missing from Unbound struct:
- Dnssec string `xml:"dnssec,omitempty"`         // DNSSEC enabled
- Dnssecstripped string `xml:"dnssecstripped,omitempty"` // DNSSEC stripped
```

### Additional Missing Sections

```go
// Missing from Opnsense struct:
- Gateways struct {
    GatewayItem []struct {
        Descr string `xml:"descr,omitempty"`
        Defaultgw string `xml:"defaultgw,omitempty"`
        Ipprotocol string `xml:"ipprotocol,omitempty"`
        Interface string `xml:"interface,omitempty"`
        Gateway string `xml:"gateway,omitempty"`
        MonitorDisable string `xml:"monitor_disable,omitempty"`
        Name string `xml:"name,omitempty"`
        Interval string `xml:"interval,omitempty"`
        Weight string `xml:"weight,omitempty"`
        Fargw string `xml:"fargw,omitempty"`
    } `xml:"gateway_item,omitempty"`
} `xml:"gateways,omitempty"`

- Revision struct {
    Username string `xml:"username,omitempty"`
    Time string `xml:"time,omitempty"`
    Description string `xml:"description,omitempty"`
} `xml:"revision,omitempty"`

- OPNsense struct {
    Wireguard struct {
        General struct {
            Version string `xml:"version,attr,omitempty"`
            Enabled string `xml:"enabled,omitempty"`
        } `xml:"general,omitempty"`
        Server struct {
            Version string `xml:"version,attr,omitempty"`
            Servers struct {
                Server []struct {
                    UUID string `xml:"uuid,attr,omitempty"`
                    Enabled string `xml:"enabled,omitempty"`
                    Name string `xml:"name,omitempty"`
                    Instance string `xml:"instance,omitempty"`
                    Pubkey string `xml:"pubkey,omitempty"`
                    Privkey string `xml:"privkey,omitempty"`
                    Port string `xml:"port,omitempty"`
                    MTU string `xml:"mtu,omitempty"`
                    DNS string `xml:"dns,omitempty"`
                    Tunneladdress string `xml:"tunneladdress,omitempty"`
                    Disableroutes string `xml:"disableroutes,omitempty"`
                    Gateway string `xml:"gateway,omitempty"`
                    Peers string `xml:"peers,omitempty"`
                } `xml:"server,omitempty"`
            } `xml:"servers,omitempty"`
        } `xml:"server,omitempty"`
        Client struct {
            Version string `xml:"version,attr,omitempty"`
            Clients struct {
                Client []struct {
                    UUID string `xml:"uuid,attr,omitempty"`
                    Enabled string `xml:"enabled,omitempty"`
                    Name string `xml:"name,omitempty"`
                    Pubkey string `xml:"pubkey,omitempty"`
                    PSK string `xml:"psk,omitempty"`
                    Tunneladdress string `xml:"tunneladdress,omitempty"`
                    Serveraddress string `xml:"serveraddress,omitempty"`
                    Serverport string `xml:"serverport,omitempty"`
                    Keepalive string `xml:"keepalive,omitempty"`
                } `xml:"client,omitempty"`
            } `xml:"clients,omitempty"`
        } `xml:"client,omitempty"`
    } `xml:"wireguard,omitempty"`
} `xml:"OPNsense,omitempty"`
```

## Summary of Issues

1. **Missing Model Fields**: Several template fields reference data that doesn't exist in the current model:
   - OpenVPN configuration
   - Static DHCP leases
   - DNS DNSSEC and custom options
   - Services array
   - System notes
   - User shell and disabled status
   - NAT rule details (only mode is available)

2. **Structural Mismatches**:
   - Template expects separate WAN/LAN firewall rule arrays, but model has single array
   - Template expects NAT rules array, but model has only NAT mode string
   - Template expects DHCP servers array, but model uses map structure

3. **Missing Helper Functions**:
   - `join` function for DNS servers
   - `add` function for rule numbering

4. **Extensive Missing Properties**: The testdata files contain many more properties than the current model supports, including:
   - Advanced interface properties (descriptions, types, virtual flags)
   - Extended DHCP configuration (gateways, DNS servers, WINS servers)
   - Detailed firewall rule properties (state types, directions, protocols, ports)
   - System configuration details (power management, hardware offloading)
   - User authentication details (API keys, SSH keys, OTP)
   - Gateway configurations
   - WireGuard VPN configurations
   - Revision tracking

## Recommended Actions

1. **Extend the model** to include missing fields (OpenVPN, static leases, etc.)
2. **Add missing properties** from testdata files to existing structs
3. **Create template data adapter** to transform model data into expected template structure
4. **Add helper functions** to template engine
5. **Update template** to work with current model structure
6. **Add missing validation tags** to model fields
7. **Consider adding new sections** for gateways, WireGuard, and revision tracking
