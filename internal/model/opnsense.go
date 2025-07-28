// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// OpnSenseDocument is the root of the OPNsense configuration.
type OpnSenseDocument struct {
	XMLName              xml.Name             `xml:"opnsense" json:"-" yaml:"-"`
	Version              string               `xml:"version,omitempty" json:"version,omitempty" yaml:"version,omitempty" validate:"omitempty,semver"`
	TriggerInitialWizard struct{}             `xml:"trigger_initial_wizard,omitempty" json:"triggerInitialWizard,omitempty" yaml:"triggerInitialWizard,omitempty"`
	Theme                string               `xml:"theme,omitempty" json:"theme,omitempty" yaml:"theme,omitempty" validate:"omitempty,oneof=opnsense opnsense-ng bootstrap"`
	Sysctl               []SysctlItem         `xml:"sysctl,omitempty" json:"sysctl,omitempty" yaml:"sysctl,omitempty" validate:"dive"`
	System               System               `xml:"system,omitempty" json:"system,omitempty" yaml:"system,omitempty" validate:"required"`
	Interfaces           Interfaces           `xml:"interfaces,omitempty" json:"interfaces,omitempty" yaml:"interfaces,omitempty" validate:"required"`
	Dhcpd                Dhcpd                `xml:"dhcpd,omitempty" json:"dhcpd,omitempty" yaml:"dhcpd,omitempty"`
	Unbound              Unbound              `xml:"unbound,omitempty" json:"unbound,omitempty" yaml:"unbound,omitempty"`
	Snmpd                Snmpd                `xml:"snmpd,omitempty" json:"snmpd,omitempty" yaml:"snmpd,omitempty"`
	Nat                  Nat                  `xml:"nat,omitempty" json:"nat,omitempty" yaml:"nat,omitempty"`
	Filter               Filter               `xml:"filter,omitempty" json:"filter,omitempty" yaml:"filter,omitempty"`
	Rrd                  Rrd                  `xml:"rrd,omitempty" json:"rrd,omitempty" yaml:"rrd,omitempty"`
	LoadBalancer         LoadBalancer         `xml:"load_balancer,omitempty" json:"loadBalancer,omitempty" yaml:"loadBalancer,omitempty"`
	Ntpd                 Ntpd                 `xml:"ntpd,omitempty" json:"ntpd,omitempty" yaml:"ntpd,omitempty"`
	Widgets              Widgets              `xml:"widgets,omitempty" json:"widgets,omitempty" yaml:"widgets,omitempty"`
	Revision             Revision             `xml:"revision,omitempty" json:"revision,omitempty" yaml:"revision,omitempty"`
	Gateways             Gateways             `xml:"gateways,omitempty" json:"gateways,omitempty" yaml:"gateways,omitempty"`
	HighAvailabilitySync HighAvailabilitySync `xml:"hasync,omitempty" json:"hasync,omitempty" yaml:"hasync,omitempty"`
	InterfaceGroups      InterfaceGroups      `xml:"ifgroups,omitempty" json:"ifgroups,omitempty" yaml:"ifgroups,omitempty"`
	GIFInterfaces        GIFInterfaces        `xml:"gifs,omitempty" json:"gifs,omitempty" yaml:"gifs,omitempty"`
	GREInterfaces        GREInterfaces        `xml:"gres,omitempty" json:"gres,omitempty" yaml:"gres,omitempty"`
	LAGGInterfaces       LAGGInterfaces       `xml:"laggs,omitempty" json:"laggs,omitempty" yaml:"laggs,omitempty"`
	VirtualIP            VirtualIP            `xml:"virtualip,omitempty" json:"virtualip,omitempty" yaml:"virtualip,omitempty"`
	VLANs                VLANs                `xml:"vlans,omitempty" json:"vlans,omitempty" yaml:"vlans,omitempty"`
	OpenVPN              OpenVPN              `xml:"openvpn,omitempty" json:"openvpn,omitempty" yaml:"openvpn,omitempty"`
	StaticRoutes         StaticRoutes         `xml:"staticroutes,omitempty" json:"staticroutes,omitempty" yaml:"staticroutes,omitempty"`
	Bridges              BridgesConfig        `xml:"bridges,omitempty" json:"bridges,omitempty" yaml:"bridges,omitempty"`
	PPPInterfaces        PPPInterfaces        `xml:"ppps,omitempty" json:"ppps,omitempty" yaml:"ppps,omitempty"`
	Wireless             Wireless             `xml:"wireless,omitempty" json:"wireless,omitempty" yaml:"wireless,omitempty"`
	CertificateAuthority CertificateAuthority `xml:"ca,omitempty" json:"ca,omitempty" yaml:"ca,omitempty"`
	DHCPv6Server         DHCPv6Server         `xml:"dhcpdv6,omitempty" json:"dhcpdv6,omitempty" yaml:"dhcpdv6,omitempty"`
	Cert                 Cert                 `xml:"cert,omitempty" json:"cert,omitempty" yaml:"cert,omitempty"`
	DNSMasquerade        DNSMasq              `xml:"dnsmasq,omitempty" json:"dnsmasq,omitempty" yaml:"dnsmasq,omitempty"`
	Syslog               Syslog               `xml:"syslog,omitempty" json:"syslog,omitempty" yaml:"syslog,omitempty"`
	OPNsense             OPNsense             `xml:"OPNsense,omitempty" json:"opnsense,omitempty" yaml:"opnsense,omitempty"`
}

// OPNsense represents the main OPNsense system configuration.
type OPNsense struct {
	XMLName xml.Name `xml:"OPNsense"`
	Text    string   `xml:",chardata" json:"text,omitempty"`

	Captiveportal struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Version   string `xml:"version,attr" json:"version,omitempty"`
		Zones     string `xml:"zones"`
		Templates string `xml:"templates"`
	} `xml:"captiveportal" json:"captiveportal"`
	Cron struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Jobs    string `xml:"jobs"`
	} `xml:"cron" json:"cron"`

	DHCPRelay struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"DHCRelay" json:"dhcrelay"`

	// Security components - now using references
	Firewall                 *Firewall `xml:"Firewall,omitempty" json:"firewall,omitempty"`
	IntrusionDetectionSystem *IDS      `xml:"IDS,omitempty" json:"ids,omitempty"`
	IPsec                    *IPsec    `xml:"IPsec,omitempty" json:"ipsec,omitempty"`
	Swanctl                  *Swanctl  `xml:"Swanctl,omitempty" json:"swanctl,omitempty"`

	// VPN components - now using references
	OpenVPNExport *OpenVPNExport `xml:"OpenVPNExport,omitempty" json:"openvpnexport,omitempty"`
	OpenVPN       *OpenVPNSystem `xml:"OpenVPN,omitempty" json:"openvpn,omitempty"`
	Wireguard     *WireGuard     `xml:"wireguard,omitempty" json:"wireguard,omitempty"`

	// Monitoring components - now using references
	Monit *Monit `xml:"monit,omitempty" json:"monit,omitempty"`

	// Network components
	Interfaces struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Loopbacks struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
		} `xml:"loopbacks" json:"loopbacks"`
		Neighbors struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
		} `xml:"neighbors" json:"neighbors"`
		Vxlans struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
		} `xml:"vxlans" json:"vxlans"`
	} `xml:"Interfaces" json:"interfaces"`

	// DHCP components
	Kea struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Dhcp4   struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			General struct {
				Text          string `xml:",chardata" json:"text,omitempty"`
				Enabled       string `xml:"enabled"`
				Interfaces    string `xml:"interfaces"`
				FirewallRules string `xml:"fwrules"`
				ValidLifetime string `xml:"valid_lifetime"`
			} `xml:"general" json:"general"`
			HighAvailability struct {
				Text              string `xml:",chardata" json:"text,omitempty"`
				Enabled           string `xml:"enabled"`
				ThisServerName    string `xml:"this_server_name"`
				MaxUnackedClients string `xml:"max_unacked_clients"`
			} `xml:"ha" json:"ha"`
			Subnets      string `xml:"subnets"`
			Reservations string `xml:"reservations"`
			HAPeers      string `xml:"ha_peers"`
		} `xml:"dhcp4" json:"dhcp4"`
		CtrlAgent struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			General struct {
				Text     string `xml:",chardata" json:"text,omitempty"`
				Enabled  string `xml:"enabled"`
				HTTPHost string `xml:"http_host"`
				HTTPPort string `xml:"http_port"`
			} `xml:"general" json:"general"`
		} `xml:"ctrl_agent" json:"ctrlAgent"`
	} `xml:"Kea" json:"kea"`

	// Other system components
	Gateways struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"Gateways" json:"gateways"`

	Netflow struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Capture struct {
			Text       string `xml:",chardata" json:"text,omitempty"`
			Interfaces string `xml:"interfaces"`
			Version    string `xml:"version"`
			EgressOnly string `xml:"egress_only"`
			Targets    string `xml:"targets"`
		} `xml:"capture" json:"capture"`
		Collect struct {
			Text   string `xml:",chardata" json:"text,omitempty"`
			Enable string `xml:"enable"`
		} `xml:"collect" json:"collect"`
		InactiveTimeout string `xml:"inactiveTimeout"`
		ActiveTimeout   string `xml:"activeTimeout"`
	} `xml:"Netflow" json:"netflow"`

	Syslog struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		General struct {
			Text        string `xml:",chardata" json:"text,omitempty"`
			Enabled     string `xml:"enabled"`
			Loglocal    string `xml:"loglocal"`
			Maxpreserve string `xml:"maxpreserve"`
			Maxfilesize string `xml:"maxfilesize"`
		} `xml:"general" json:"general"`
		Destinations string `xml:"destinations"`
	} `xml:"Syslog" json:"syslog"`

	TrafficShaper struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Pipes   string `xml:"pipes"`
		Queues  string `xml:"queues"`
		Rules   string `xml:"rules"`
	} `xml:"TrafficShaper" json:"trafficshaper"`

	Trust struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		General struct {
			Text                    string `xml:",chardata" json:"text,omitempty"`
			Version                 string `xml:"version,attr" json:"version,omitempty"`
			StoreIntermediateCerts  string `xml:"store_intermediate_certs"`
			InstallCrls             string `xml:"install_crls"`
			FetchCrls               string `xml:"fetch_crls"`
			EnableLegacySect        string `xml:"enable_legacy_sect"`
			EnableConfigConstraints string `xml:"enable_config_constraints"`
			CipherString            string `xml:"CipherString"`
			Ciphersuites            string `xml:"Ciphersuites"`
			Groups                  string `xml:"groups"`
			MinProtocol             string `xml:"MinProtocol"`
			MinProtocolDTLS         string `xml:"MinProtocol_DTLS"`
		} `xml:"general" json:"general"`
	} `xml:"trust" json:"trust"`

	UnboundPlus struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		General struct {
			Text               string `xml:",chardata" json:"text,omitempty"`
			Enabled            string `xml:"enabled"`
			Port               string `xml:"port"`
			Stats              string `xml:"stats"`
			ActiveInterface    string `xml:"active_interface"`
			Dnssec             string `xml:"dnssec"`
			DNS64              string `xml:"dns64"`
			DNS64prefix        string `xml:"dns64prefix"`
			Noarecords         string `xml:"noarecords"`
			RegisterDHCP       string `xml:"regdhcp"`
			RegisterDHCPDomain string `xml:"regdhcpdomain"`
			RegisterDHCPStatic string `xml:"regdhcpstatic"`
			NoRegisterLLAddr6  string `xml:"noreglladdr6"`
			NoRegisterRecords  string `xml:"noregrecords"`
			Txtsupport         string `xml:"txtsupport"`
			Cacheflush         string `xml:"cacheflush"`
			LocalZoneType      string `xml:"local_zone_type"`
			OutgoingInterface  string `xml:"outgoing_interface"`
			EnableWpad         string `xml:"enable_wpad"`
		} `xml:"general" json:"general"`
		Advanced struct {
			Text                      string `xml:",chardata" json:"text,omitempty"`
			Hideidentity              string `xml:"hideidentity"`
			Hideversion               string `xml:"hideversion"`
			Prefetch                  string `xml:"prefetch"`
			Prefetchkey               string `xml:"prefetchkey"`
			Dnssecstripped            string `xml:"dnssecstripped"`
			Aggressivensec            string `xml:"aggressivensec"`
			Serveexpired              string `xml:"serveexpired"`
			Serveexpiredreplyttl      string `xml:"serveexpiredreplyttl"`
			Serveexpiredttl           string `xml:"serveexpiredttl"`
			Serveexpiredttlreset      string `xml:"serveexpiredttlreset"`
			Serveexpiredclienttimeout string `xml:"serveexpiredclienttimeout"`
			Qnameminstrict            string `xml:"qnameminstrict"`
			Extendedstatistics        string `xml:"extendedstatistics"`
			Logqueries                string `xml:"logqueries"`
			Logreplies                string `xml:"logreplies"`
			Logtagqueryreply          string `xml:"logtagqueryreply"`
			Logservfail               string `xml:"logservfail"`
			Loglocalactions           string `xml:"loglocalactions"`
			Logverbosity              string `xml:"logverbosity"`
			Valloglevel               string `xml:"valloglevel"`
			Privatedomain             string `xml:"privatedomain"`
			Privateaddress            string `xml:"privateaddress"`
			Insecuredomain            string `xml:"insecuredomain"`
			Msgcachesize              string `xml:"msgcachesize"`
			Rrsetcachesize            string `xml:"rrsetcachesize"`
			Outgoingnumtcp            string `xml:"outgoingnumtcp"`
			Incomingnumtcp            string `xml:"incomingnumtcp"`
			Numqueriesperthread       string `xml:"numqueriesperthread"`
			Outgoingrange             string `xml:"outgoingrange"`
			Jostletimeout             string `xml:"jostletimeout"`
			Discardtimeout            string `xml:"discardtimeout"`
			Cachemaxttl               string `xml:"cachemaxttl"`
			Cachemaxnegativettl       string `xml:"cachemaxnegativettl"`
			Cacheminttl               string `xml:"cacheminttl"`
			Infrahostttl              string `xml:"infrahostttl"`
			Infrakeepprobing          string `xml:"infrakeepprobing"`
			Infracachenumhosts        string `xml:"infracachenumhosts"`
			Unwantedreplythreshold    string `xml:"unwantedreplythreshold"`
		} `xml:"advanced" json:"advanced"`
		Acls struct {
			Text          string `xml:",chardata" json:"text,omitempty"`
			DefaultAction string `xml:"default_action"`
		} `xml:"acls" json:"acls"`
		Dnsbl struct {
			Text       string `xml:",chardata" json:"text,omitempty"`
			Enabled    string `xml:"enabled"`
			Safesearch string `xml:"safesearch"`
			Type       string `xml:"type"`
			Lists      string `xml:"lists"`
			Whitelists string `xml:"whitelists"`
			Blocklists string `xml:"blocklists"`
			Wildcards  string `xml:"wildcards"`
			Address    string `xml:"address"`
			Nxdomain   string `xml:"nxdomain"`
		} `xml:"dnsbl" json:"dnsbl"`
		Forwarding struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Enabled string `xml:"enabled"`
		} `xml:"forwarding" json:"forwarding"`
		Dots    string `xml:"dots"`
		Hosts   string `xml:"hosts"`
		Aliases string `xml:"aliases"`
		Domains string `xml:"domains"`
	} `xml:"unboundplus" json:"unboundplus"`

	// Legacy components (keeping as embedded for now)
	HighAvailabilitySync struct {
		Text            string `xml:",chardata" json:"text,omitempty"`
		Version         string `xml:"version,attr" json:"version,omitempty"`
		Disablepreempt  string `xml:"disablepreempt"`
		Disconnectppps  string `xml:"disconnectppps"`
		Pfsyncinterface string `xml:"pfsyncinterface"`
		Pfsyncpeerip    string `xml:"pfsyncpeerip"`
		Pfsyncversion   string `xml:"pfsyncversion"`
		Synchronizetoip string `xml:"synchronizetoip"`
		Username        string `xml:"username"`
		Password        string `xml:"password"`
		Syncitems       string `xml:"syncitems"`
	} `xml:"hasync" json:"hasync,omitempty"`
	InterfaceGroups struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"ifgroups" json:"ifgroups,omitempty"`
	GIFInterfaces struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Gif     string `xml:"gif"`
	} `xml:"gifs" json:"gifs,omitempty"`
	GREInterfaces struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Gre     string `xml:"gre"`
	} `xml:"gres" json:"gres,omitempty"`
	LAGGInterfaces struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Lagg    string `xml:"lagg"`
	} `xml:"laggs" json:"laggs,omitempty"`
	VirtualIP struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Vip     string `xml:"vip"`
	} `xml:"virtualip" json:"virtualip,omitempty"`
	VLANs struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		VLAN    string `xml:"vlan"`
	} `xml:"vlans" json:"vlans,omitempty"`
	Openvpn      string `xml:"openvpn"`
	Staticroutes struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Route   string `xml:"route"`
	} `xml:"staticroutes" json:"staticroutes,omitempty"`
	Bridges struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Bridged string `xml:"bridged"`
	} `xml:"bridges" json:"bridges,omitempty"`
	PPPInterfaces struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Ppp  string `xml:"ppp"`
	} `xml:"ppps" json:"ppps,omitempty"`
	Wireless struct {
		Text  string `xml:",chardata" json:"text,omitempty"`
		Clone string `xml:"clone"`
	} `xml:"wireless" json:"wireless,omitempty"`
	CertificateAuthority string `xml:"ca"`
	DHCPv6Server         string `xml:"dhcpdv6"`
	Cert                 struct {
		Text  string `xml:",chardata" json:"text,omitempty"`
		Refid string `xml:"refid"`
		Descr string `xml:"descr"`
		Crt   string `xml:"crt"`
		Prv   string `xml:"prv"`
	} `xml:"cert" json:"cert,omitempty"`
	Routes struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Route   string `xml:"route"`
	} `xml:"routes" json:"routes,omitempty"`
	UnboundDNS struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Unbound string `xml:"unbound"`
	} `xml:"unbound" json:"unbound,omitempty"`
	Created string `xml:"created,omitempty"`
	Updated string `xml:"updated,omitempty"`
}

// Cert represents a certificate configuration.
type Cert struct {
	Text  string `xml:",chardata" json:"text,omitempty"`
	Refid string `xml:"refid"`
	Descr string `xml:"descr"`
	Crt   string `xml:"crt"`
	Prv   string `xml:"prv"`
}

// Constructor functions

// NewOpnSenseDocument creates a new OpnSenseDocument configuration with properly initialized slices.
func NewOpnSenseDocument() *OpnSenseDocument {
	return &OpnSenseDocument{
		Sysctl: make([]SysctlItem, 0),
		Filter: Filter{
			Rule: make([]Rule, 0),
		},
		LoadBalancer: LoadBalancer{
			MonitorType: make([]MonitorType, 0),
		},
		System: System{
			Group: make([]Group, 0),
			User:  make([]User, 0),
		},
		Interfaces: Interfaces{
			Items: make(map[string]Interface),
		},
		Dhcpd: Dhcpd{
			Items: make(map[string]DhcpdInterface),
		},
	}
}

// Helper methods for RootConfig

// Hostname returns the configured hostname from the system configuration.
// This is a convenience method that extracts the hostname field from the nested System struct.
//
// Example:
//
//	hostname := config.Hostname()
//	fmt.Printf("Firewall hostname: %s\n", hostname)
func (o *OpnSenseDocument) Hostname() string {
	return o.System.Hostname
}

// InterfaceByName returns a network interface by its interface name (e.g., "em0", "igb0").
// It searches through all interfaces in the map-based Interfaces struct and returns a pointer
// to the matching interface, or nil if no interface with the given name is found.
//
// Parameters:
//   - name: The interface name to search for (e.g., "em0", "igb0", "vtnet0")
//
// Returns:
//   - *Interface: Pointer to the matching interface, or nil if not found
//
// Example:
//
//	iface := config.InterfaceByName("em0")
//	if iface != nil {
//		fmt.Printf("Interface %s has IP: %s\n", iface.If, iface.IPAddr)
//	}
func (o *OpnSenseDocument) InterfaceByName(name string) *Interface {
	for _, iface := range o.Interfaces.Items {
		if iface.If == name {
			return &iface
		}
	}
	return nil
}

// FilterRules returns a slice of all firewall filter rules configured in the system.
// This provides direct access to the firewall rules for analysis, processing, or iteration.
//
// Returns:
//   - []Rule: Slice of all firewall rules, may be empty if no rules are configured
//
// Example:
//
//	rules := config.FilterRules()
//	fmt.Printf("Found %d firewall rules\n", len(rules))
//	for i, rule := range rules {
//		fmt.Printf("Rule %d: %s %s on %s\n", i+1, rule.Type, rule.IPProtocol, rule.Interface)
//	}
func (o *OpnSenseDocument) FilterRules() []Rule {
	return o.Filter.Rule
}

// SystemConfig returns the system configuration grouped by functionality.
// This groups system-level settings including core system configuration and sysctl tunables
// into a single structured object for easier access and processing.
//
// Returns:
//   - SystemConfig: Grouped system configuration containing System and Sysctl fields
//
// Example:
//
//	sysConfig := config.SystemConfig()
//	fmt.Printf("Hostname: %s\n", sysConfig.System.Hostname)
//	fmt.Printf("Sysctl items: %d\n", len(sysConfig.Sysctl))
func (o *OpnSenseDocument) SystemConfig() SystemConfig {
	return SystemConfig{
		System: o.System,
		Sysctl: o.Sysctl,
	}
}

// NetworkConfig returns the network configuration grouped by functionality.
// This provides a focused view of network-related settings including all interface configurations.
//
// Returns:
//   - NetworkConfig: Grouped network configuration containing interface definitions
//
// Example:
//
//	netConfig := config.NetworkConfig()
//	fmt.Printf("WAN IP: %s\n", netConfig.Interfaces.Wan.IPAddr)
//	fmt.Printf("LAN IP: %s\n", netConfig.Interfaces.Lan.IPAddr)
func (o *OpnSenseDocument) NetworkConfig() NetworkConfig {
	return NetworkConfig{
		Interfaces: o.Interfaces,
	}
}

// SecurityConfig returns the security configuration grouped by functionality.
// This groups security-related settings including firewall rules and NAT configuration
// into a single structured object for security analysis and processing.
//
// Returns:
//   - SecurityConfig: Grouped security configuration containing NAT and Filter settings
//
// Example:
//
//	secConfig := config.SecurityConfig()
//	fmt.Printf("NAT mode: %s\n", secConfig.Nat.Outbound.Mode)
//	fmt.Printf("Filter rules: %d\n", len(secConfig.Filter.Rule))
func (o *OpnSenseDocument) SecurityConfig() SecurityConfig {
	return SecurityConfig{
		Nat:    o.Nat,
		Filter: o.Filter,
	}
}

// ServiceConfig returns the service configuration grouped by functionality.
// This groups all service-related settings including DHCP, DNS, SNMP, monitoring,
// load balancing, and time services into a single structured object.
//
// Returns:
//   - ServiceConfig: Grouped service configuration containing all service settings
//
// Example:
//
//	svcConfig := config.ServiceConfig()
//	if lanDhcp, ok := svcConfig.Dhcpd.Get("lan"); ok && lanDhcp.Range.From != "" {
//		fmt.Printf("DHCP range: %s - %s\n", lanDhcp.Range.From, lanDhcp.Range.To)
//	}
//	fmt.Printf("SNMP community: %s\n", svcConfig.Snmpd.ROCommunity)
func (o *OpnSenseDocument) ServiceConfig() ServiceConfig {
	return ServiceConfig{
		Dhcpd:        o.Dhcpd,
		Unbound:      o.Unbound,
		Snmpd:        o.Snmpd,
		Rrd:          o.Rrd,
		LoadBalancer: o.LoadBalancer,
		Ntpd:         o.Ntpd,
	}
}
