// Package schema defines the data structures for OPNsense configurations.
package schema

import (
	"encoding/xml"
)

// OpnSenseDocument is the root of the OPNsense configuration.
type OpnSenseDocument struct {
	XMLName              xml.Name             `xml:"opnsense"                         json:"-"                    yaml:"-"`
	Version              string               `xml:"version,omitempty"                json:"version,omitempty"    yaml:"version,omitempty"              validate:"omitempty,semver"`
	TriggerInitialWizard BoolFlag             `xml:"trigger_initial_wizard,omitempty" json:"triggerInitialWizard" yaml:"triggerInitialWizard,omitempty"`
	Theme                string               `xml:"theme,omitempty"                  json:"theme,omitempty"      yaml:"theme,omitempty"                validate:"omitempty,oneof=opnsense opnsense-ng bootstrap"`
	Sysctl               []SysctlItem         `xml:"sysctl,omitempty"                 json:"sysctl,omitempty"     yaml:"sysctl,omitempty"               validate:"dive"`
	System               System               `xml:"system,omitempty"                 json:"system"               yaml:"system,omitempty"               validate:"required"`
	Interfaces           Interfaces           `xml:"interfaces,omitempty"             json:"interfaces"           yaml:"interfaces,omitempty"           validate:"required"`
	Dhcpd                Dhcpd                `xml:"dhcpd,omitempty"                  json:"dhcpd"                yaml:"dhcpd,omitempty"`
	Unbound              Unbound              `xml:"unbound,omitempty"                json:"unbound"              yaml:"unbound,omitempty"`
	Snmpd                Snmpd                `xml:"snmpd,omitempty"                  json:"snmpd"                yaml:"snmpd,omitempty"`
	Nat                  Nat                  `xml:"nat,omitempty"                    json:"nat"                  yaml:"nat,omitempty"`
	Filter               Filter               `xml:"filter,omitempty"                 json:"filter"               yaml:"filter,omitempty"`
	Rrd                  Rrd                  `xml:"rrd,omitempty"                    json:"rrd"                  yaml:"rrd,omitempty"`
	LoadBalancer         LoadBalancer         `xml:"load_balancer,omitempty"          json:"loadBalancer"         yaml:"loadBalancer,omitempty"`
	Ntpd                 Ntpd                 `xml:"ntpd,omitempty"                   json:"ntpd"                 yaml:"ntpd,omitempty"`
	Widgets              Widgets              `xml:"widgets,omitempty"                json:"widgets"              yaml:"widgets,omitempty"`
	Revision             Revision             `xml:"revision,omitempty"               json:"revision"             yaml:"revision,omitempty"`
	Gateways             Gateways             `xml:"gateways,omitempty"               json:"gateways"             yaml:"gateways,omitempty"`
	HighAvailabilitySync HighAvailabilitySync `xml:"hasync,omitempty"                 json:"hasync"               yaml:"hasync,omitempty"`
	InterfaceGroups      InterfaceGroups      `xml:"ifgroups,omitempty"               json:"ifgroups"             yaml:"ifgroups,omitempty"`
	GIFInterfaces        GIFInterfaces        `xml:"gifs,omitempty"                   json:"gifs"                 yaml:"gifs,omitempty"`
	GREInterfaces        GREInterfaces        `xml:"gres,omitempty"                   json:"gres"                 yaml:"gres,omitempty"`
	LAGGInterfaces       LAGGInterfaces       `xml:"laggs,omitempty"                  json:"laggs"                yaml:"laggs,omitempty"`
	VirtualIP            VirtualIP            `xml:"virtualip,omitempty"              json:"virtualip"            yaml:"virtualip,omitempty"`
	VLANs                VLANs                `xml:"vlans,omitempty"                  json:"vlans"                yaml:"vlans,omitempty"`
	OpenVPN              OpenVPN              `xml:"openvpn,omitempty"                json:"openvpn"              yaml:"openvpn,omitempty"`
	StaticRoutes         StaticRoutes         `xml:"staticroutes,omitempty"           json:"staticroutes"         yaml:"staticroutes,omitempty"`
	Bridges              BridgesConfig        `xml:"bridges,omitempty"                json:"bridges"              yaml:"bridges,omitempty"`
	PPPInterfaces        PPPInterfaces        `xml:"ppps,omitempty"                   json:"ppps"                 yaml:"ppps,omitempty"`
	Wireless             Wireless             `xml:"wireless,omitempty"               json:"wireless"             yaml:"wireless,omitempty"`
	CertificateAuthority CertificateAuthority `xml:"ca,omitempty"                     json:"ca"                   yaml:"ca,omitempty"`
	DHCPv6Server         DHCPv6Server         `xml:"dhcpdv6,omitempty"                json:"dhcpdv6"              yaml:"dhcpdv6,omitempty"`
	Cert                 Cert                 `xml:"cert,omitempty"                   json:"cert"                 yaml:"cert,omitempty"`
	DNSMasquerade        DNSMasq              `xml:"dnsmasq,omitempty"                json:"dnsmasq"              yaml:"dnsmasq,omitempty"`
	Syslog               Syslog               `xml:"syslog,omitempty"                 json:"syslog"               yaml:"syslog,omitempty"`
	OPNsense             OPNsense             `xml:"OPNsense,omitempty"               json:"opnsense"             yaml:"opnsense,omitempty"`
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
	} `xml:"cron"          json:"cron"`

	DHCPRelay struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"DHCRelay" json:"dhcrelay"`

	// Security components - now using references
	Firewall                 *Firewall `xml:"Firewall,omitempty" json:"firewall,omitempty"`
	IntrusionDetectionSystem *IDS      `xml:"IDS,omitempty"      json:"ids,omitempty"`
	IPsec                    *IPsec    `xml:"IPsec,omitempty"    json:"ipsec,omitempty"`
	Swanctl                  *Swanctl  `xml:"Swanctl,omitempty"  json:"swanctl,omitempty"`

	// VPN components - now using references
	OpenVPNExport *OpenVPNExport `xml:"OpenVPNExport,omitempty" json:"openvpnexport,omitempty"`
	OpenVPN       *OpenVPNSystem `xml:"OpenVPN,omitempty"       json:"openvpn_system,omitempty"`
	Wireguard     *WireGuard     `xml:"wireguard,omitempty"     json:"wireguard,omitempty"`

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
	} `xml:"Gateways" json:"gateways_internal"`

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

	SyslogInternal struct {
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
	} `xml:"Syslog" json:"syslog_internal"`

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

	Routes struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Route   string `xml:"route"`
	} `xml:"routes"            json:"routes"`
	UnboundDNS struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Unbound string `xml:"unbound"`
	} `xml:"unbound"           json:"unbound_internal"`
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

// NewOpnSenseDocument returns a new OpnSenseDocument with all slice and map fields initialized for safe use.
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
func (o *OpnSenseDocument) Hostname() string {
	return o.System.Hostname
}

// InterfaceByName returns a network interface by its interface name (e.g., "em0", "igb0").
func (o *OpnSenseDocument) InterfaceByName(name string) *Interface {
	for _, iface := range o.Interfaces.Items {
		if iface.If == name {
			return &iface
		}
	}

	return nil
}

// FilterRules returns a slice of all firewall filter rules configured in the system.
func (o *OpnSenseDocument) FilterRules() []Rule {
	return o.Filter.Rule
}

// SystemConfig returns the system configuration grouped by functionality.
func (o *OpnSenseDocument) SystemConfig() SystemConfig {
	return SystemConfig{
		System: o.System,
		Sysctl: o.Sysctl,
	}
}

// NetworkConfig returns the network configuration grouped by functionality.
func (o *OpnSenseDocument) NetworkConfig() NetworkConfig {
	return NetworkConfig{
		Interfaces: o.Interfaces,
	}
}

// SecurityConfig returns the security configuration grouped by functionality.
func (o *OpnSenseDocument) SecurityConfig() SecurityConfig {
	return SecurityConfig{
		Nat:    o.Nat,
		Filter: o.Filter,
	}
}

// ServiceConfig returns the service configuration grouped by functionality.
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

// NATSummary provides comprehensive NAT configuration information for security analysis.
func (o *OpnSenseDocument) NATSummary() NATSummary {
	// Initialize with safe defaults
	summary := NATSummary{
		Mode:               "",
		ReflectionDisabled: false,
		PfShareForward:     false,
		OutboundRules:      nil,
		InboundRules:       nil,
	}

	// Safely access System fields
	if o.System.DisableNATReflection == "yes" {
		summary.ReflectionDisabled = true
	}
	if o.System.PfShareForward == 1 {
		summary.PfShareForward = true
	}

	// Safely access NAT fields with nil checks
	if o.Nat.Outbound.Mode != "" {
		summary.Mode = o.Nat.Outbound.Mode
	}
	if o.Nat.Outbound.Rule != nil {
		summary.OutboundRules = o.Nat.Outbound.Rule
	}
	if o.Nat.Inbound != nil {
		summary.InboundRules = o.Nat.Inbound
	}

	return summary
}
