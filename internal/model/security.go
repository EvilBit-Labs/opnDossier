// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
	"slices"
	"strings"
)

// InterfaceList represents a comma-separated list of interfaces that can be unmarshaled from XML.
type InterfaceList []string

// UnmarshalXML implements custom XML unmarshaling for comma-separated interface lists.
func (il *InterfaceList) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var content string
	if err := d.DecodeElement(&content, &start); err != nil {
		return err
	}

	// Handle empty content
	if content == "" {
		*il = InterfaceList{}
		return nil
	}

	// Split by comma and trim whitespace
	parts := strings.Split(content, ",")
	interfaces := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			interfaces = append(interfaces, trimmed)
		}
	}

	*il = InterfaceList(interfaces)
	return nil
}

// MarshalXML implements custom XML marshaling for comma-separated interface lists.
func (il *InterfaceList) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	content := ""
	if len(*il) > 0 {
		content = strings.Join([]string(*il), ",")
	}
	return e.EncodeElement(content, start)
}

// String returns the comma-separated string representation.
func (il *InterfaceList) String() string {
	return strings.Join([]string(*il), ",")
}

// Contains checks if the interface list contains a specific interface.
func (il *InterfaceList) Contains(iface string) bool {
	return slices.Contains(*il, iface)
}

// IsEmpty returns true if the interface list is empty.
func (il *InterfaceList) IsEmpty() bool {
	return len(*il) == 0
}

// SecurityConfig groups security-related configuration.
type SecurityConfig struct {
	Nat    Nat    `json:"nat"    yaml:"nat,omitempty"`
	Filter Filter `json:"filter" yaml:"filter,omitempty"`
}

// NATSummary provides comprehensive NAT configuration for security analysis.
type NATSummary struct {
	Mode               string    `json:"mode" yaml:"mode"`
	ReflectionDisabled bool      `json:"reflectionDisabled" yaml:"reflectionDisabled"`
	PfShareForward     bool      `json:"pfShareForward" yaml:"pfShareForward"`
	OutboundRules      []NATRule `json:"outboundRules,omitempty" yaml:"outboundRules,omitempty"`
}

// Nat represents NAT configuration.
type Nat struct {
	Outbound Outbound `xml:"outbound" json:"outbound" yaml:"outbound"`
}

// Outbound represents outbound NAT configuration.
type Outbound struct {
	Mode string    `xml:"mode" json:"mode" yaml:"mode"`
	Rule []NATRule `xml:"rule" json:"rules,omitempty" yaml:"rules,omitempty"`
}

// Filter represents firewall filter configuration.
type Filter struct {
	Rule []Rule `xml:"rule"`
}

// NATRule represents a NAT rule with enhanced fields for security analysis.
type NATRule struct {
	XMLName     xml.Name      `xml:"rule"`
	Interface   InterfaceList `xml:"interface,omitempty" json:"interface,omitempty" yaml:"interface,omitempty"`
	IPProtocol  string        `xml:"ipprotocol,omitempty" json:"ipProtocol,omitempty" yaml:"ipProtocol,omitempty"`
	Protocol    string        `xml:"protocol,omitempty" json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Source      Source        `xml:"source" json:"source" yaml:"source"`
	Destination Destination   `xml:"destination" json:"destination" yaml:"destination"`
	Target      string        `xml:"target,omitempty" json:"target,omitempty" yaml:"target,omitempty"`
	SourcePort  string        `xml:"sourceport,omitempty" json:"sourcePort,omitempty" yaml:"sourcePort,omitempty"`
	Disabled    string        `xml:"disabled,omitempty" json:"disabled,omitempty" yaml:"disabled,omitempty"`
	Descr       string        `xml:"descr,omitempty" json:"description,omitempty" yaml:"description,omitempty"`
	Category    string        `xml:"category,omitempty" json:"category,omitempty" yaml:"category,omitempty"`
	Tag         string        `xml:"tag,omitempty" json:"tag,omitempty" yaml:"tag,omitempty"`
	Tagged      string        `xml:"tagged,omitempty" json:"tagged,omitempty" yaml:"tagged,omitempty"`
	PoolOpts    string        `xml:"poolopts,omitempty" json:"poolOpts,omitempty" yaml:"poolOpts,omitempty"`
	Updated     *Updated      `xml:"updated,omitempty" json:"updated,omitempty" yaml:"updated,omitempty"`
	Created     *Created      `xml:"created,omitempty" json:"created,omitempty" yaml:"created,omitempty"`
	UUID        string        `xml:"uuid,attr,omitempty" json:"uuid,omitempty" yaml:"uuid,omitempty"`
}

// Rule represents a firewall rule.
type Rule struct {
	XMLName     xml.Name      `xml:"rule"`
	Type        string        `xml:"type"`
	Descr       string        `xml:"descr,omitempty"`
	Interface   InterfaceList `xml:"interface,omitempty"`
	IPProtocol  string        `xml:"ipprotocol,omitempty"`
	StateType   string        `xml:"statetype,omitempty"`
	Direction   string        `xml:"direction,omitempty"`
	Quick       string        `xml:"quick,omitempty"`
	Protocol    string        `xml:"protocol,omitempty"`
	Source      Source        `xml:"source"`
	Destination Destination   `xml:"destination"`
	Target      string        `xml:"target,omitempty"`
	SourcePort  string        `xml:"sourceport,omitempty"`
	Disabled    string        `xml:"disabled,omitempty"`
	Updated     *Updated      `xml:"updated,omitempty"`
	Created     *Created      `xml:"created,omitempty"`
	UUID        string        `xml:"uuid,attr,omitempty"`
}

// Source represents a firewall rule source.
type Source struct {
	Any     string `xml:"any,omitempty"`
	Network string `xml:"network,omitempty"`
}

// Destination represents a firewall rule destination.
type Destination struct {
	Any     string `xml:"any,omitempty"`
	Network string `xml:"network,omitempty"`
	Port    string `xml:"port,omitempty"`
}

// Updated represents update information.
type Updated struct {
	Username    string `xml:"username"`
	Time        string `xml:"time"`
	Description string `xml:"description"`
}

// Created represents creation information.
type Created struct {
	Username    string `xml:"username"`
	Time        string `xml:"time"`
	Description string `xml:"description"`
}

// Firewall represents firewall configuration.
type Firewall struct {
	XMLName    xml.Name `xml:"Firewall"`
	Text       string   `xml:",chardata"  json:"text,omitempty"`
	Lvtemplate struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Version   string `xml:"version,attr" json:"version,omitempty"`
		Templates string `xml:"templates"`
	} `xml:"Lvtemplate" json:"lvtemplate"`
	Alias struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Geoip   struct {
			Text string `xml:",chardata" json:"text,omitempty"`
			URL  string `xml:"url"`
		} `xml:"geoip" json:"geoip"`
		Aliases string `xml:"aliases"`
	} `xml:"Alias"      json:"alias"`
	Category struct {
		Text       string `xml:",chardata" json:"text,omitempty"`
		Version    string `xml:"version,attr" json:"version,omitempty"`
		Categories string `xml:"categories"`
	} `xml:"Category"   json:"category"`
	Filter struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Version   string `xml:"version,attr" json:"version,omitempty"`
		Rules     string `xml:"rules"`
		Snatrules string `xml:"snatrules"`
		Npt       string `xml:"npt"`
		Onetoone  string `xml:"onetoone"`
	} `xml:"Filter"     json:"filter"`
}

// IDS represents Intrusion Detection System configuration.
//
//revive:disable:var-naming

// IDS represents the complete Intrusion Detection System configuration.
type IDS struct {
	XMLName          xml.Name `xml:"IDS"`
	Text             string   `xml:",chardata"        json:"text,omitempty"`
	Version          string   `xml:"version,attr"     json:"version,omitempty"`
	Rules            string   `xml:"rules"`
	Policies         string   `xml:"policies"`
	UserDefinedRules string   `xml:"userDefinedRules"`
	Files            string   `xml:"files"`
	FileTags         string   `xml:"fileTags"`
	General          struct {
		Text              string `xml:",chardata" json:"text,omitempty"`
		Enabled           string `xml:"enabled"`
		Ips               string `xml:"ips"`
		Promisc           string `xml:"promisc"`
		Interfaces        string `xml:"interfaces"`
		Homenet           string `xml:"homenet"`
		DefaultPacketSize string `xml:"defaultPacketSize"`
		UpdateCron        string `xml:"UpdateCron"`
		AlertLogrotate    string `xml:"AlertLogrotate"`
		AlertSaveLogs     string `xml:"AlertSaveLogs"`
		MPMAlgo           string `xml:"MPMAlgo"`
		Detect            struct {
			Text           string `xml:",chardata" json:"text,omitempty"`
			Profile        string `xml:"Profile"`
			ToclientGroups string `xml:"toclient_groups"`
			ToserverGroups string `xml:"toserver_groups"`
		} `xml:"detect" json:"detect"`
		Syslog     string `xml:"syslog"`
		SyslogEve  string `xml:"syslog_eve"`
		LogPayload string `xml:"LogPayload"`
		Verbosity  string `xml:"verbosity"`
		EveLog     struct {
			Text string `xml:",chardata" json:"text,omitempty"`
			HTTP struct {
				Text           string `xml:",chardata" json:"text,omitempty"`
				Enable         string `xml:"enable"`
				Extended       string `xml:"extended"`
				DumpAllHeaders string `xml:"dumpAllHeaders"`
			} `xml:"http" json:"http"`
			TLS struct {
				Text              string `xml:",chardata" json:"text,omitempty"`
				Enable            string `xml:"enable"`
				Extended          string `xml:"extended"`
				SessionResumption string `xml:"sessionResumption"`
				Custom            string `xml:"custom"`
			} `xml:"tls" json:"tls"`
		} `xml:"eveLog" json:"evelog"`
	} `xml:"general"          json:"general"`
}

// IPsec represents IPsec configuration.
type IPsec struct {
	XMLName xml.Name `xml:"IPsec"`
	Text    string   `xml:",chardata"     json:"text,omitempty"`
	Version string   `xml:"version,attr"  json:"version,omitempty"`
	General struct {
		Text                string `xml:",chardata" json:"text,omitempty"`
		Enabled             string `xml:"enabled"`
		PreferredOldsa      string `xml:"preferred_oldsa"`
		Disablevpnrules     string `xml:"disablevpnrules"`
		PassthroughNetworks string `xml:"passthrough_networks"`
	} `xml:"general"       json:"general"`
	Charon struct {
		Text               string `xml:",chardata" json:"text,omitempty"`
		MaxIkev1Exchanges  string `xml:"max_ikev1_exchanges"`
		Threads            string `xml:"threads"`
		IkesaTableSize     string `xml:"ikesa_table_size"`
		IkesaTableSegments string `xml:"ikesa_table_segments"`
		InitLimitHalfOpen  string `xml:"init_limit_half_open"`
		IgnoreAcquireTs    string `xml:"ignore_acquire_ts"` //nolint:staticcheck // XML field name requires underscore
		MakeBeforeBreak    string `xml:"make_before_break"`
		RetransmitTries    string `xml:"retransmit_tries"`
		RetransmitTimeout  string `xml:"retransmit_timeout"`
		RetransmitBase     string `xml:"retransmit_base"`
		RetransmitJitter   string `xml:"retransmit_jitter"`
		RetransmitLimit    string `xml:"retransmit_limit"`
		Syslog             struct {
			Text   string `xml:",chardata" json:"text,omitempty"`
			Daemon struct {
				Text     string `xml:",chardata" json:"text,omitempty"`
				IkeName  string `xml:"ike_name"`
				LogLevel string `xml:"log_level"`
				App      string `xml:"app"`
				Asn      string `xml:"asn"`
				Cfg      string `xml:"cfg"`
				Chd      string `xml:"chd"`
				Dmn      string `xml:"dmn"`
				Enc      string `xml:"enc"`
				Esp      string `xml:"esp"`
				Ike      string `xml:"ike"`
				Imc      string `xml:"imc"`
				Imv      string `xml:"imv"`
				Job      string `xml:"job"`
				Knl      string `xml:"knl"`
				Lib      string `xml:"lib"`
				Mgr      string `xml:"mgr"`
				Net      string `xml:"net"`
				Pts      string `xml:"pts"`
				TLS      string `xml:"tls"`
				Tnc      string `xml:"tnc"`
			} `xml:"daemon" json:"daemon"`
		} `xml:"syslog" json:"syslog"`
	} `xml:"charon"        json:"charon"`
	KeyPairs      string `xml:"keyPairs"`
	PreSharedKeys string `xml:"preSharedKeys"`
}

// Swanctl represents StrongSwan configuration.
type Swanctl struct {
	XMLName     xml.Name `xml:"Swanctl"`
	Text        string   `xml:",chardata"    json:"text,omitempty"`
	Version     string   `xml:"version,attr" json:"version,omitempty"`
	Connections string   `xml:"Connections"`
	Locals      string   `xml:"locals"`
	Remotes     string   `xml:"remotes"`
	Children    string   `xml:"children"`
	Pools       string   `xml:"Pools"`
	VTIs        string   `xml:"VTIs"`
	SPDs        string   `xml:"SPDs"`
}

// Constructor functions

// NewSecurityConfig returns a new SecurityConfig instance with an empty filter rule set.
func NewSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Filter: Filter{
			Rule: make([]Rule, 0),
		},
	}
}

// NewFirewall returns a pointer to a new, empty Firewall configuration.
func NewFirewall() *Firewall {
	return &Firewall{}
}

// NewIDS creates a new IDS configuration.
//
// NewIDS returns a new instance of the IDS configuration struct.
func NewIDS() *IDS {
	return &IDS{}
}

// NewIPsec returns a pointer to a new IPsec configuration instance.
func NewIPsec() *IPsec {
	return &IPsec{}
}

// NewSwanctl returns a new instance of the Swanctl configuration struct.
func NewSwanctl() *Swanctl {
	return &Swanctl{}
}
