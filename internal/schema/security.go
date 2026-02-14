// Package schema defines the data structures for OPNsense configurations.
package schema

import (
	"encoding/xml"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
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
	Mode               string        `json:"mode"                    yaml:"mode"`
	ReflectionDisabled bool          `json:"reflectionDisabled"      yaml:"reflectionDisabled"`
	PfShareForward     bool          `json:"pfShareForward"          yaml:"pfShareForward"`
	OutboundRules      []NATRule     `json:"outboundRules,omitempty" yaml:"outboundRules,omitempty"`
	InboundRules       []InboundRule `json:"inboundRules,omitempty"  yaml:"inboundRules,omitempty"`
}

// Nat represents NAT configuration.
type Nat struct {
	Outbound Outbound      `xml:"outbound"     json:"outbound"          yaml:"outbound"`
	Inbound  []InboundRule `xml:"inbound>rule" json:"inbound,omitempty" yaml:"inbound,omitempty"`
}

// Outbound represents outbound NAT configuration.
type Outbound struct {
	Mode string    `xml:"mode" json:"mode"            yaml:"mode"`
	Rule []NATRule `xml:"rule" json:"rules,omitempty" yaml:"rules,omitempty"`
}

// Filter represents firewall filter configuration.
type Filter struct {
	Rule []Rule `xml:"rule"`
}

// NATRule represents a NAT rule with enhanced fields for security analysis.
type NATRule struct {
	XMLName     xml.Name      `xml:"rule"`
	Interface   InterfaceList `xml:"interface,omitempty"  json:"interface,omitempty"   yaml:"interface,omitempty"`
	IPProtocol  string        `xml:"ipprotocol,omitempty" json:"ipProtocol,omitempty"  yaml:"ipProtocol,omitempty"`
	Protocol    string        `xml:"protocol,omitempty"   json:"protocol,omitempty"    yaml:"protocol,omitempty"`
	Source      Source        `xml:"source"               json:"source"                yaml:"source"`
	Destination Destination   `xml:"destination"          json:"destination"           yaml:"destination"`
	Target      string        `xml:"target,omitempty"     json:"target,omitempty"      yaml:"target,omitempty"`
	SourcePort  string        `xml:"sourceport,omitempty" json:"sourcePort,omitempty"  yaml:"sourcePort,omitempty"`
	Disabled    BoolFlag      `xml:"disabled,omitempty"   json:"disabled,omitempty"    yaml:"disabled,omitempty"`
	Log         BoolFlag      `xml:"log,omitempty"        json:"log,omitempty"         yaml:"log,omitempty"`
	Descr       string        `xml:"descr,omitempty"      json:"description,omitempty" yaml:"description,omitempty"`
	Category    string        `xml:"category,omitempty"   json:"category,omitempty"    yaml:"category,omitempty"`
	Tag         string        `xml:"tag,omitempty"        json:"tag,omitempty"         yaml:"tag,omitempty"`
	Tagged      string        `xml:"tagged,omitempty"     json:"tagged,omitempty"      yaml:"tagged,omitempty"`
	PoolOpts    string        `xml:"poolopts,omitempty"   json:"poolOpts,omitempty"    yaml:"poolOpts,omitempty"`
	Updated     *Updated      `xml:"updated,omitempty"    json:"updated,omitempty"     yaml:"updated,omitempty"`
	Created     *Created      `xml:"created,omitempty"    json:"created,omitempty"     yaml:"created,omitempty"`
	UUID        string        `xml:"uuid,attr,omitempty"  json:"uuid,omitempty"        yaml:"uuid,omitempty"`
}

// InboundRule represents an inbound NAT rule (port forwarding) with enhanced fields for security analysis.
type InboundRule struct {
	XMLName      xml.Name      `xml:"rule"`
	Interface    InterfaceList `xml:"interface,omitempty"    json:"interface,omitempty"    yaml:"interface,omitempty"`
	IPProtocol   string        `xml:"ipprotocol,omitempty"   json:"ipProtocol,omitempty"   yaml:"ipProtocol,omitempty"`
	Protocol     string        `xml:"protocol,omitempty"     json:"protocol,omitempty"     yaml:"protocol,omitempty"`
	Source       Source        `xml:"source"                 json:"source"                 yaml:"source"`
	Destination  Destination   `xml:"destination"            json:"destination"            yaml:"destination"`
	ExternalPort string        `xml:"externalport,omitempty" json:"externalPort,omitempty" yaml:"externalPort,omitempty"`
	InternalIP   string        `xml:"internalip,omitempty"   json:"internalIP,omitempty"   yaml:"internalIP,omitempty"`
	InternalPort string        `xml:"internalport,omitempty" json:"internalPort,omitempty" yaml:"internalPort,omitempty"`
	Reflection   string        `xml:"reflection,omitempty"   json:"reflection,omitempty"   yaml:"reflection,omitempty"`
	Priority     int           `xml:"priority,omitempty"     json:"priority,omitempty"     yaml:"priority,omitempty"`
	Disabled     BoolFlag      `xml:"disabled,omitempty"     json:"disabled,omitempty"     yaml:"disabled,omitempty"`
	Log          BoolFlag      `xml:"log,omitempty"          json:"log,omitempty"          yaml:"log,omitempty"`
	Descr        string        `xml:"descr,omitempty"        json:"description,omitempty"  yaml:"description,omitempty"`
	Updated      *Updated      `xml:"updated,omitempty"      json:"updated,omitempty"      yaml:"updated,omitempty"`
	Created      *Created      `xml:"created,omitempty"      json:"created,omitempty"      yaml:"created,omitempty"`
	UUID         string        `xml:"uuid,attr,omitempty"    json:"uuid,omitempty"         yaml:"uuid,omitempty"`
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
	Floating    string        `xml:"floating,omitempty"`
	Quick       BoolFlag      `xml:"quick,omitempty"`
	Protocol    string        `xml:"protocol,omitempty"`
	Source      Source        `xml:"source"`
	Destination Destination   `xml:"destination"`
	Target      string        `xml:"target,omitempty"`
	Gateway     string        `xml:"gateway,omitempty"`
	SourcePort  string        `xml:"sourceport,omitempty"`
	Log         BoolFlag      `xml:"log,omitempty"`
	Disabled    BoolFlag      `xml:"disabled,omitempty"`
	Tracker     string        `xml:"tracker,omitempty"`
	Updated     *Updated      `xml:"updated,omitempty"`
	Created     *Created      `xml:"created,omitempty"`
	UUID        string        `xml:"uuid,attr,omitempty"`
}

// Source represents a firewall rule source.
// Any is a pointer to distinguish XML element presence (<any/> → non-nil "")
// from absence (nil), since Go's encoding/xml produces "" for both self-closing
// tags and absent elements when using a plain string.
//
// Any, Network, and Address are mutually exclusive per OPNsense semantics.
// Resolution priority: Network > Address > Any (per legacyMoveAddressFields).
type Source struct {
	Any     *string  `xml:"any,omitempty"     json:"any,omitempty"     yaml:"any,omitempty"`
	Network string   `xml:"network,omitempty" json:"network,omitempty" yaml:"network,omitempty"`
	Address string   `xml:"address,omitempty" json:"address,omitempty" yaml:"address,omitempty"`
	Port    string   `xml:"port,omitempty"    json:"port,omitempty"    yaml:"port,omitempty"`
	Not     BoolFlag `xml:"not,omitempty"     json:"not,omitempty"     yaml:"not,omitempty"`
}

// IsAny returns true if the source represents "any" (the <any> element is present).
// OPNsense treats <any> as a presence-based flag; the element's value is irrelevant.
func (s Source) IsAny() bool {
	return s.Any != nil
}

// EffectiveAddress returns the resolved address target following OPNsense priority:
// Network > Address > "any" (if Any is present) > "" (empty).
func (s Source) EffectiveAddress() string {
	if s.Network != "" {
		return s.Network
	}
	if s.Address != "" {
		return s.Address
	}
	if s.IsAny() {
		return constants.NetworkAny
	}
	return ""
}

// Equal reports whether two Source values are semantically equal.
// Any is compared by presence only (nil vs non-nil), not by value,
// because OPNsense treats <any> as a presence-based flag.
func (s Source) Equal(other Source) bool {
	if (s.Any != nil) != (other.Any != nil) {
		return false
	}
	return s.Network == other.Network &&
		s.Address == other.Address &&
		s.Port == other.Port &&
		s.Not == other.Not
}

// Destination represents a firewall rule destination.
// Any is a pointer for the same reason as Source.Any.
//
// Any, Network, and Address are mutually exclusive per OPNsense semantics.
// Resolution priority: Network > Address > Any (per legacyMoveAddressFields).
type Destination struct {
	Any     *string  `xml:"any,omitempty"     json:"any,omitempty"     yaml:"any,omitempty"`
	Network string   `xml:"network,omitempty" json:"network,omitempty" yaml:"network,omitempty"`
	Address string   `xml:"address,omitempty" json:"address,omitempty" yaml:"address,omitempty"`
	Port    string   `xml:"port,omitempty"    json:"port,omitempty"    yaml:"port,omitempty"`
	Not     BoolFlag `xml:"not,omitempty"     json:"not,omitempty"     yaml:"not,omitempty"`
}

// IsAny returns true if the destination represents "any" (the <any> element is present).
// OPNsense treats <any> as a presence-based flag; the element's value is irrelevant.
func (d Destination) IsAny() bool {
	return d.Any != nil
}

// EffectiveAddress returns the resolved address target following OPNsense priority:
// Network > Address > "any" (if Any is present) > "" (empty).
func (d Destination) EffectiveAddress() string {
	if d.Network != "" {
		return d.Network
	}
	if d.Address != "" {
		return d.Address
	}
	if d.IsAny() {
		return constants.NetworkAny
	}
	return ""
}

// Equal reports whether two Destination values are semantically equal.
// Any is compared by presence only (nil vs non-nil), not by value,
// because OPNsense treats <any> as a presence-based flag.
func (d Destination) Equal(other Destination) bool {
	if (d.Any != nil) != (other.Any != nil) {
		return false
	}
	return d.Network == other.Network &&
		d.Address == other.Address &&
		d.Port == other.Port &&
		d.Not == other.Not
}

// StringPtr returns a pointer to the given string value.
// This is a convenience helper for constructing Source/Destination literals
// with the *string Any field:
//
//	src := Source{Any: StringPtr("1")}   // equivalent to <any>1</any>
//	dst := Destination{Any: StringPtr("")} // equivalent to <any/>
func StringPtr(s string) *string {
	return &s
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

// NewIDS creates a new IDS configuration with zero-value defaults.
func NewIDS() *IDS {
	return &IDS{}
}

// IDS helper methods

// IsEnabled returns true if the IDS is enabled.
func (ids *IDS) IsEnabled() bool {
	return ids != nil && ids.General.Enabled == "1"
}

// IsIPSMode returns true if the IDS is operating in IPS (Intrusion Prevention) mode.
func (ids *IDS) IsIPSMode() bool {
	return ids != nil && ids.General.Ips == "1"
}

// GetMonitoredInterfaces parses the comma-separated interfaces string and returns a slice.
func (ids *IDS) GetMonitoredInterfaces() []string {
	if ids == nil {
		return nil
	}
	return parseCommaSeparatedList(ids.General.Interfaces)
}

// GetHomeNetworks parses the comma-separated home networks string and returns a slice.
func (ids *IDS) GetHomeNetworks() []string {
	if ids == nil {
		return nil
	}
	return parseCommaSeparatedList(ids.General.Homenet)
}

// parseCommaSeparatedList splits a comma-separated string into a slice,
// trimming whitespace from each element and filtering out empty strings.
func parseCommaSeparatedList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetDetectionMode returns a human-readable description of the detection mode.
func (ids *IDS) GetDetectionMode() string {
	if ids == nil {
		return "Disabled"
	}
	if ids.General.Ips == "1" {
		return "IPS (Prevention)"
	}
	return "IDS (Detection Only)"
}

// IsSyslogEnabled returns true if syslog output is enabled.
func (ids *IDS) IsSyslogEnabled() bool {
	return ids != nil && ids.General.Syslog == "1"
}

// IsSyslogEveEnabled returns true if EVE syslog output is enabled.
func (ids *IDS) IsSyslogEveEnabled() bool {
	return ids != nil && ids.General.SyslogEve == "1"
}

// IsPromiscuousMode returns true if promiscuous mode is enabled.
func (ids *IDS) IsPromiscuousMode() bool {
	return ids != nil && ids.General.Promisc == "1"
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

// NewIPsec returns a pointer to a new IPsec configuration instance.
func NewIPsec() *IPsec {
	return &IPsec{}
}

// NewSwanctl returns a new instance of the Swanctl configuration struct.
func NewSwanctl() *Swanctl {
	return &Swanctl{}
}
