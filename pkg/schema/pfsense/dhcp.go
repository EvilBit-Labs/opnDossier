// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"
	"fmt"
	"maps"
	"slices"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// DhcpdInterface contains the DHCP server configuration for a specific pfSense interface.
// It is a copy-on-write fork of opnsense.DhcpdInterface with Enable changed from string
// to BoolFlag, because pfSense uses presence-based <enable/> elements.
type DhcpdInterface struct {
	Enable              opnsense.BoolFlag           `xml:"enable,omitempty"              json:"enable,omitempty"              yaml:"enable,omitempty"`
	Range               opnsense.Range              `xml:"range,omitempty"               json:"range"                         yaml:"range,omitempty"`
	Gateway             string                      `xml:"gateway,omitempty"             json:"gateway,omitempty"             yaml:"gateway,omitempty"`
	DdnsDomainAlgorithm string                      `xml:"ddnsdomainalgorithm,omitempty" json:"ddnsdomainalgorithm,omitempty" yaml:"ddnsdomainalgorithm,omitempty"`
	NumberOptions       []opnsense.DHCPNumberOption `xml:"numberoptions>item,omitempty"  json:"numberOptions,omitempty"       yaml:"numberOptions,omitempty"`
	Winsserver          string                      `xml:"winsserver,omitempty"          json:"winsserver,omitempty"          yaml:"winsserver,omitempty"`
	Dnsserver           string                      `xml:"dnsserver,omitempty"           json:"dnsserver,omitempty"           yaml:"dnsserver,omitempty"`
	Ntpserver           string                      `xml:"ntpserver,omitempty"           json:"ntpserver,omitempty"           yaml:"ntpserver,omitempty"`
	Staticmap           []opnsense.DHCPStaticLease  `xml:"staticmap,omitempty"           json:"staticmap,omitempty"           yaml:"staticmap,omitempty"`

	// Advanced DHCP fields
	AliasAddress   string `xml:"alias-address,omitempty"  json:"aliasAddress,omitempty"   yaml:"aliasAddress,omitempty"`
	AliasSubnet    string `xml:"alias-subnet,omitempty"   json:"aliasSubnet,omitempty"    yaml:"aliasSubnet,omitempty"`
	DHCPRejectFrom string `xml:"dhcprejectfrom,omitempty" json:"dhcprejectfrom,omitempty" yaml:"dhcprejectfrom,omitempty"`

	// Advanced DHCP options
	AdvDHCPPTTimeout              string `xml:"adv_dhcp_pt_timeout,omitempty"                json:"advDhcpPtTimeout,omitempty"              yaml:"advDhcpPtTimeout,omitempty"`
	AdvDHCPPTRetry                string `xml:"adv_dhcp_pt_retry,omitempty"                  json:"advDhcpPtRetry,omitempty"                yaml:"advDhcpPtRetry,omitempty"`
	AdvDHCPPTSelectTimeout        string `xml:"adv_dhcp_pt_select_timeout,omitempty"         json:"advDhcpPtSelectTimeout,omitempty"        yaml:"advDhcpPtSelectTimeout,omitempty"`
	AdvDHCPPTReboot               string `xml:"adv_dhcp_pt_reboot,omitempty"                 json:"advDhcpPtReboot,omitempty"               yaml:"advDhcpPtReboot,omitempty"`
	AdvDHCPPTBackoffCutoff        string `xml:"adv_dhcp_pt_backoff_cutoff,omitempty"         json:"advDhcpPtBackoffCutoff,omitempty"        yaml:"advDhcpPtBackoffCutoff,omitempty"`
	AdvDHCPPTInitialInterval      string `xml:"adv_dhcp_pt_initial_interval,omitempty"       json:"advDhcpPtInitialInterval,omitempty"      yaml:"advDhcpPtInitialInterval,omitempty"`
	AdvDHCPPTValues               string `xml:"adv_dhcp_pt_values,omitempty"                 json:"advDhcpPtValues,omitempty"               yaml:"advDhcpPtValues,omitempty"`
	AdvDHCPSendOptions            string `xml:"adv_dhcp_send_options,omitempty"              json:"advDhcpSendOptions,omitempty"            yaml:"advDhcpSendOptions,omitempty"`
	AdvDHCPRequestOptions         string `xml:"adv_dhcp_request_options,omitempty"           json:"advDhcpRequestOptions,omitempty"         yaml:"advDhcpRequestOptions,omitempty"`
	AdvDHCPRequiredOptions        string `xml:"adv_dhcp_required_options,omitempty"          json:"advDhcpRequiredOptions,omitempty"        yaml:"advDhcpRequiredOptions,omitempty"`
	AdvDHCPOptionModifiers        string `xml:"adv_dhcp_option_modifiers,omitempty"          json:"advDhcpOptionModifiers,omitempty"        yaml:"advDhcpOptionModifiers,omitempty"`
	AdvDHCPConfigAdvanced         string `xml:"adv_dhcp_config_advanced,omitempty"           json:"advDhcpConfigAdvanced,omitempty"         yaml:"advDhcpConfigAdvanced,omitempty"`
	AdvDHCPConfigFileOverride     string `xml:"adv_dhcp_config_file_override,omitempty"      json:"advDhcpConfigFileOverride,omitempty"     yaml:"advDhcpConfigFileOverride,omitempty"`
	AdvDHCPConfigFileOverridePath string `xml:"adv_dhcp_config_file_override_path,omitempty" json:"advDhcpConfigFileOverridePath,omitempty" yaml:"advDhcpConfigFileOverridePath,omitempty"`

	// Advanced DHCPv6 fields
	Track6Interface                                 string `xml:"track6-interface,omitempty"                                      json:"track6Interface,omitempty"                                 yaml:"track6Interface,omitempty"`
	Track6PrefixID                                  string `xml:"track6-prefix-id,omitempty"                                      json:"track6PrefixId,omitempty"                                  yaml:"track6PrefixId,omitempty"`
	AdvDHCP6InterfaceStatementSendOptions           string `xml:"adv_dhcp6_interface_statement_send_options,omitempty"            json:"advDhcp6InterfaceStatementSendOptions,omitempty"           yaml:"advDhcp6InterfaceStatementSendOptions,omitempty"`
	AdvDHCP6InterfaceStatementRequestOptions        string `xml:"adv_dhcp6_interface_statement_request_options,omitempty"         json:"advDhcp6InterfaceStatementRequestOptions,omitempty"        yaml:"advDhcp6InterfaceStatementRequestOptions,omitempty"`
	AdvDHCP6InterfaceStatementInformationOnlyEnable string `xml:"adv_dhcp6_interface_statement_information_only_enable,omitempty" json:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty" yaml:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty"`
	AdvDHCP6InterfaceStatementScript                string `xml:"adv_dhcp6_interface_statement_script,omitempty"                  json:"advDhcp6InterfaceStatementScript,omitempty"                yaml:"advDhcp6InterfaceStatementScript,omitempty"`
	AdvDHCP6IDAssocStatementAddressEnable           string `xml:"adv_dhcp6_id_assoc_statement_address_enable,omitempty"           json:"advDhcp6IdAssocStatementAddressEnable,omitempty"           yaml:"advDhcp6IdAssocStatementAddressEnable,omitempty"`
	AdvDHCP6IDAssocStatementAddress                 string `xml:"adv_dhcp6_id_assoc_statement_address,omitempty"                  json:"advDhcp6IdAssocStatementAddress,omitempty"                 yaml:"advDhcp6IdAssocStatementAddress,omitempty"`
	AdvDHCP6IDAssocStatementAddressID               string `xml:"adv_dhcp6_id_assoc_statement_address_id,omitempty"               json:"advDhcp6IdAssocStatementAddressId,omitempty"               yaml:"advDhcp6IdAssocStatementAddressId,omitempty"`
	AdvDHCP6IDAssocStatementAddressPLTime           string `xml:"adv_dhcp6_id_assoc_statement_address_pltime,omitempty"           json:"advDhcp6IdAssocStatementAddressPltime,omitempty"           yaml:"advDhcp6IdAssocStatementAddressPltime,omitempty"`
	AdvDHCP6IDAssocStatementAddressVLTime           string `xml:"adv_dhcp6_id_assoc_statement_address_vltime,omitempty"           json:"advDhcp6IdAssocStatementAddressVltime,omitempty"           yaml:"advDhcp6IdAssocStatementAddressVltime,omitempty"`
	AdvDHCP6IDAssocStatementPrefixEnable            string `xml:"adv_dhcp6_id_assoc_statement_prefix_enable,omitempty"            json:"advDhcp6IdAssocStatementPrefixEnable,omitempty"            yaml:"advDhcp6IdAssocStatementPrefixEnable,omitempty"`
	AdvDHCP6IDAssocStatementPrefix                  string `xml:"adv_dhcp6_id_assoc_statement_prefix,omitempty"                   json:"advDhcp6IdAssocStatementPrefix,omitempty"                  yaml:"advDhcp6IdAssocStatementPrefix,omitempty"`
	AdvDHCP6IDAssocStatementPrefixID                string `xml:"adv_dhcp6_id_assoc_statement_prefix_id,omitempty"                json:"advDhcp6IdAssocStatementPrefixId,omitempty"                yaml:"advDhcp6IdAssocStatementPrefixId,omitempty"`
	AdvDHCP6IDAssocStatementPrefixPLTime            string `xml:"adv_dhcp6_id_assoc_statement_prefix_pltime,omitempty"            json:"advDhcp6IdAssocStatementPrefixPltime,omitempty"            yaml:"advDhcp6IdAssocStatementPrefixPltime,omitempty"`
	AdvDHCP6IDAssocStatementPrefixVLTime            string `xml:"adv_dhcp6_id_assoc_statement_prefix_vltime,omitempty"            json:"advDhcp6IdAssocStatementPrefixVltime,omitempty"            yaml:"advDhcp6IdAssocStatementPrefixVltime,omitempty"`
	AdvDHCP6PrefixInterfaceStatementSLALen          string `xml:"adv_dhcp6_prefix_interface_statement_sla_len,omitempty"          json:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty"          yaml:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty"`
	AdvDHCP6AuthenticationStatementAuthName         string `xml:"adv_dhcp6_authentication_statement_authname,omitempty"           json:"advDhcp6AuthenticationStatementAuthname,omitempty"         yaml:"advDhcp6AuthenticationStatementAuthname,omitempty"`
	AdvDHCP6AuthenticationStatementProtocol         string `xml:"adv_dhcp6_authentication_statement_protocol,omitempty"           json:"advDhcp6AuthenticationStatementProtocol,omitempty"         yaml:"advDhcp6AuthenticationStatementProtocol,omitempty"`
	AdvDHCP6AuthenticationStatementAlgorithm        string `xml:"adv_dhcp6_authentication_statement_algorithm,omitempty"          json:"advDhcp6AuthenticationStatementAlgorithm,omitempty"        yaml:"advDhcp6AuthenticationStatementAlgorithm,omitempty"`
	AdvDHCP6AuthenticationStatementRDM              string `xml:"adv_dhcp6_authentication_statement_rdm,omitempty"                json:"advDhcp6AuthenticationStatementRdm,omitempty"              yaml:"advDhcp6AuthenticationStatementRdm,omitempty"`
	AdvDHCP6KeyInfoStatementKeyName                 string `xml:"adv_dhcp6_key_info_statement_keyname,omitempty"                  json:"advDhcp6KeyInfoStatementKeyname,omitempty"                 yaml:"advDhcp6KeyInfoStatementKeyname,omitempty"`
	AdvDHCP6KeyInfoStatementRealm                   string `xml:"adv_dhcp6_key_info_statement_realm,omitempty"                    json:"advDhcp6KeyInfoStatementRealm,omitempty"                   yaml:"advDhcp6KeyInfoStatementRealm,omitempty"`
	AdvDHCP6KeyInfoStatementKeyID                   string `xml:"adv_dhcp6_key_info_statement_keyid,omitempty"                    json:"advDhcp6KeyInfoStatementKeyId,omitempty"                   yaml:"advDhcp6KeyInfoStatementKeyId,omitempty"`
	AdvDHCP6KeyInfoStatementSecret                  string `xml:"adv_dhcp6_key_info_statement_secret,omitempty"                   json:"advDhcp6KeyInfoStatementSecret,omitempty"                  yaml:"advDhcp6KeyInfoStatementSecret,omitempty"`
	AdvDHCP6KeyInfoStatementExpire                  string `xml:"adv_dhcp6_key_info_statement_expire,omitempty"                   json:"advDhcp6KeyInfoStatementExpire,omitempty"                  yaml:"advDhcp6KeyInfoStatementExpire,omitempty"`
	AdvDHCP6ConfigAdvanced                          string `xml:"adv_dhcp6_config_advanced,omitempty"                             json:"advDhcp6ConfigAdvanced,omitempty"                          yaml:"advDhcp6ConfigAdvanced,omitempty"`
	AdvDHCP6ConfigFileOverride                      string `xml:"adv_dhcp6_config_file_override,omitempty"                        json:"advDhcp6ConfigFileOverride,omitempty"                      yaml:"advDhcp6ConfigFileOverride,omitempty"`
	AdvDHCP6ConfigFileOverridePath                  string `xml:"adv_dhcp6_config_file_override_path,omitempty"                   json:"advDhcp6ConfigFileOverridePath,omitempty"                  yaml:"advDhcp6ConfigFileOverridePath,omitempty"`
}

// dhcpdInterfaceAlias is a type alias used to break the recursion in DhcpdInterface.MarshalXML.
// encoding/xml would infinitely recurse if MarshalXML called EncodeElement on the same type.
type dhcpdInterfaceAlias DhcpdInterface

// MarshalXML implements custom XML marshaling for DhcpdInterface, ensuring that the
// Enable BoolFlag field is addressable so (*BoolFlag).MarshalXML is invoked.
// Without this, direct xml.Marshal calls on DhcpdInterface values would fall back to
// default bool serialization instead of producing pfSense-compatible <enable/> elements.
// Uses a value receiver so both value and pointer marshaling work correctly.
func (d DhcpdInterface) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement((*dhcpdInterfaceAlias)(&d), start)
}

// Dhcpd contains the DHCP server configuration for all pfSense interfaces.
// Uses a map-based representation where keys are interface identifiers (wan, lan, opt0, etc.).
type Dhcpd struct {
	Items map[string]DhcpdInterface `xml:",any" json:"dhcp,omitempty" yaml:"dhcp,omitempty"`
}

// UnmarshalXML implements custom XML unmarshaling for the Dhcpd map.
func (d *Dhcpd) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	d.Items = make(map[string]DhcpdInterface)

	for {
		tok, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("failed to read Dhcpd token: %w", err)
		}

		switch se := tok.(type) {
		case xml.StartElement:
			var dhcpIface DhcpdInterface
			if err := decoder.DecodeElement(&dhcpIface, &se); err != nil {
				return fmt.Errorf("failed to decode DHCP interface %s: %w", se.Name.Local, err)
			}

			d.Items[se.Name.Local] = dhcpIface
		case xml.EndElement:
			if se.Name == start.Name {
				return nil
			}
		}
	}
}

// MarshalXML implements custom XML marshaling for the Dhcpd map.
func (d *Dhcpd) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}

	for _, key := range slices.Sorted(maps.Keys(d.Items)) {
		dhcpIface := d.Items[key]
		ifaceStart := xml.StartElement{Name: xml.Name{Local: key}}
		if err := e.EncodeElement(&dhcpIface, ifaceStart); err != nil {
			return err
		}
	}

	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

// Get returns a DHCP interface configuration by its key name (e.g., "wan", "lan", "opt0").
// Returns the DHCP interface configuration and a boolean indicating if it was found.
func (d *Dhcpd) Get(key string) (DhcpdInterface, bool) {
	if d.Items == nil {
		return DhcpdInterface{}, false
	}

	dhcpIface, ok := d.Items[key]

	return dhcpIface, ok
}

// Names returns a sorted list of all DHCP interface names.
func (d *Dhcpd) Names() []string {
	if d.Items == nil {
		return []string{}
	}

	return slices.Sorted(maps.Keys(d.Items))
}

// Wan returns the WAN DHCP configuration if it exists, otherwise returns a zero-value DhcpdInterface and false.
func (d *Dhcpd) Wan() (DhcpdInterface, bool) {
	return d.Get("wan")
}

// Lan returns the LAN DHCP configuration if it exists, otherwise returns a zero-value DhcpdInterface and false.
func (d *Dhcpd) Lan() (DhcpdInterface, bool) {
	return d.Get("lan")
}
