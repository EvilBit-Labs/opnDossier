// Package opnsense defines the data structures for OPNsense configurations.
package opnsense

import "encoding/xml"

// KeaDhcp4 contains the full Kea DHCP4 configuration including subnets and
// reservations as stored in the OPNsense MVC model (KeaDhcpv4.xml v1.0.4).
// Element names ("subnet4", "reservation") are pinned to this MVC model version;
// see GOTCHAS 18.1 for version compatibility notes.
type KeaDhcp4 struct {
	XMLName xml.Name `xml:"dhcp4"`
	Text    string   `xml:",chardata"              json:"text,omitempty"`
	Version string   `xml:"version,attr,omitempty" json:"version,omitempty"`
	General struct {
		Text          string `xml:",chardata" json:"text,omitempty"`
		Enabled       string `xml:"enabled"`
		Interfaces    string `xml:"interfaces"`
		FirewallRules string `xml:"fwrules"`
		ValidLifetime string `xml:"valid_lifetime"`
	} `xml:"general"                json:"general"`
	HighAvailability struct {
		Text              string `xml:",chardata" json:"text,omitempty"`
		Enabled           string `xml:"enabled"`
		ThisServerName    string `xml:"this_server_name"`
		MaxUnackedClients string `xml:"max_unacked_clients"`
	} `xml:"ha"                     json:"ha"`
	// Subnets are MVC ArrayField elements named "subnet4" under <subnets>.
	Subnets []KeaSubnet `xml:"subnets>subnet4"`
	// Reservations reference their parent subnet by UUID.
	Reservations []KeaReservation `xml:"reservations>reservation"`
	HAPeers      string           `xml:"ha_peers"`
}

// KeaSubnet represents a single Kea DHCP4 subnet definition.
type KeaSubnet struct {
	UUID                  string        `xml:"uuid,attr"`
	Subnet                string        `xml:"subnet"`                  // CIDR notation (e.g., "192.168.1.0/24")
	OptionDataAutocollect string        `xml:"option_data_autocollect"` // "0" or "1"
	OptionData            KeaOptionData `xml:"option_data"`
	// Pools contains newline-separated pool range strings from KeaPoolsField.
	// Each entry is either "start-end" (e.g., "192.168.1.100-192.168.1.200") or CIDR notation.
	Pools       string `xml:"pools"`
	NextServer  string `xml:"next_server"`
	Description string `xml:"description"`
}

// KeaOptionData contains DHCP options for a subnet or reservation.
// These map to standard DHCP option fields that Kea advertises to clients.
type KeaOptionData struct {
	DomainNameServers string `xml:"domain_name_servers"` // Comma-separated IPs
	DomainSearch      string `xml:"domain_search"`       // Comma-separated domains
	Routers           string `xml:"routers"`             // Gateway — comma-separated IPs
	DomainName        string `xml:"domain_name"`
	NTPServers        string `xml:"ntp_servers"` // Comma-separated IPs
	TFTPServerName    string `xml:"tftp_server_name"`
	BootFileName      string `xml:"boot_file_name"`
}

// KeaReservation represents a single Kea DHCP4 host reservation.
// The Subnet field references the parent subnet's UUID.
type KeaReservation struct {
	UUID        string        `xml:"uuid,attr"`
	Subnet      string        `xml:"subnet"` // UUID of parent subnet
	IPAddress   string        `xml:"ip_address"`
	HWAddress   string        `xml:"hw_address"`
	Hostname    string        `xml:"hostname"`
	Description string        `xml:"description"`
	OptionData  KeaOptionData `xml:"option_data"`
}
