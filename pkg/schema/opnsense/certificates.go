// Package opnsense defines the data structures for OPNsense configurations.
package opnsense

import (
	"encoding/xml"
)

// CertificateAuthority represents a certificate authority entry in the OPNsense trust store,
// containing the CA certificate (Crt), private key (Prv), reference ID, serial number, and description.
type CertificateAuthority struct {
	XMLName xml.Name `xml:"ca"               json:"-"                yaml:"-"`
	Refid   string   `xml:"refid,omitempty"  json:"refid,omitempty"  yaml:"refid,omitempty"`
	Descr   string   `xml:"descr,omitempty"  json:"descr,omitempty"  yaml:"descr,omitempty"`
	Crt     string   `xml:"crt,omitempty"    json:"crt,omitempty"    yaml:"crt,omitempty"`
	Prv     string   `xml:"prv,omitempty"    json:"prv,omitempty"    yaml:"prv,omitempty"`
	Serial  string   `xml:"serial,omitempty" json:"serial,omitempty" yaml:"serial,omitempty"`
}

// DHCPv6Server represents the DHCPv6 server configuration container.
// This is currently a placeholder struct for the <dhcpdv6> XML element.
type DHCPv6Server struct {
	XMLName xml.Name `xml:"dhcpdv6" json:"-" yaml:"-"`
}
