// Package schema defines the data structures for OPNsense configurations.
package schema

import (
	"encoding/xml"
)

// CertificateAuthority represents certificate authority configuration.
type CertificateAuthority struct {
	XMLName xml.Name `xml:"ca"              json:"-"               yaml:"-"`
	Refid   string   `xml:"refid,omitempty" json:"refid,omitempty" yaml:"refid,omitempty"`
	Descr   string   `xml:"descr,omitempty" json:"descr,omitempty" yaml:"descr,omitempty"`
	Crt     string   `xml:"crt,omitempty"   json:"crt,omitempty"   yaml:"crt,omitempty"`
}

// DHCPv6Server represents DHCPv6 server configuration.
type DHCPv6Server struct {
	XMLName xml.Name `xml:"dhcpdv6" json:"-" yaml:"-"`
}
