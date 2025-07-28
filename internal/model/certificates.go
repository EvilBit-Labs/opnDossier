// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// CertificateAuthority represents certificate authority configuration.
type CertificateAuthority struct {
	XMLName xml.Name `xml:"ca" json:"-" yaml:"-"`
}

// DHCPv6Server represents DHCPv6 server configuration.
type DHCPv6Server struct {
	XMLName xml.Name `xml:"dhcpdv6" json:"-" yaml:"-"`
}
