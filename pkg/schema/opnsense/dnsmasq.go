package opnsense

import (
	"encoding/xml"
	"strings"
)

// DNSMasqDHCP holds the <dnsmasq><dhcp> settings block of the Dnsmasq model.
type DNSMasqDHCP struct {
	// NoInterface is the comma-separated list of interfaces dnsmasq serves
	// DNS on but not DHCP.
	NoInterface string `xml:"no_interface,omitempty"`
}

// DNSMasqDHCPRange is one <dhcp_ranges> entry of the Dnsmasq model. The
// template treats a start address holding a colon as an IPv6 range and every
// other one as IPv4. An IPv6 range usually holds only the host part of the
// address (::1000), which dnsmasq completes from the prefix of the interface
// named in Constructor.
type DNSMasqDHCPRange struct {
	UUID        string `xml:"uuid,attr,omitempty"`
	Interface   string `xml:"interface,omitempty"`
	SetTag      string `xml:"set_tag,omitempty"`
	StartAddr   string `xml:"start_addr,omitempty"`
	EndAddr     string `xml:"end_addr,omitempty"`
	SubnetMask  string `xml:"subnet_mask,omitempty"`
	Constructor string `xml:"constructor,omitempty"`
	Mode        string `xml:"mode,omitempty"`
	PrefixLen   string `xml:"prefix_len,omitempty"`
	LeaseTime   string `xml:"lease_time,omitempty"`
	DomainType  string `xml:"domain_type,omitempty"`
	Domain      string `xml:"domain,omitempty"`
	RAMode      string `xml:"ra_mode,omitempty"`
	Description string `xml:"description,omitempty"`
}

// DNSMasqDHCPOption is one <dhcp_options> entry of the Dnsmasq model. Option
// holds a DHCPv4 option number and Option6 a DHCPv6 one; the template uses
// Option6 when both are set. Type is "set" (the default) or "match".
type DNSMasqDHCPOption struct {
	UUID        string `xml:"uuid,attr,omitempty"`
	Type        string `xml:"type,omitempty"`
	Option      string `xml:"option,omitempty"`
	Option6     string `xml:"option6,omitempty"`
	Interface   string `xml:"interface,omitempty"`
	Tag         string `xml:"tag,omitempty"`
	SetTag      string `xml:"set_tag,omitempty"`
	Value       string `xml:"value,omitempty"`
	Force       string `xml:"force,omitempty"`
	Description string `xml:"description,omitempty"`
}

// DNSMasqHostAliases holds the extra names of a dnsmasq host override, each
// a full name such as files.example.com.
//
// The two generations write <aliases> differently. The model stores one
// comma-separated list as text. The legacy page stored one <item> per alias
// with <host>, <domain> and <description> children. Both decode here; the
// encoder writes the model's form, as OPNsense itself does once the model
// has loaded a legacy config.
type DNSMasqHostAliases []string

// legacyAliasItem is one <item> of the legacy <aliases> shape.
type legacyAliasItem struct {
	Host   string `xml:"host"`
	Domain string `xml:"domain"`
}

// UnmarshalXML decodes either <aliases> shape. A legacy item without a
// domain is skipped, and one without a host reads as its domain alone, as
// the model's HostnameField flattens them.
func (a *DNSMasqHostAliases) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var (
		text  strings.Builder
		names []string
	)

	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.CharData:
			text.Write(t)
		case xml.StartElement:
			if t.Name.Local != "item" {
				if err := d.Skip(); err != nil {
					return err
				}
				continue
			}
			var item legacyAliasItem
			if err := d.DecodeElement(&item, &t); err != nil {
				return err
			}
			domain := strings.TrimSpace(item.Domain)
			if domain == "" {
				continue
			}
			if host := strings.TrimSpace(item.Host); host != "" {
				names = append(names, host+"."+domain)
			} else {
				names = append(names, domain)
			}
		case xml.EndElement:
			if t.Name == start.Name {
				for entry := range strings.SplitSeq(text.String(), ",") {
					if entry = strings.TrimSpace(entry); entry != "" {
						names = append(names, entry)
					}
				}
				*a = names
				return nil
			}
		}
	}
}

// MarshalXML writes the aliases as the model's comma-separated text, and
// nothing when there are none. It has a value receiver so that a host
// encoded by value still finds it (GOTCHAS 15.1).
func (a DNSMasqHostAliases) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(a) == 0 {
		return nil
	}

	return e.EncodeElement(strings.Join(a, ","), start)
}
