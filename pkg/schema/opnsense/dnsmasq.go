package opnsense

import (
	"encoding/xml"
	"strings"
)

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
