package opnsense

import (
	"fmt"
	"net/netip"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// knownDnsmasqVersions lists the Dnsmasq model versions whose element names
// the schema was checked against. The model arrived in 25.1.2 at 1.0.0, and
// the releases since wrote 1.0.5 (25.1.6), 1.0.6 (25.1.8), 1.0.7 (25.1.10 to
// 25.7), 1.0.8 (25.7.11 to 26.1) and 1.0.9 (26.7). Each of those versions
// only added fields, and the model has a single migration, M1_0_0, which
// renames nothing. A version not listed here may have moved an element the
// converter reads (GOTCHAS 3.7, 18.1).
var knownDnsmasqVersions = map[string]struct{}{
	dnsmasqFirstModelVersion: {},
	"1.0.5":                  {},
	"1.0.6":                  {},
	"1.0.7":                  {},
	"1.0.8":                  {},
	"1.0.9":                  {},
}

const (
	// dnsmasqFirstModelVersion is the version the Dnsmasq model shipped at.
	dnsmasqFirstModelVersion = "1.0.0"

	// dnsmasqOptionSet is the dhcp_options type that sends an option. The
	// other type, "match", only tags clients.
	dnsmasqOptionSet = "set"

	// DHCPv4 option numbers the scope model has a field for.
	dhcpOptionRouter     = "3"
	dhcpOptionDNSServers = "6"
	dhcpOptionNTPServers = "42"
	dhcpOptionWINS       = "44"
)

// convertDNSMasq maps <dnsmasq> to common.DNSMasqConfig. The DHCP side of the
// same element becomes DHCP scopes in convertDnsmasqDHCPScopes.
func (c *converter) convertDNSMasq(doc *schema.OpnSenseDocument) common.DNSMasqConfig {
	dm := doc.DNSMasquerade

	if dm.Version != "" {
		if _, ok := knownDnsmasqVersions[dm.Version]; !ok {
			c.addWarning(
				"DNS.DNSMasq.Version",
				dm.Version,
				"unrecognized OPNsense Dnsmasq MVC model version; element mapping may be stale",
				common.SeverityMedium,
			)
		}
	}

	return common.DNSMasqConfig{
		Enabled:         bool(dm.Enable),
		DNSSEC:          dnsmasqDNSSEC(dm),
		Port:            strings.TrimSpace(dm.Port),
		Hosts:           convertDnsmasqHosts(dm.Hosts),
		DomainOverrides: convertDnsmasqDomainOverrides(dm.DomainOverrides),
		Forwarders:      c.convertForwarders(dm.Forwarders),
	}
}

// dnsmasqDNSSEC reports whether dnsmasq validates DNSSEC. The model's
// template writes `dnssec` only when the value is exactly "1". The legacy
// page, used up to 25.1.1, tested the element with isset(), so any
// <dnssec> element turned validation on there; a config without a model
// version attribute was written by that page.
func dnsmasqDNSSEC(dm schema.DNSMasq) bool {
	if dm.Dnssec == nil {
		return false
	}
	if dm.Version == "" {
		return true
	}

	return *dm.Dnssec == "1"
}

// convertDnsmasqHosts maps the <hosts> entries to DNS host overrides. Every
// entry is kept, including those that are only DHCP reservations, since the
// firewall writes each one with an address into its hosts file.
func convertDnsmasqHosts(hosts []schema.DNSMasqHost) []common.DNSMasqHost {
	if len(hosts) == 0 {
		return nil
	}

	result := make([]common.DNSMasqHost, 0, len(hosts))
	for _, h := range hosts {
		result = append(result, common.DNSMasqHost{
			Host:        h.Host,
			Domain:      h.Domain,
			IP:          h.IP,
			Description: h.Descr,
			Aliases:     []string(h.Aliases),
		})
	}

	return result
}

// convertDnsmasqDomainOverrides maps the <domainoverrides> entries.
func convertDnsmasqDomainOverrides(overrides []schema.DomainOverride) []common.DomainOverride {
	if len(overrides) == 0 {
		return nil
	}

	result := make([]common.DomainOverride, 0, len(overrides))
	for _, o := range overrides {
		result = append(result, common.DomainOverride{
			Domain:      o.Domain,
			IP:          o.IP,
			Description: o.Descr,
			Port:        o.Port,
			SourceIP:    o.SrcIP,
		})
	}

	return result
}

// convertDnsmasqDHCPScopes turns the dnsmasq <dhcp_ranges> into DHCP scopes,
// one per interface as for ISC, with the first IPv4 range in Range and the
// first IPv6 range in RangeV6. A range that names no interface serves every
// interface dnsmasq listens on and gets a scope with an empty Interface.
//
// A scope is enabled when dnsmasq is, unless dnsmasq does not serve DHCP on
// the interface: it is listed under <dhcp><no_interface>, or <interface>
// limits dnsmasq to other interfaces.
func (c *converter) convertDnsmasqDHCPScopes(doc *schema.OpnSenseDocument) []common.DHCPScope {
	dm := doc.DNSMasquerade
	if len(dm.DHCPRanges) == 0 {
		return nil
	}

	listen := csvSet(dm.Interface)
	var noDHCP map[string]struct{}
	if dm.DHCP != nil {
		noDHCP = csvSet(dm.DHCP.NoInterface)
	}
	servesOn := func(iface string) bool {
		if _, excluded := noDHCP[iface]; excluded && iface != "" {
			return false
		}
		if len(listen) == 0 || iface == "" {
			return true
		}
		_, ok := listen[iface]
		return ok
	}

	var scopes []common.DHCPScope
	index := make(map[string]int)
	for _, r := range dm.DHCPRanges {
		start := strings.TrimSpace(r.StartAddr)
		if start == "" {
			c.addWarning("dnsmasq.dhcp_ranges.start_addr", r.UUID,
				"dnsmasq DHCP range has no start address; dnsmasq does not serve it",
				common.SeverityLow)
			continue
		}

		iface := strings.TrimSpace(r.Interface)
		i, ok := index[iface]
		if !ok {
			i = len(scopes)
			index[iface] = i
			scopes = append(scopes, common.DHCPScope{
				Interface:   iface,
				Source:      common.DHCPSourceDnsmasq,
				Enabled:     bool(dm.Enable) && servesOn(iface),
				Description: r.Description,
			})
		}
		scope := &scopes[i]

		rng := common.DHCPRange{From: start, To: strings.TrimSpace(r.EndAddr)}
		// The template tells the families apart by a colon in start_addr.
		switch {
		case strings.Contains(start, ":") && scope.RangeV6 == nil:
			scope.RangeV6 = &rng
		case !strings.Contains(start, ":") && scope.Range == (common.DHCPRange{}):
			scope.Range = rng
		default:
			c.addWarning("dnsmasq.dhcp_ranges", fmt.Sprintf("%s - %s", rng.From, rng.To),
				fmt.Sprintf("dnsmasq serves more than one range of this address family on interface %q; "+
					"only the first is represented in the DHCP scope", iface),
				common.SeverityInfo)
		}
	}

	options := c.mappableDnsmasqOptions(dm.DHCPOptions)
	for i := range scopes {
		applyDnsmasqOptions(&scopes[i], options)
	}
	c.attachDnsmasqReservations(doc, scopes)

	return scopes
}

// mappableDnsmasqOptions returns the dhcp_options entries a DHCP scope can
// hold: DHCPv4 options sent to every client on an interface. Options that
// apply only to tagged clients, DHCPv6 options and match entries have no
// place in the scope and draw one warning each.
func (c *converter) mappableDnsmasqOptions(options []schema.DNSMasqDHCPOption) []schema.DNSMasqDHCPOption {
	var result []schema.DNSMasqDHCPOption
	for _, o := range options {
		kind := strings.TrimSpace(o.Type)
		if (kind != "" && kind != dnsmasqOptionSet) || strings.TrimSpace(o.Tag) != "" ||
			strings.TrimSpace(o.Option6) != "" || strings.TrimSpace(o.Option) == "" {
			c.addWarning("dnsmasq.dhcp_options", o.UUID,
				"dnsmasq DHCP option is tagged, DHCPv6 or a match entry; not represented in any DHCP scope",
				common.SeverityLow)
			continue
		}
		result = append(result, o)
	}

	return result
}

// applyDnsmasqOptions copies the options dnsmasq sends on the scope's
// interface into it. An option bound to the interface overrides one that
// names no interface, as the more specific dhcp-option tag wins in dnsmasq.
func applyDnsmasqOptions(scope *common.DHCPScope, options []schema.DNSMasqDHCPOption) {
	values := make(map[string]string)
	var order []string
	for _, global := range []bool{true, false} {
		for _, o := range options {
			iface := strings.TrimSpace(o.Interface)
			if (iface == "") != global || (!global && iface != scope.Interface) {
				continue
			}
			number := strings.TrimSpace(o.Option)
			if _, seen := values[number]; !seen {
				order = append(order, number)
			}
			values[number] = o.Value
		}
	}

	for _, number := range order {
		value := values[number]
		switch number {
		case dhcpOptionRouter:
			scope.Gateway = firstCSV(value)
		case dhcpOptionDNSServers:
			scope.SetDNSServers(splitCSV(value))
		case dhcpOptionNTPServers:
			scope.NTPServer = firstCSV(value)
		case dhcpOptionWINS:
			scope.WINSServer = firstCSV(value)
		default:
			scope.NumberOptions = append(scope.NumberOptions, common.DHCPNumberOption{
				Number: number,
				Value:  value,
			})
		}
	}
}

// attachDnsmasqReservations turns the <hosts> entries dnsmasq hands out as
// DHCP reservations into static leases. The template writes a dhcp-host line
// for an entry with a client id, or with a hardware address holding a colon.
//
// A host entry names no interface; dnsmasq applies it on the range whose
// network holds its address. The lease goes to the scope whose interface
// network holds the entry's first IPv4 address. Failing that it goes to the
// only scope with an IPv4 range, or to the scope that names no interface,
// and an entry with no home is reported rather than dropped silently.
func (c *converter) attachDnsmasqReservations(doc *schema.OpnSenseDocument, scopes []common.DHCPScope) {
	fallback := -1
	v4Scopes := 0
	for i := range scopes {
		if scopes[i].Range.From != "" {
			v4Scopes++
			fallback = i
		}
	}
	if v4Scopes != 1 {
		fallback = -1
	}
	for i := range scopes {
		if scopes[i].Interface == "" {
			fallback = i
			break
		}
	}

	for _, h := range doc.DNSMasquerade.Hosts {
		clientID := strings.TrimSpace(h.ClientID)
		hwaddr := strings.TrimSpace(h.HWAddr)
		if clientID == "" && !strings.Contains(hwaddr, ":") {
			continue
		}
		label := strings.TrimSpace(h.Host)
		if label == "" {
			label = hwaddr + clientID
		}
		if strings.TrimSpace(h.Ignore) == "1" {
			c.addWarning("dnsmasq.hosts.ignore", label,
				"dnsmasq is told to ignore this DHCP client; the entry is not a lease and is not represented",
				common.SeverityLow)
			continue
		}

		target := dnsmasqScopeFor(doc, scopes, h.IP)
		if target < 0 {
			target = fallback
		}
		if target < 0 {
			c.addWarning("dnsmasq.hosts", label,
				"dnsmasq DHCP reservation matches no DHCP range's interface network; not attached to a scope",
				common.SeverityLow)
			continue
		}

		scopes[target].StaticLeases = append(scopes[target].StaticLeases, common.DHCPStaticLease{
			MAC:         hwaddr,
			CID:         clientID,
			IPAddress:   strings.TrimSpace(h.IP),
			Hostname:    strings.TrimSpace(h.Host),
			Description: h.Descr,
		})
	}
}

// dnsmasqScopeFor returns the index of the scope whose interface network
// holds the first IPv4 address in ips, or -1.
func dnsmasqScopeFor(doc *schema.OpnSenseDocument, scopes []common.DHCPScope, ips string) int {
	var addr netip.Addr
	for entry := range strings.SplitSeq(ips, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(entry)); err == nil && a.Is4() {
			addr = a
			break
		}
	}
	if !addr.IsValid() {
		return -1
	}

	for i := range scopes {
		if scopes[i].Interface == "" || scopes[i].Range.From == "" {
			continue
		}
		iface, ok := doc.Interfaces.Items[scopes[i].Interface]
		if !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(iface.IPAddr) + "/" + strings.TrimSpace(iface.Subnet))
		if err == nil && prefix.Contains(addr) {
			return i
		}
	}

	return -1
}

// csvSet returns the trimmed, non-empty members of a comma-separated list.
func csvSet(s string) map[string]struct{} {
	members := splitCSV(s)
	if len(members) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(members))
	for _, m := range members {
		set[m] = struct{}{}
	}

	return set
}

// convertAllDHCPScopes collects the scopes of every DHCP server OPNsense
// offers: ISC, Kea and dnsmasq.
func (c *converter) convertAllDHCPScopes(doc *schema.OpnSenseDocument) []common.DHCPScope {
	scopes := append(c.convertDHCP(doc), c.convertKeaDHCPScopes(doc)...)

	return append(scopes, c.convertDnsmasqDHCPScopes(doc)...)
}
