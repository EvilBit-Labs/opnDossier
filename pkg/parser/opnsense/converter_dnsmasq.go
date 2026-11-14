package opnsense

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// knownDnsmasqVersions lists the Dnsmasq model versions whose element names
// the schema was checked against. The model arrived in 25.1.2 at 1.0.0, and
// the releases since wrote 1.0.5 (25.1.6), 1.0.6 (25.1.8), 1.0.7 (25.1.10 to
// 25.7.1), 1.0.8 (25.7.2 to 26.1.4) and 1.0.9 (26.1.5 on). Each of those versions
// only added fields, and the model has a single migration, M1_0_0, which
// renames nothing. A version not listed here may have moved an element the
// converter reads (GOTCHAS 3.7, 18.1). One literal keeps the version strings
// clear of goconst's count across the package's other version sets.
var knownDnsmasqVersions = strings.Fields("1.0.0 1.0.5 1.0.6 1.0.7 1.0.8 1.0.9")

const (
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
		if !slices.Contains(knownDnsmasqVersions, dm.Version) {
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
// <dnssec> element turned validation on there. A config without a model
// version attribute was written either by that page or by a writer that
// leaves <dnssec> out, such as the factory default and the console's
// set-IP flow, so reading presence is right for all of them.
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
// firewall writes each one with an address into its hosts file. An empty
// placeholder is dropped (GOTCHAS 3.4).
//
// The legacy page let an entry name only a domain and answered for the
// domain itself; migration M1_0_0 moves such a domain into <host>, and the
// same is done here so that both generations read alike.
func convertDnsmasqHosts(hosts []schema.DNSMasqHost) []common.DNSMasqHost {
	var result []common.DNSMasqHost
	for _, h := range hosts {
		if h.IsPlaceholder() {
			continue
		}
		host, domain := h.Host, h.Domain
		if host == "" {
			host, domain = domain, ""
		}
		result = append(result, common.DNSMasqHost{
			Host:        host,
			Domain:      domain,
			IP:          h.IP,
			Description: h.Descr,
			Aliases:     []string(h.Aliases),
		})
	}

	return result
}

// convertDnsmasqDomainOverrides maps the <domainoverrides> entries, dropping
// an empty placeholder (GOTCHAS 3.4).
func convertDnsmasqDomainOverrides(overrides []schema.DomainOverride) []common.DomainOverride {
	var result []common.DomainOverride
	for _, o := range overrides {
		if o.IsPlaceholder() {
			continue
		}
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

// dnsmasqScopeNets holds what a dnsmasq scope's ranges say about the IPv6
// addresses it serves, which the scope model has no field for.
type dnsmasqScopeNets struct {
	// v6 holds the IPv6 networks of the scope: its interface's static
	// network, the constructor interface's, and the prefix of a range given
	// as a full address.
	v6 []netip.Prefix
	// v4 holds the IPv4 network of a range no interface's network holds,
	// which dnsmasq can serve only through a relay agent: the start address
	// with the range's subnet mask, or the address's class when the mask is
	// empty, as dnsmasq(8) guesses for a relayed network.
	v4 []netip.Prefix
	// constructed is set when a range is built from an interface's prefix,
	// where a reservation holding only a host part (::50) applies.
	constructed bool
}

// convertDnsmasqDHCPScopes turns the dnsmasq <dhcp_ranges> into DHCP scopes,
// one per interface as for ISC, with the first IPv4 range in Range and the
// first IPv6 range in RangeV6.
//
// A range that names no interface (Any) is written without an interface tag,
// and dnsmasq serves it on the interface whose network holds it, or whose
// prefix its constructor names. Such a range gets the scope of that
// interface. One that no interface's network holds serves no interface the
// config describes; it keeps a scope of its own with an empty Interface.
//
// A scope is enabled when dnsmasq is, unless dnsmasq does not serve DHCP on
// the interface: it is listed under <dhcp><no_interface>, or <interface>
// limits dnsmasq to other interfaces.
//
// Some entries hand out no pool. A static range serves only the
// reservations, so its scope keeps an empty range. An IPv6 range with
// ra-stateless in its RA mode answers stateless DHCPv6 and allocates no
// address, with or without an end address (dnsmasq skips such a context when
// it allocates), so its scope is kept with no RangeV6. Any other IPv6 entry
// with no end address hands out no addresses either (the range dialog's help;
// Dnsmasq.php requires an end address only for an IPv4 range that is not
// static): it only sends router advertisements, which is not DHCP, and it
// makes no scope. An end address makes dnsmasq serve DHCP from the range
// whatever else the RA mode holds, ra-only included.
func (c *converter) convertDnsmasqDHCPScopes(doc *schema.OpnSenseDocument) []common.DHCPScope {
	dm := doc.DNSMasquerade
	if len(dm.DHCPRanges) == 0 {
		return nil
	}

	servesOn := dnsmasqServesOn(dm)
	var (
		scopes []common.DHCPScope
		nets   []dnsmasqScopeNets
	)
	index := make(map[string]int)
	for n, r := range dm.DHCPRanges {
		if r.IsPlaceholder() {
			continue
		}
		start, end := strings.TrimSpace(r.StartAddr), strings.TrimSpace(r.EndAddr)
		kind := classifyDnsmasqRange(r, start, end)
		v6 := kind.v6
		if !kind.serves {
			continue
		}
		if start == "" {
			c.addWarning("dnsmasq.dhcp_ranges.start_addr", r.UUID,
				"dnsmasq DHCP range has no start address; dnsmasq does not serve it",
				common.SeverityLow)
			continue
		}

		iface := dnsmasqRangeInterface(doc, r, start)
		key := iface
		if key == "" {
			// No interface serves it; keep it apart from every other range.
			key = fmt.Sprintf("\x00%d", n)
		}
		i, ok := index[key]
		if !ok {
			i = len(scopes)
			index[key] = i
			scopes = append(scopes, common.DHCPScope{
				Interface:   iface,
				Source:      common.DHCPSourceDnsmasq,
				Enabled:     bool(dm.Enable) && servesOn(iface),
				Description: r.Description,
			})
			nets = append(nets, dnsmasqScopeNets{})
			if p, ok := interfaceNetwork6(doc, iface); ok {
				nets[i].v6 = append(nets[i].v6, p)
			}
		}
		if v6 {
			addRangeNetworks6(doc, &nets[i], r, start)
		} else if iface == "" {
			addRelayedNetwork4(&nets[i], r, start)
		}
		scope := &scopes[i]
		if kind.noPool {
			continue
		}

		rng := common.DHCPRange{From: start, To: end}
		switch {
		case v6 && scope.RangeV6 == nil:
			scope.RangeV6 = &rng
		case !v6 && scope.Range == (common.DHCPRange{}):
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
	c.attachDnsmasqReservations(doc, scopes, nets)

	return scopes
}

// dnsmasqServesOn returns a test for whether dnsmasq serves DHCP on an
// interface: it is not listed under <dhcp><no_interface>, and <interface>,
// when set, includes it. A range that names no interface passes.
func dnsmasqServesOn(dm schema.DNSMasq) func(string) bool {
	listen := csvSet(dm.Interface)
	var noDHCP map[string]struct{}
	if dm.DHCP != nil {
		noDHCP = csvSet(dm.DHCP.NoInterface)
	}

	return func(iface string) bool {
		if iface == "" {
			return true
		}
		if _, excluded := noDHCP[iface]; excluded {
			return false
		}
		if len(listen) == 0 {
			return true
		}
		_, ok := listen[iface]
		return ok
	}
}

// dnsmasqRangeKind says what dnsmasq does with a range.
type dnsmasqRangeKind struct {
	// v6 is set for an IPv6 range; the template tells the families apart by
	// a colon in start_addr.
	v6 bool
	// noPool is set when the range allocates no address.
	noPool bool
	// serves is set when dnsmasq serves DHCP from the range at all.
	serves bool
}

// classifyDnsmasqRange classifies a range by its addresses and modes.
func classifyDnsmasqRange(r schema.DNSMasqDHCPRange, start, end string) dnsmasqRangeKind {
	_, static := csvSet(r.Mode)["static"]
	_, stateless := csvSet(r.RAMode)["ra-stateless"]
	v6 := strings.Contains(start, ":")
	if v6 && end == "" && !static && !stateless {
		return dnsmasqRangeKind{v6: true}
	}

	return dnsmasqRangeKind{v6: v6, noPool: static || (v6 && stateless), serves: true}
}

// dnsmasqRangeInterface returns the interface a range serves: the one it
// names, else the one its constructor names, else the one whose network
// holds its start address, or "" when none does.
func dnsmasqRangeInterface(doc *schema.OpnSenseDocument, r schema.DNSMasqDHCPRange, start string) string {
	if iface := strings.TrimSpace(r.Interface); iface != "" {
		return iface
	}
	if constructor := strings.TrimSpace(r.Constructor); constructor != "" {
		return constructor
	}
	addr, err := netip.ParseAddr(start)
	if err != nil {
		return ""
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Interfaces.Items)) {
		if interfaceNetworkHolds(doc, name, addr) {
			return name
		}
	}

	return ""
}

// ipv4Classes lists the classful IPv4 address spaces, class A, B and C,
// each with the size of a network in it.
var ipv4Classes = []struct {
	space   netip.Prefix
	network netip.Prefix
}{
	{space: netip.MustParsePrefix("0.0.0.0/1"), network: netip.MustParsePrefix("0.0.0.0/8")},
	{space: netip.MustParsePrefix("128.0.0.0/2"), network: netip.MustParsePrefix("128.0.0.0/16")},
	{space: netip.MustParsePrefix("192.0.0.0/3"), network: netip.MustParsePrefix("192.0.0.0/24")},
}

// addRelayedNetwork4 records the IPv4 network a range that no interface's
// network holds serves through a relay agent. dnsmasq(8) takes the network
// from the range's netmask, and without one guesses it from the class of the
// start address: /8 for class A, /16 for class B and /24 for class C.
func addRelayedNetwork4(nets *dnsmasqScopeNets, r schema.DNSMasqDHCPRange, start string) {
	addr, err := netip.ParseAddr(start)
	if err != nil || !addr.Is4() {
		return
	}
	bits := -1
	if mask := strings.TrimSpace(r.SubnetMask); mask != "" {
		bits = maskBits(mask)
	} else {
		for _, class := range ipv4Classes {
			if class.space.Contains(addr) {
				bits = class.network.Bits()
				break
			}
		}
	}
	if bits < 0 {
		return
	}
	if p, err := addr.Prefix(bits); err == nil {
		nets.v4 = append(nets.v4, p)
	}
}

// maskBits returns the prefix length of a dotted IPv4 netmask such as
// 255.255.255.0, or -1 when the value is not a contiguous IPv4 mask.
func maskBits(mask string) int {
	addr, err := netip.ParseAddr(mask)
	if err != nil || !addr.Is4() {
		return -1
	}
	b := addr.As4()
	ones, size := net.IPv4Mask(b[0], b[1], b[2], b[3]).Size()
	if size == 0 {
		return -1
	}

	return ones
}

// addRangeNetworks6 records the IPv6 networks an IPv6 range serves: the
// prefix of its constructor interface, or the prefix_len network (64 when
// unset, as the template writes it) around a start given in full.
func addRangeNetworks6(doc *schema.OpnSenseDocument, nets *dnsmasqScopeNets, r schema.DNSMasqDHCPRange, start string) {
	if constructor := strings.TrimSpace(r.Constructor); constructor != "" {
		nets.constructed = true
		if p, ok := interfaceNetwork6(doc, constructor); ok {
			nets.v6 = append(nets.v6, p)
		}
		return
	}
	bits := strings.TrimSpace(r.PrefixLen)
	if bits == "" {
		bits = "64"
	}
	if strings.HasPrefix(start, "::") {
		// A host part with no constructor names no network.
		return
	}
	if p, err := netip.ParsePrefix(start + "/" + bits); err == nil && p.Addr().Is6() {
		nets.v6 = append(nets.v6, p.Masked())
	}
}

// mappableDnsmasqOptions returns the dhcp_options entries a DHCP scope can
// hold: DHCPv4 options sent to every client on an interface. Options that
// apply only to tagged clients, DHCPv6 options and match entries have no
// place in the scope and draw one warning each.
func (c *converter) mappableDnsmasqOptions(options []schema.DNSMasqDHCPOption) []schema.DNSMasqDHCPOption {
	var result []schema.DNSMasqDHCPOption
	for _, o := range options {
		if o.IsPlaceholder() {
			continue
		}
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
// subnet holds its address (dnsmasq(8), --dhcp-host). The lease goes to the
// first scope that holds one of the entry's addresses, see dnsmasqLeaseTargets.
// An entry with no address goes to the only scope with an IPv4 range. An
// entry with no home is reported rather than dropped silently.
func (c *converter) attachDnsmasqReservations(
	doc *schema.OpnSenseDocument,
	scopes []common.DHCPScope,
	nets []dnsmasqScopeNets,
) {
	fallback := -1
	for i := range scopes {
		if scopes[i].Range.From == "" {
			continue
		}
		if fallback >= 0 {
			fallback = -1
			break
		}
		fallback = i
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

		targets := dnsmasqLeaseTargets(doc, scopes, nets, h.IP, fallback)
		if len(targets) == 0 {
			c.addWarning("dnsmasq.hosts", label,
				"dnsmasq DHCP reservation matches no DHCP range's network; not attached to a scope",
				common.SeverityLow)
			continue
		}

		for _, target := range targets {
			scopes[target].StaticLeases = append(scopes[target].StaticLeases, common.DHCPStaticLease{
				MAC:         hwaddr,
				CID:         clientID,
				IPAddress:   strings.TrimSpace(h.IP),
				Hostname:    strings.TrimSpace(h.Host),
				Description: h.Descr,
			})
		}
	}
}

// dnsmasqLeaseTargets returns the indexes of the scopes a reservation with
// the comma-separated addresses ips belongs to. The template writes every
// address into one dhcp-host line, so each address places the lease, and a
// scope that several addresses reach takes it once. An IPv4 address goes to
// the scope whose interface network holds it, else to a relayed range whose
// network holds it; a full IPv6 address goes to the scope whose IPv6
// networks hold it. An address holding only a host part (::50) applies in
// every range built by a constructor (dnsmasq(8), --dhcp-host), so it goes
// to each such scope. Only an entry with no address at all takes the
// fallback.
func dnsmasqLeaseTargets(
	doc *schema.OpnSenseDocument,
	scopes []common.DHCPScope,
	nets []dnsmasqScopeNets,
	ips string,
	fallback int,
) []int {
	var targets []int
	add := func(i int) {
		if i >= 0 && !slices.Contains(targets, i) {
			targets = append(targets, i)
		}
	}

	addresses := false
	for entry := range strings.SplitSeq(ips, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		addresses = true
		addr, err := netip.ParseAddr(entry)
		switch {
		case err != nil:
			continue
		case addr.Is6() && strings.HasPrefix(entry, "::"):
			for i := range nets {
				if nets[i].constructed {
					add(i)
				}
			}
		default:
			add(dnsmasqScopeHolding(doc, scopes, nets, addr))
		}
	}

	if !addresses && fallback >= 0 {
		return []int{fallback}
	}

	return targets
}

// dnsmasqScopeHolding returns the index of the scope that serves addr, or -1:
// for IPv4 the scope whose interface network holds it, else the relayed range
// whose network does; for IPv6 the scope whose IPv6 networks hold it.
func dnsmasqScopeHolding(
	doc *schema.OpnSenseDocument,
	scopes []common.DHCPScope,
	nets []dnsmasqScopeNets,
	addr netip.Addr,
) int {
	contains := func(p netip.Prefix) bool { return p.Contains(addr) }
	if addr.Is6() {
		for i := range nets {
			if slices.ContainsFunc(nets[i].v6, contains) {
				return i
			}
		}
		return -1
	}
	for i := range scopes {
		if interfaceNetworkHolds(doc, scopes[i].Interface, addr) {
			return i
		}
	}
	for i := range nets {
		if slices.ContainsFunc(nets[i].v4, contains) {
			return i
		}
	}

	return -1
}

// interfaceNetworkHolds reports whether the network of the named interface
// in addr's family holds addr.
func interfaceNetworkHolds(doc *schema.OpnSenseDocument, name string, addr netip.Addr) bool {
	if addr.Is6() {
		prefix, ok := interfaceNetwork6(doc, name)
		return ok && prefix.Contains(addr)
	}
	iface, ok := doc.Interfaces.Items[name]
	if !ok {
		return false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(iface.IPAddr) + "/" + strings.TrimSpace(iface.Subnet))

	return err == nil && prefix.Contains(addr)
}

// interfaceNetwork6 returns the static IPv6 network of the named interface.
// An interface whose ipaddrv6 is a mode such as track6 or dhcp6 has none.
func interfaceNetwork6(doc *schema.OpnSenseDocument, name string) (netip.Prefix, bool) {
	iface, ok := doc.Interfaces.Items[name]
	if !ok {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(iface.IPAddrv6) + "/" + strings.TrimSpace(iface.Subnetv6))
	if err != nil || !prefix.Addr().Is6() {
		return netip.Prefix{}, false
	}

	return prefix.Masked(), true
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
