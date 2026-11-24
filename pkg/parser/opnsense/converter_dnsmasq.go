package opnsense

import (
	"encoding/binary"
	"fmt"
	"maps"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"strconv"
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

	if dm.Version == "" {
		if dm.Dnssec != nil {
			c.warnOnLegacyZeroFlag("DNS.DNSMasq.DNSSEC", *dm.Dnssec)
		}
		if dm.Enable != nil {
			c.warnOnLegacyZeroFlag("DNS.DNSMasq.Enabled", *dm.Enable)
		}
	}

	return common.DNSMasqConfig{
		Enabled:         dnsmasqEnabled(dm),
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

// dnsmasqEnabled reports whether the firewall runs dnsmasq. A legacy config,
// which has no model version, is enabled by the presence of <enable>:
// dnsmasq_enabled() tests it with isset() up to 25.1.1. From 25.1.2, the
// release the model arrived in, it tests !empty(), so a 0 or an empty element
// is off.
func dnsmasqEnabled(dm schema.DNSMasq) bool {
	if dm.Enable == nil {
		return false
	}

	return dm.Version == "" || modelFlagSet(*dm.Enable)
}

// dnsmasqScopeNets holds what a dnsmasq scope's ranges say about the
// addresses it serves, which the scope model has no field for.
type dnsmasqScopeNets struct {
	// v6 holds the IPv6 networks the scope's ranges are matched on, each
	// with the range's prefix_len: the constructor interface's address, or
	// the range's start given in full. dnsmasq matches a reservation on the
	// range's prefix only (is_config_in_context), not on the interface's
	// whole network.
	v6 []netip.Prefix
	// v4 holds the IPv4 networks the scope's ranges are matched on: see
	// dnsmasqRangeNetwork4.
	v4 []dnsmasqNet4
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
	enabled := dnsmasqEnabled(dm)
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
		if constructor := strings.TrimSpace(r.Constructor); v6 && constructedOnLongPrefix(doc, constructor) {
			c.addWarning("dnsmasq.dhcp_ranges.constructor", constructor,
				fmt.Sprintf("dnsmasq builds no DHCPv6 range on interface %q: its IPv6 prefix is longer than /64; "+
					"the range serves no address and is not exported", constructor),
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
				Enabled:     enabled && servesOn(iface),
				Description: r.Description,
			})
			nets = append(nets, dnsmasqScopeNets{})
		}
		if v6 {
			addRangeNetworks6(doc, &nets[i], r, start)
		} else if n4, ok := dnsmasqRangeNetwork4(doc, r, iface, start, end); ok {
			nets[i].v4 = append(nets[i].v4, n4)
		}
		scope := &scopes[i]
		if !ok && iface == "" {
			// A range no interface's network holds is named by the network
			// dnsmasq assumes for it.
			switch {
			case len(nets[i].v4) > 0:
				scope.Subnet = nets[i].v4[0].String()
			case len(nets[i].v6) > 0:
				scope.Subnet = nets[i].v6[0].String()
			}
		}
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
// each with the netmask of a network in it.
var ipv4Classes = []struct {
	space netip.Prefix
	mask  netip.Addr
}{
	{space: netip.MustParsePrefix("0.0.0.0/1"), mask: netip.MustParseAddr("255.0.0.0")},
	{space: netip.MustParsePrefix("128.0.0.0/2"), mask: netip.MustParseAddr("255.255.0.0")},
	{space: netip.MustParsePrefix("192.0.0.0/3"), mask: netip.MustParseAddr("255.255.255.0")},
}

// dnsmasqNet4 is an IPv4 network as dnsmasq matches a range on it: an address
// belongs to it when, under the mask, it equals both the range's start and
// its end (is_same_net in dhcp.c and rfc2131.c). The mask need not be
// contiguous; dnsmasq applies whatever the option holds.
type dnsmasqNet4 struct {
	start, end, mask uint32
	// local is set when dnsmasq serves the range to clients on its
	// interface directly rather than through a relay: the interface's
	// network holds its start and end, or the interface has no static IPv4
	// network the config shows and so may hold them at runtime.
	local bool
	// dynamic is set for a local range on an interface with no static IPv4
	// network the config shows, whose network is therefore an estimate.
	dynamic bool
}

// contains reports whether addr belongs to the network.
func (n dnsmasqNet4) contains(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	masked := ipv4Uint(addr) & n.mask
	startNet, endNet := n.start&n.mask, n.end&n.mask

	// Equal to both: equal to the start, and the start equal to the end.
	return masked == startNet && startNet == endNet
}

// String writes the network as a CIDR, or as address/mask when the mask is
// not contiguous.
func (n dnsmasqNet4) String() string {
	base := uintIPv4(n.start & n.mask).String()
	mask := uintIPv4(n.mask)
	m4 := mask.As4()
	if ones, size := net.IPv4Mask(m4[0], m4[1], m4[2], m4[3]).Size(); size != 0 {
		return base + "/" + strconv.Itoa(ones)
	}

	return base + "/" + mask.String()
}

// ipv4Uint returns an IPv4 address as a number.
func ipv4Uint(addr netip.Addr) uint32 {
	return binary.BigEndian.Uint32(addr.AsSlice())
}

// uintIPv4 returns the IPv4 address a number stands for.
func uintIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)

	return netip.AddrFrom4(b)
}

// dnsmasqRangeNetwork4 returns the IPv4 network dnsmasq matches an IPv4 range
// and its reservations on. A range is local when the network of the
// interface it serves holds its start and its end, or when that interface
// has no static IPv4 network the config shows (dhcp, pppoe, or an address
// only a virtual IP carries), since dnsmasq serves it there directly once
// the interface's address is in its network; it is relayed otherwise.
//
// With a subnet mask, dnsmasq keeps that mask whether the range is local or
// relayed (CONTEXT_NETMASK, dhcp.c), and offers a reservation only inside it
// (is_config_in_context, dhcp-common.c), so a mask narrower than the
// interface's network narrows what the range serves. Without one, a local
// range takes the interface's network, and a relayed range a mask guessed
// from the address class, but only when the start and the end are in the same
// class: /8 for class A, /16 for class B and /24 for class C (rfc2131.c). A
// static range has no end and is matched on its start alone.
func dnsmasqRangeNetwork4(
	doc *schema.OpnSenseDocument,
	r schema.DNSMasqDHCPRange,
	iface, start, end string,
) (dnsmasqNet4, bool) {
	first, err := netip.ParseAddr(start)
	if err != nil || !first.Is4() {
		return dnsmasqNet4{}, false
	}
	last := first
	if end != "" {
		if last, err = netip.ParseAddr(end); err != nil || !last.Is4() {
			return dnsmasqNet4{}, false
		}
	}
	ifNet, hasIfNet := interfaceNetwork4(doc, iface)
	_, named := doc.Interfaces.Items[iface]
	dynamic := named && !hasIfNet
	n := dnsmasqNet4{
		start:   ipv4Uint(first),
		end:     ipv4Uint(last),
		local:   dynamic || (hasIfNet && ifNet.Contains(first) && ifNet.Contains(last)),
		dynamic: dynamic,
	}

	if mask := strings.TrimSpace(r.SubnetMask); mask != "" {
		m, err := netip.ParseAddr(mask)
		if err != nil || !m.Is4() {
			return dnsmasqNet4{}, false
		}
		n.mask = ipv4Uint(m)
		return n, true
	}
	if n.local && !dynamic {
		n.mask = prefixMask4(ifNet.Bits())
		return n, true
	}
	if dynamic {
		// The interface has no static IPv4 network the config shows: its
		// address comes at runtime (dhcp, pppoe), or only a virtual IP
		// carries one. dnsmasq takes a range's mask from any local address
		// whose network holds its start or end (guess_range_netmask in
		// dhcp.c), and whatever that mask is, it keeps the start and the end
		// in one network (complete_context). The smallest prefix holding both
		// is the narrowest such network, so it holds every reservation inside
		// the pool.
		n.mask = prefixMask4(bits.LeadingZeros32(n.start ^ n.end))
		return n, true
	}
	for _, class := range ipv4Classes {
		if class.space.Contains(first) && class.space.Contains(last) {
			n.mask = ipv4Uint(class.mask)
			return n, true
		}
	}

	return dnsmasqNet4{}, false
}

// ipv4AllOnes is the IPv4 address with every bit set.
var ipv4AllOnes = netip.MustParseAddr("255.255.255.255")

// prefixMask4 returns the IPv4 netmask of a prefix length.
func prefixMask4(length int) uint32 {
	return ipv4Uint(netip.PrefixFrom(ipv4AllOnes, length).Masked().Addr())
}

// addRangeNetworks6 records the IPv6 network an IPv6 range serves: the
// prefix_len network (64 when unset, as the template writes it) around a
// start given in full, or around the start dnsmasq constructs.
//
// dnsmasq accepts only 64 for a constructor and nothing below 64 (option.c),
// so a range with any other prefix_len is refused and matches nothing. For a
// constructed range it builds a context only when the constructor
// interface's prefix is at most 64, and takes as its start the interface's
// address with the low 64 bits replaced by the range's host part
// (construct_worker and setaddr6part in dhcp6.c), so the range's network is
// the /64 around the interface's address. An interface with no static IPv6
// address gets one at runtime, so its range is constructed but has no
// network the config shows.
func addRangeNetworks6(doc *schema.OpnSenseDocument, nets *dnsmasqScopeNets, r schema.DNSMasqDHCPRange, start string) {
	length := dnsmasqIPv6Prefix
	if prefixLen := strings.TrimSpace(r.PrefixLen); prefixLen != "" {
		var err error
		if length, err = strconv.Atoi(prefixLen); err != nil || length < dnsmasqIPv6Prefix {
			return
		}
	}
	if constructor := strings.TrimSpace(r.Constructor); constructor != "" {
		if length == dnsmasqIPv6Prefix {
			addConstructedNetwork6(doc, nets, constructor)
		}
		return
	}
	addr, err := netip.ParseAddr(start)
	if err != nil || !addr.Is6() || isIPv6HostPart(addr) {
		// A host part with no constructor names no network.
		return
	}
	if p, err := addr.Prefix(length); err == nil {
		nets.v6 = append(nets.v6, p)
	}
}

// isIPv6HostPart reports whether addr is an IPv6 address whose network half is
// zero. dnsmasq reads such an address as a host part to combine with a range's
// prefix, whatever its spelling: it tests the first eight bytes of the parsed
// address (option.c, "set WILDCARD if network part all zeros"), so
// 0:0:0:0:0:0:0:50 is read as ::50 is.
func isIPv6HostPart(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	b := addr.As16()

	return binary.BigEndian.Uint64(b[:8]) == 0
}

// addConstructedNetwork6 records the network of a range dnsmasq constructs
// from the constructor interface's address; see addRangeNetworks6.
func addConstructedNetwork6(doc *schema.OpnSenseDocument, nets *dnsmasqScopeNets, constructor string) {
	iface, ok := doc.Interfaces.Items[constructor]
	if !ok {
		return
	}
	ifPrefix, ok := interfacePrefix6(iface)
	if !ok {
		nets.constructed = true
		return
	}
	// A range kept on a longer prefix is built from another address of the
	// interface, such as a virtual IP, so it is constructed, on a network
	// the config does not show.
	nets.constructed = true
	if ifPrefix.Bits() > dnsmasqIPv6Prefix {
		return
	}
	if p, err := ifPrefix.Addr().Prefix(dnsmasqIPv6Prefix); err == nil {
		nets.v6 = append(nets.v6, p)
	}
}

// interfacePrefix6 returns the static IPv6 prefix of an interface. ok is
// false when the config shows none, as for an interface that gets its
// address at runtime.
func interfacePrefix6(iface schema.Interface) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(iface.IPAddrv6) + "/" + strings.TrimSpace(iface.Subnetv6))
	if err != nil || !prefix.Addr().Is6() {
		return netip.Prefix{}, false
	}

	return prefix, true
}

// constructedOnLongPrefix reports whether a range's constructor names an
// interface whose static IPv6 prefix is longer than 64. dnsmasq builds a
// context for a constructed range only when the interface's prefix is at
// most the range's (construct_worker in dhcp6.c), so such a range serves no
// address. A prefix the config does not show is assigned at runtime and may
// be short enough, so it does not count. Neither does an interface that
// carries an IPv6 virtual IP: dnsmasq tries every address of the interface,
// and the schema does not read a virtual IP's prefix length, so the range may
// be built from that address.
func constructedOnLongPrefix(doc *schema.OpnSenseDocument, constructor string) bool {
	prefix, ok := interfaceNetwork6(doc, constructor)
	if !ok || prefix.Bits() <= dnsmasqIPv6Prefix {
		return false
	}

	return !slices.ContainsFunc(doc.VirtualIP.Vip, func(vip schema.VIP) bool {
		return strings.TrimSpace(vip.Interface) == constructor && strings.Contains(vip.Subnet, ":")
	})
}

// dnsmasqIPv6Prefix is the prefix_len the template writes when it is empty,
// the shortest dnsmasq accepts on any IPv6 range, and the only one it accepts
// with a constructor (option.c).
const dnsmasqIPv6Prefix = 64

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
// subnet holds its address (dnsmasq(8), --dhcp-host). Each address places
// the lease on one scope, see dnsmasqLeaseTargets, and the lease is attached
// once to each scope its addresses reach. An entry with no address goes to
// the only scope with an IPv4 range. An entry with no home is reported rather
// than dropped silently.
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

		targets := dnsmasqLeaseTargets(nets, h.IP, fallback)
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
// scope that several addresses reach takes it once. A full address goes to
// one scope, chosen by dnsmasqScopeHolding. An address holding only a host part (::50) applies in
// every range built by a constructor (dnsmasq(8), --dhcp-host), so it goes
// to each such scope. Only an entry with no address at all takes the
// fallback.
func dnsmasqLeaseTargets(nets []dnsmasqScopeNets, ips string, fallback int) []int {
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
		case isIPv6HostPart(addr):
			for i := range nets {
				if nets[i].constructed {
					add(i)
				}
			}
		default:
			add(dnsmasqScopeHolding(nets, addr))
		}
	}

	if !addresses && fallback >= 0 {
		return []int{fallback}
	}

	return targets
}

// dnsmasqScopeHolding returns the index of the one scope that serves addr, or
// -1. For IPv4 the ranges are tried in three tiers (dnsmasqRangeNetwork4):
// local ranges whose interface network the config shows, then ranges on an
// interface with no static IPv4 network, whose network is an estimate, then
// relayed ranges. The first scope with a range whose network holds addr, in
// the earliest tier that has one, serves it, so an address a range on a known
// network holds never goes to an estimated or relayed one. For IPv6 it is the
// first scope whose ranges' prefixes hold it.
func dnsmasqScopeHolding(nets []dnsmasqScopeNets, addr netip.Addr) int {
	contains := func(p netip.Prefix) bool { return p.Contains(addr) }
	if addr.Is6() {
		for i := range nets {
			if slices.ContainsFunc(nets[i].v6, contains) {
				return i
			}
		}
		return -1
	}
	tiers := []func(dnsmasqNet4) bool{
		func(n dnsmasqNet4) bool { return n.local && !n.dynamic },
		func(n dnsmasqNet4) bool { return n.dynamic },
		func(n dnsmasqNet4) bool { return !n.local },
	}
	for _, tier := range tiers {
		for i := range nets {
			if slices.ContainsFunc(nets[i].v4, func(n dnsmasqNet4) bool {
				return tier(n) && n.contains(addr)
			}) {
				return i
			}
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
	prefix, ok := interfaceNetwork4(doc, name)

	return ok && prefix.Contains(addr)
}

// interfaceNetwork4 returns the static IPv4 network of the named interface.
// An interface whose ipaddr is a mode such as dhcp has none.
func interfaceNetwork4(doc *schema.OpnSenseDocument, name string) (netip.Prefix, bool) {
	iface, ok := doc.Interfaces.Items[name]
	if !ok {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(iface.IPAddr) + "/" + strings.TrimSpace(iface.Subnet))
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}

	return prefix, true
}

// interfaceNetwork6 returns the static IPv6 network of the named interface.
// An interface whose ipaddrv6 is a mode such as track6 or dhcp6 has none.
func interfaceNetwork6(doc *schema.OpnSenseDocument, name string) (netip.Prefix, bool) {
	iface, ok := doc.Interfaces.Items[name]
	if !ok {
		return netip.Prefix{}, false
	}
	prefix, ok := interfacePrefix6(iface)
	if !ok {
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
