package opnsense

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

const (
	// defaultRuleSequence is the sequence the filter model gives a rule that
	// stores none.
	defaultRuleSequence = "1"
	// listSeparator separates the entries of an interface or address list.
	listSeparator = ","
	// stateSuffix is what the legacy store appends to a state type.
	stateSuffix = " state"
	// stateTypeKeep is the state type of a rule that names none.
	stateTypeKeep = "keep"
	// wildcardIPv4 and wildcardIPv6 are the networks that hold every address.
	wildcardIPv4 = "0.0.0.0/0"
	wildcardIPv6 = "::/0"
	// filterModelRulesPath addresses a warning about a rule of the filter
	// model that is not in the rule list.
	filterModelRulesPath = "OPNsense.Firewall.Filter.Rules"
	// filterModelVersionPath addresses a warning about the filter model's
	// version.
	filterModelVersionPath = "OPNsense.Firewall.Filter.Version"
	// phpWhitespace is the whitespace PHP allows around a numeric string.
	phpWhitespace = " \t\n\r\v\f"
)

// The priorities OPNsense ranks a filter rule by. Lower ones are evaluated
// first. Rules of equal priority keep the order they were registered in: the
// filter model's in sequence, then the legacy ones in document order.
const (
	priorityFloating  = 200000
	priorityGroup     = 300000
	priorityInterface = 400000
	priorityUnloaded  = 600000
)

// The priorities the os-firewall plugin gave a rule of the filter model, below
// every legacy rule's.
const (
	pluginPriorityList      = 1000
	pluginPriorityGroup     = 2000
	pluginPriorityInterface = 3000
)

// The filter model versions only the os-firewall plugin wrote, up to 23.7,
// before the model moved into the core in 24.1.
const (
	pluginFilterModelVersion0 = "1.0.0"
	pluginFilterModelVersion1 = "1.0.1"
	pluginFilterModelVersion2 = "1.0.2"
)

// knownFilterModelVersions lists the <OPNsense><Firewall><Filter version="...">
// values this converter has been checked against. They name the rule elements
// alike; each later one only adds some.
var knownFilterModelVersions = map[string]struct{}{
	"":                        {},
	pluginFilterModelVersion0: {},
	pluginFilterModelVersion1: {},
	pluginFilterModelVersion2: {},
	"1.0.3":                   {},
	"1.0.4":                   {},
	"1.0.5":                   {},
	"1.0.6":                   {},
}

// pluginFilterModelVersions are the versions only the os-firewall plugin wrote.
// A migration raises the version on upgrade, so a config that holds one of them
// was saved by the plugin, which ranked the model's rules its own way
// (pluginRulePriority).
var pluginFilterModelVersions = map[string]struct{}{
	pluginFilterModelVersion0: {},
	pluginFilterModelVersion1: {},
	pluginFilterModelVersion2: {},
}

// unrepresentedRuleElements are elements of a filter model rule that narrow what
// it matches, limit when it applies or change where the traffic goes, and that
// the common rule has no field for. The rule is reported without them, so each
// one set gets a warning. received-on is one too (checkReceivedOn).
var unrepresentedRuleElements = []struct {
	field   string
	value   func(schema.FirewallFilterRule) string
	message string
}{
	{
		"TOS", func(r schema.FirewallFilterRule) string { return r.TOS },
		"the rule only matches packets with this type of service, which is not reported",
	},
	{
		"Prio", func(r schema.FirewallFilterRule) string { return r.Prio },
		"the rule only matches packets with this priority, which is not reported",
	},
	{
		"MaxPktRateNumber", maxPacketRate,
		"the rule stops matching above this packet rate, which is not reported",
	},
	{
		"Sched", func(r schema.FirewallFilterRule) string { return r.Sched },
		"the rule only applies during this schedule, which is not reported",
	},
	{
		"DivertTo", func(r schema.FirewallFilterRule) string { return r.DivertTo },
		"the rule diverts the traffic it matches, which is not reported",
	},
	{
		"ReplyTo", func(r schema.FirewallFilterRule) string { return r.ReplyTo },
		"the rule routes replies through this gateway, which is not reported",
	},
}

// wellKnownPorts maps the service names the filter model accepts as a port to
// their numbers, as OPNsense does when it builds the ruleset.
var wellKnownPorts = map[string]string{
	"afs3-fileserver": "7000", "aol": "5190", "auth": "113", "avt-profile-1": "5004", "cvsup": "5999",
	"domain": "53", "domain-s": "853", "ftp": "21", "hbci": "3000", "http": "80", "https": "443",
	"igmpv3lite": "465", "imap": "143", "imaps": "993", "ipsec-msft": "10000", "ipsec-nat-t": "4500",
	"isakmp": "500", "l2f": "1701", "ldap": "389", "ldaps": "636", "microsoft-ds": "445",
	"ms-streaming": "1755", "ms-wbt-server": "3389", "msnp": "1863", "nat-stun-port": "3478",
	"netbios-dgm": "138", "netbios-ns": "137", "netbios-ssn": "139", "nntp": "119", "ntp": "123",
	"openvpn": "1194", "pop3": "110", "pop3s": "995", "pptp": "1723", "radius": "1812",
	"radius-acct": "1813", "rfb": "5900", "sip": "5060", "sip-tls": "5061", "smtp": "25", "snmp": "161",
	"snmptrap": "162", "ssh": "22", "submission": "587", "submissions": "465", "telnet": "23",
	"teredo": "3544", "tftp": "69", "urd": "465", "wins": "1512",
}

// icmp6TypeNames maps the ICMPv6 type numbers the filter model stores to the
// names the legacy store uses for them.
var icmp6TypeNames = map[string]string{
	"1": "unreach", "2": "toobig", "3": "timex", "4": "paramprob", "128": "echoreq", "129": "echorep",
	"130": "listqry", "131": "listenrep", "132": "listendone", "133": "routersol", "134": "routeradv",
	"135": "neighbrsol", "136": "neighbradv", "137": "redir", "138": "routrrenum", "139": "niqry",
	"140": "nirep", "200": "mtraceresp", "201": "mtrace",
}

// filterRuleSource is one stored rule on its way into the rule list. Exactly
// one of model and legacy is set.
type filterRuleSource struct {
	model    *schema.FirewallFilterRule
	legacy   *schema.Rule
	priority int
}

// filterRulesInOrder returns the rules of both stores in the order the firewall
// evaluates them. OPNsense gives each rule a priority (see modelRulePriority and
// legacyRulePriority) and evaluates the priorities in turn; within one, the
// filter model's rules come first, in sequence, then the legacy ones in
// document order.
//
// This is the order of 26.7.2 and later, and of the os-firewall plugin when
// the model's version says the plugin saved it. The core releases before 26.7.2
// rank some rules of the filter model differently (GOTCHAS 3.8), and their
// versions do not say which of them wrote a config.
func (c *converter) filterRulesInOrder(doc *schema.OpnSenseDocument) []filterRuleSource {
	var rules []filterRuleSource

	groups := groupSequences(doc)

	if doc.OPNsense.Firewall != nil {
		filter := &doc.OPNsense.Firewall.Filter
		c.checkFilterModelVersion(filter.Version, len(filter.Rules))

		_, plugin := pluginFilterModelVersions[filter.Version]

		for _, rule := range c.modelRulesInSequence(filter.Rules) {
			priority := modelRulePriority(rule, doc, groups)
			if plugin {
				priority = pluginRulePriority(rule, doc)
			}

			rules = append(rules, filterRuleSource{model: &rule, priority: priority})
		}
	}

	for i := range doc.Filter.Rule {
		rule := &doc.Filter.Rule[i]
		if rule.IsPlaceholder() {
			continue
		}

		rules = append(rules, filterRuleSource{legacy: rule, priority: legacyRulePriority(rule, groups)})
	}

	slices.SortStableFunc(rules, func(a, b filterRuleSource) int {
		return cmp.Compare(a.priority, b.priority)
	})

	return rules
}

// checkFilterModelVersion warns when the filter model carries a version this
// converter has not been checked against. With rules decoded the mapping may be
// stale. With none it may be worse: a version that renames <rules> or <rule>
// decodes to no rules at all (§18.1), which the rules cannot show, so that case
// warns too, at Low, since a model with no rules is also the common one.
func (c *converter) checkFilterModelVersion(version string, rules int) {
	if _, known := knownFilterModelVersions[version]; known {
		return
	}

	if rules == 0 {
		c.addWarning(
			filterModelVersionPath,
			version,
			"unrecognized OPNsense firewall filter model version and no rules decoded; the rule element may have been renamed",
			common.SeverityLow,
		)

		return
	}

	c.addWarning(filterModelVersionPath, version,
		"unrecognized OPNsense firewall filter model version; element mapping may be stale",
		common.SeverityMedium)
}

// modelRulePriority returns the priority OPNsense gives a rule of the filter
// model. A rule whose interfaces, or whose received-on interfaces, are none the
// config defines is not loaded and goes last. One that names other than a
// single interface, or excludes one, is floating. One on an interface group
// goes by the group's sequence.
func modelRulePriority(rule schema.FirewallFilterRule, doc *schema.OpnSenseDocument, groups map[string]int) int {
	interfaces := listValues(rule.Interface)

	for _, set := range [][]string{interfaces, listValues(rule.ReceivedOn)} {
		if len(set) > 0 && !definesAny(doc, set) {
			return priorityUnloaded
		}
	}

	switch {
	case len(interfaces) != 1 || modelFlagSet(rule.InterfaceNot):
		return priorityFloating
	case doc.Interfaces.Items[interfaces[0]].Type == interfaceTypeGroup:
		return priorityGroup + groups[interfaces[0]]
	default:
		return priorityInterface
	}
}

// pluginRulePriority returns the priority the os-firewall plugin gave a rule of
// the filter model: a list of interfaces first, then a group, then the rest,
// which includes a rule on no interface. The rule list follows it, but the
// shadow analysis still takes a floating rule with no interface, of either
// store, ahead of every other rule (GOTCHAS 3.8).
func pluginRulePriority(rule schema.FirewallFilterRule, doc *schema.OpnSenseDocument) int {
	switch {
	case strings.Contains(rule.Interface, listSeparator):
		return pluginPriorityList
	case doc.Interfaces.Items[rule.Interface].Type == interfaceTypeGroup:
		return pluginPriorityGroup
	default:
		return pluginPriorityInterface
	}
}

// legacyRulePriority returns the priority OPNsense gives a legacy rule: floating
// first, then rules on a group <ifgroups> defines, by the group's sequence.
func legacyRulePriority(rule *schema.Rule, groups map[string]int) int {
	// The firewall tests for the element, which holds yes or 1. An empty one
	// cannot be told from an absent one here.
	if rule.Floating != "" {
		return priorityFloating
	}

	if sequence, ok := groups[rule.Interface.String()]; ok {
		return priorityGroup + sequence
	}

	return priorityInterface
}

// groupSequences returns the sequence <ifgroups> gives each interface group. A
// group that stores none, or one that is not a number, has 0.
func groupSequences(doc *schema.OpnSenseDocument) map[string]int {
	groups := make(map[string]int, len(doc.InterfaceGroups.IfGroupEntry))

	for _, entry := range doc.InterfaceGroups.IfGroupEntry {
		sequence, err := strconv.Atoi(strings.TrimSpace(entry.Sequence))
		if err != nil {
			sequence = 0
		}

		groups[entry.IfName] = sequence
	}

	return groups
}

// modelRulesInSequence returns the rules OPNsense loads from the filter model,
// in the order it loads them: by sequence, and by uuid where sequences are
// equal.
//
// A rule without a uuid is given a fresh random one each time OPNsense loads the
// model, so its place among rules of the same sequence is not fixed. Here such
// rules come ahead of their peers, in document order, as a stand-in. Only a
// hand-edited or generated config has them: OPNsense writes a uuid for every
// rule it saves.
//
// An empty <rule/> is not loaded. Nor is a rule whose uuid a later rule
// repeats: OPNsense keeps its rules by uuid, so the later one replaces it.
func (c *converter) modelRulesInSequence(rules []schema.FirewallFilterRule) []schema.FirewallFilterRule {
	lastWithUUID := make(map[string]int, len(rules))

	for i, rule := range rules {
		if !rule.IsPlaceholder() {
			lastWithUUID[rule.UUID] = i
		}
	}

	var kept []schema.FirewallFilterRule

	for i, rule := range rules {
		switch {
		case rule.IsPlaceholder():
		case rule.UUID != "" && lastWithUUID[rule.UUID] != i:
			c.addWarning(
				filterModelRulesPath,
				rule.UUID,
				fmt.Sprintf(
					"a later rule has the same uuid and replaces this one on the firewall, so it is left out (sequence %q, description %q)",
					rule.Sequence,
					rule.Description,
				),
				common.SeverityMedium,
			)
		default:
			kept = append(kept, rule)
		}
	}

	slices.SortStableFunc(kept, func(a, b schema.FirewallFilterRule) int {
		return naturalCompareFold(modelRuleSortKey(a), modelRuleSortKey(b))
	})

	return kept
}

// modelRuleSortKey builds the key OPNsense sorts a rule by: the sequence as
// stored, padded to a fixed width on the left when PHP reads it as a number and
// on the right otherwise, then the uuid.
func modelRuleSortKey(rule schema.FirewallFilterRule) string {
	sequence := cmp.Or(rule.Sequence, defaultRuleSequence)
	if isNumericString(sequence) {
		return sequenceSortKey(sequence, rule.UUID)
	}

	return fmt.Sprintf("%-*s,%s", sortKeyWidth, sequence, rule.UUID)
}

// modelRuleIsFloating reports whether a rule of the filter model is reported as
// floating: one that names other than a single interface, or excludes one. The
// model has no element for it. A list with an empty entry counts as several,
// since the firewall then also applies the rule on every interface, though it
// ranks the rule by its other entries (modelRulePriority).
func modelRuleIsFloating(rule schema.FirewallFilterRule) bool {
	return len(splitList(rule.Interface)) != 1 || modelFlagSet(rule.InterfaceNot)
}

// convertFilterModelRule maps a rule of the filter model to the common rule,
// in the vocabulary the legacy store uses, so both stores read alike. i is the
// rule's index in the rule list and addresses its warnings.
func (c *converter) convertFilterModelRule(
	i int,
	rule schema.FirewallFilterRule,
	doc *schema.OpnSenseDocument,
) common.FirewallRule {
	path := fmt.Sprintf("FirewallRules[%d]", i)

	family := common.IPProtocolInet
	if rule.IPProtocol != nil {
		family = c.ruleFamily(i, *rule.IPProtocol)
	}

	interfaces, applies := c.modelRuleInterfaces(path, rule, doc)
	if applies {
		applies = c.checkUnrepresentedElements(path, rule, doc)
	}

	return common.FirewallRule{
		UUID:        rule.UUID,
		Type:        c.ruleType(i, cmp.Or(rule.Action, string(common.RuleTypePass))),
		Description: rule.Description,
		Interfaces:  interfaces,
		IPProtocol:  family,
		StateType:   legacyStateType(rule.StateType),
		Direction:   c.ruleDirection(i, cmp.Or(rule.Direction, string(common.DirectionIn))),
		Floating:    modelRuleIsFloating(rule),
		Quick:       modelFlag(rule.Quick),
		Protocol:    legacyProtocol(rule.Protocol),
		Source:      c.modelRuleEndpoint(path+".Source", rule.SourceNet, rule.SourcePort, rule.SourceNot),
		Destination: c.modelRuleEndpoint(
			path+".Destination",
			rule.DestinationNet,
			rule.DestinationPort,
			rule.DestinationNot,
		),
		Gateway:         rule.Gateway,
		Log:             modelFlagSet(rule.Log),
		Disabled:        !modelFlag(rule.Enabled) || !applies,
		MaxSrcNodes:     rule.MaxSrcNodes,
		MaxSrcConn:      rule.MaxSrcConn,
		MaxSrcConnRate:  rule.MaxSrcConnRate,
		MaxSrcConnRates: rule.MaxSrcConnRates,
		TCPFlags1:       rule.TCPFlags1,
		TCPFlags2:       rule.TCPFlags2,
		TCPFlagsAny:     modelFlagSet(rule.TCPFlagsAny),
		ICMPType:        rule.ICMPType,
		ICMP6Type:       legacyICMP6Types(rule.ICMP6Type),
		StateTimeout:    rule.StateTimeout,
		AllowOpts:       modelFlagSet(rule.AllowOpts),
		DisableReplyTo:  modelFlagSet(rule.DisableReplyTo),
		NoPfSync:        modelFlagSet(rule.NoPfSync),
		NoSync:          modelFlagSet(rule.NoSync),
		Tag:             rule.Tag,
		Tagged:          rule.Tagged,
	}
}

// checkUnrepresentedElements warns about each element a rule of the filter model
// sets that the common rule cannot hold, and reports whether the firewall loads
// the rule as far as those elements go (checkReceivedOn).
func (c *converter) checkUnrepresentedElements(
	path string,
	rule schema.FirewallFilterRule,
	doc *schema.OpnSenseDocument,
) bool {
	if !c.checkReceivedOn(path, rule, doc) {
		return false
	}

	for _, element := range unrepresentedRuleElements {
		if value := element.value(rule); value != "" {
			c.addWarning(path+"."+element.field, value, element.message, common.SeverityMedium)
		}
	}

	return true
}

// checkReceivedOn warns about a received-on list, which limits a rule to traffic
// that arrived on the interfaces it names, or with received-on-not to traffic
// that did not, and reports whether the firewall loads the rule. As for
// <interface>, the firewall writes one rule for each entry and drops those on an
// interface the config does not define. So an empty entry, or a negated list
// naming several defined interfaces, matches traffic from any interface, and a
// rule whose entries are all undefined interfaces is not loaded.
func (c *converter) checkReceivedOn(path string, rule schema.FirewallFilterRule, doc *schema.OpnSenseDocument) bool {
	field := path + ".ReceivedOn"
	entries := splitList(rule.ReceivedOn)
	negated := modelFlagSet(rule.ReceivedOnNot)

	var defined []string

	for _, value := range listValues(rule.ReceivedOn) {
		if definesAny(doc, []string{value}) && !slices.Contains(defined, value) {
			defined = append(defined, value)
		}
	}

	switch {
	case len(entries) == 0:
	case slices.Contains(entries, ""):
		c.addWarning(field, rule.ReceivedOn,
			"received-on list has an empty entry, which the firewall matches on traffic from any interface",
			common.SeverityMedium)
	case len(defined) == 0:
		c.addWarning(field, rule.ReceivedOn,
			"no interface the rule's received-on names is defined, so the firewall does not load it; "+
				"it is reported as disabled",
			common.SeverityMedium)

		return false
	case negated && len(defined) > 1:
		c.addWarning(field, rule.ReceivedOn,
			"received-on-not is applied to each interface on its own, so the rule matches traffic from any interface",
			common.SeverityMedium)
	case negated:
		c.addWarning(field, rule.ReceivedOn,
			"the rule only matches traffic that did not arrive on this interface, which is not reported",
			common.SeverityMedium)
	default:
		c.addWarning(field, rule.ReceivedOn,
			"the rule only matches traffic that arrived on these interfaces, which is not reported",
			common.SeverityMedium)
	}

	return true
}

// modelRuleInterfaces returns the interfaces a rule of the filter model applies
// on, and whether the firewall loads it on any. No interface means every
// interface.
func (c *converter) modelRuleInterfaces(
	path string,
	rule schema.FirewallFilterRule,
	doc *schema.OpnSenseDocument,
) ([]string, bool) {
	keys := splitList(rule.Interface)
	negated := modelFlagSet(rule.InterfaceNot)

	switch {
	case len(keys) == 0:
		return nil, true
	case slices.Contains(keys, ""):
		c.addWarning(path+".Interface", rule.Interface,
			"interface list has an empty entry, which the firewall applies on every interface",
			common.SeverityMedium)

		return nil, true
	case !definesAny(doc, listValues(rule.Interface)):
		c.addWarning(path+".Interface", rule.Interface,
			"no interface the rule names is defined, so the firewall does not load it; it is reported as disabled",
			common.SeverityMedium)

		return keys, false
	case !negated:
		return keys, true
	case len(keys) > 1:
		c.addWarning(path+".Interface", rule.Interface,
			"several interfaces are excluded, which the firewall applies on every interface",
			common.SeverityMedium)

		return nil, true
	}

	return c.interfacesExcept(path, keys[0], doc), true
}

// interfacesExcept returns every interface of the document other than excluded.
// The common rule has no way to say "all but one", so the rule is given the
// interfaces it does apply on; the list changes when an interface is added.
//
// Excluding a group excludes its members. A group <ifgroups> lists with an
// excluded member is left out too, since the rule does not apply on all of it;
// its other members are listed on their own. The members of the built-in groups
// are not in the config, so those groups stay in the list. A rule that excludes
// every interface the config defines is left with none, which reads as every
// interface: the firewall applies the rule on each interface it does not name,
// lo0 and the tunnels among them, so that is the nearer reading.
func (c *converter) interfacesExcept(path, excluded string, doc *schema.OpnSenseDocument) []string {
	members, listed := groupMembers(doc, excluded)
	skip := append([]string{excluded}, members...)
	skipped := func(key string) bool { return slices.Contains(skip, key) }

	var rest []string

	for key := range doc.Interfaces.Items {
		if skipped(key) {
			continue
		}

		if inGroup, ok := groupMembers(doc, key); ok && slices.ContainsFunc(inGroup, skipped) {
			continue
		}

		rest = append(rest, key)
	}

	slices.Sort(rest)

	switch {
	case len(rest) == 0:
		c.addWarning(path+".Interface", excluded,
			"the rule excludes every interface the config defines, so it is reported on every interface",
			common.SeverityMedium)
	case doc.Interfaces.Items[excluded].Type == interfaceTypeGroup && !listed:
		c.addWarning(path+".Interface", excluded,
			"the rule applies on every interface outside this group, whose members are not in the config",
			common.SeverityMedium)
	default:
		c.addWarning(path+".Interface", excluded,
			"the rule applies on every interface but this one; it is listed with the others",
			common.SeverityLow)
	}

	return rest
}

// groupMembers returns the members <ifgroups> lists for an interface group, and
// false when it does not list the group.
func groupMembers(doc *schema.OpnSenseDocument, group string) ([]string, bool) {
	for _, entry := range doc.InterfaceGroups.IfGroupEntry {
		if entry.IfName == group {
			return strings.FieldsFunc(entry.Members, func(r rune) bool { return r == ' ' || r == ',' }), true
		}
	}

	return nil, false
}

// definesAny reports whether the document defines an interface named by any of
// keys.
func definesAny(doc *schema.OpnSenseDocument, keys []string) bool {
	return slices.ContainsFunc(keys, func(key string) bool {
		_, ok := doc.Interfaces.Items[key]

		return ok
	})
}

// modelRuleEndpoint builds one side of a rule of the filter model. field
// addresses its warnings.
//
// The model keeps aliases, interface names and addresses in one element, and a
// list of them when the rule names several. A side without the element matches
// any address. An empty element does too, and the firewall then ignores that
// side's port.
func (c *converter) modelRuleEndpoint(field string, network *string, port, not string) common.RuleEndpoint {
	if network != nil && *network == "" {
		return common.RuleEndpoint{Address: schema.NetworkAny}
	}

	stored := schema.NetworkAny
	if network != nil {
		stored = *network
	}

	endpoint := c.listEndpoint(field, stored, modelFlagSet(not))
	endpoint.Port, endpoint.PortRef = c.modelRulePort(port)

	return endpoint
}

// listEndpoint returns the address part of an endpoint that may name several
// addresses. OPNsense writes one rule for each, so a list matches each of them.
//
// A list that holds any or an empty entry matches any address, negated or not:
// the firewall ignores negation on those. Without negation a network of every
// address does too. Negation is applied to each entry on its own, so a negated
// list matches every address outside the entries' overlap: every address when
// they do not overlap, and always more than the "none of them" it reads as. It
// keeps the list and Negated, which the shadow analysis does not rely on and
// the checks for wide-open rules read as any (analysis.IsAnyEndpoint), and a
// warning says what it matches. Either way the aliases the list names keep
// their references.
func (c *converter) listEndpoint(field, stored string, negated bool) common.RuleEndpoint {
	items := splitList(stored)

	if len(items) == 1 {
		return common.RuleEndpoint{
			Address:    items[0],
			AddressRef: c.namedObjects.Ref(items[0]),
			Negated:    negated && items[0] != schema.NetworkAny,
		}
	}

	refs := c.listRefs(items)

	switch {
	case slices.ContainsFunc(items, ignoresNegation):
		c.addWarning(field, stored,
			"address list holds any or an empty entry, so the rule matches any address",
			common.SeverityMedium)

		return common.RuleEndpoint{Address: schema.NetworkAny, AddressRefs: refs}
	case !negated && slices.ContainsFunc(items, isWildcardNetwork):
		c.addWarning(field, stored,
			"address list holds a network of every address, so the rule matches any address",
			common.SeverityMedium)

		return common.RuleEndpoint{Address: schema.NetworkAny, AddressRefs: refs}
	case negated:
		c.addWarning(field, stored,
			"negation on an address list is applied to each entry, so the rule matches every address "+
				"outside their overlap, which is every address when they do not overlap",
			common.SeverityMedium)
	}

	return common.RuleEndpoint{
		Address:     strings.Join(items, listSeparator),
		Negated:     negated,
		AddressRefs: refs,
	}
}

// ignoresNegation reports whether an entry of an address list matches every
// address whether the side is negated or not.
func ignoresNegation(item string) bool {
	return item == "" || item == schema.NetworkAny
}

// isWildcardNetwork reports whether an entry of an address list is a network of
// every address of its family.
func isWildcardNetwork(item string) bool {
	return item == wildcardIPv4 || item == wildcardIPv6
}

// listRefs returns a reference for each entry of an address list that names an
// alias, in list order.
func (c *converter) listRefs(items []string) []common.ObjectRef {
	var refs []common.ObjectRef

	for _, item := range items {
		if ref := c.namedObjects.Ref(item); ref != nil {
			refs = append(refs, *ref)
		}
	}

	return refs
}

// legacyListRefs returns the references for a legacy address that holds a
// list, and nil for a single address, which [common.RuleEndpoint.AddressRef]
// covers.
func (c *converter) legacyListRefs(address string) []common.ObjectRef {
	if !strings.Contains(address, listSeparator) {
		return nil
	}

	return c.listRefs(splitList(address))
}

// modelRulePort returns a port of the filter model and the alias it names, if
// any. A service name becomes its number, since the port checks read numbers
// and the legacy store holds only those; OPNsense resolves the name before it
// looks for an alias.
func (c *converter) modelRulePort(port string) (string, *common.ObjectRef) {
	if number, ok := wellKnownPorts[strings.ToLower(port)]; ok {
		return number, nil
	}

	return port, c.namedObjects.Ref(port)
}

// maxPacketRate returns a rule's packet rate limit as number/seconds, or nothing
// when either part is empty or 0, in which case the firewall applies none.
func maxPacketRate(rule schema.FirewallFilterRule) string {
	if !modelFlagSet(rule.MaxPktRateNumber) || !modelFlagSet(rule.MaxPktRateSeconds) {
		return ""
	}

	return rule.MaxPktRateNumber + "/" + rule.MaxPktRateSeconds
}

// modelFlag reads a flag of the filter model that defaults to on.
func modelFlag(value *string) bool {
	return value == nil || modelFlagSet(*value)
}

// modelFlagSet reads a flag of the filter model the way the firewall does:
// anything but an empty element and 0 sets it. The model itself writes 0 or 1,
// so this differs from [shared.IsValueTrue] only for text nothing but a hand
// edit puts there, and for that text the firewall's reading is the one to
// report: the other would show a loaded rule as disabled.
func modelFlagSet(value string) bool {
	return value != "" && value != "0"
}

// legacyStateType returns the legacy spelling of a state type of the filter
// model. A rule that names none keeps state.
func legacyStateType(stateType string) string {
	switch stateType {
	case "", stateTypeKeep:
		return stateTypeKeep + stateSuffix
	case "sloppy", "modulate", "synproxy":
		return stateType + stateSuffix
	default:
		return stateType
	}
}

// legacyProtocol returns the legacy spelling of a protocol of the filter model,
// which writes upper case and spells out any where the legacy store has no
// element.
func legacyProtocol(protocol string) string {
	protocol = strings.ToLower(protocol)
	if protocol == schema.NetworkAny {
		return ""
	}

	return protocol
}

// legacyICMP6Types returns the legacy names for the ICMPv6 type numbers of the
// filter model. A number without a name is kept.
func legacyICMP6Types(types string) string {
	if types == "" {
		return ""
	}

	names := splitList(types)
	for i, number := range names {
		names[i] = cmp.Or(icmp6TypeNames[number], number)
	}

	return strings.Join(names, listSeparator)
}

// splitList splits a comma-separated element into its entries, trimmed. Empty
// entries are kept, because the firewall gives them a meaning; an empty element
// has no entries.
func splitList(value string) []string {
	if value == "" {
		return nil
	}

	items := strings.Split(value, listSeparator)
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}

	return items
}

// listValues returns the entries of a comma-separated element as OPNsense reads
// them to rank a rule: untrimmed, and without the empty ones.
func listValues(value string) []string {
	return slices.DeleteFunc(strings.Split(value, listSeparator), func(item string) bool { return item == "" })
}

// isNumericString reports whether PHP 8's is_numeric accepts s: a decimal
// number with an optional sign, fraction and exponent, between optional
// whitespace.
func isNumericString(s string) bool {
	s = strings.Trim(s, phpWhitespace)
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}

	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(s), "e")
	if hasExponent {
		if exponent != "" && (exponent[0] == '+' || exponent[0] == '-') {
			exponent = exponent[1:]
		}

		if !isDigits(exponent) {
			return false
		}
	}

	whole, fraction, _ := strings.Cut(mantissa, ".")

	return (whole != "" || fraction != "") &&
		(whole == "" || isDigits(whole)) &&
		(fraction == "" || isDigits(fraction))
}

// isDigits reports whether s is a non-empty run of decimal digits.
func isDigits(s string) bool {
	for i := range len(s) {
		if !isDigit(s[i]) {
			return false
		}
	}

	return s != ""
}
