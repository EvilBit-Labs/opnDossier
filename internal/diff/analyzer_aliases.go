package diff

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareAliases compares the named objects (aliases) of two configs, paired by
// name.
//
// A rule that names an alias holds only its name (common.ObjectRef), so the
// firewall and NAT comparisons see no change when the alias's members do. This
// comparison is what reports a pass rule whose effective source, destination or
// port set grew because the alias it names did (#953).
//
// There is no section-level guard: an alias added or removed is reported on its
// own, as firewall rules and users are (GOTCHAS §4.1).
//
// oldCfg and newCfg supply the rules that name each alias, for the security
// impact; see aliasImpact.
func (a *Analyzer) CompareAliases(oldCfg, newCfg *common.CommonDevice) []Change {
	oldObjs, newObjs := oldCfg.NamedObjects, newCfg.NamedObjects
	if len(oldObjs) == 0 && len(newObjs) == 0 {
		return nil
	}

	oldActive := activeAliases(oldCfg)
	newActive := activeAliases(newCfg)

	var changes []Change

	for _, name := range slices.Sorted(maps.Keys(oldObjs)) {
		if _, ok := newObjs[name]; ok {
			continue
		}
		obj := oldObjs[name]
		changes = append(changes, Change{
			Type:           ChangeRemoved,
			Section:        SectionAliases,
			Path:           aliasPath(name),
			Description:    "Removed alias: " + aliasDescription(name, obj),
			OldValue:       formatAlias(obj),
			SecurityImpact: aliasImpact(oldActive[name]),
		})
	}

	for _, name := range slices.Sorted(maps.Keys(newObjs)) {
		if _, ok := oldObjs[name]; ok {
			continue
		}
		obj := newObjs[name]
		changes = append(changes, Change{
			Type:           ChangeAdded,
			Section:        SectionAliases,
			Path:           aliasPath(name),
			Description:    "Added alias: " + aliasDescription(name, obj),
			NewValue:       formatAlias(obj),
			SecurityImpact: aliasImpact(newActive[name]),
		})
	}

	for _, name := range slices.Sorted(maps.Keys(oldObjs)) {
		newObj, ok := newObjs[name]
		if !ok {
			continue
		}
		changes = append(changes, compareAlias(name, oldObjs[name], newObj,
			aliasImpact(oldActive[name] || newActive[name]))...)
	}

	return changes
}

// compareAlias returns one entry per field of the alias that changed. When a
// field is added to common.NamedObject it belongs here;
// TestCompareAlias_ComparesEveryNamedObjectField fails until it is.
//
// The members entry is summarized: its values are the members joined for
// display, and normalization must not hide a change to one of them, such as a
// member that gained or lost a space, behind the joined text (GOTCHAS §4.5).
func compareAlias(name string, old, newObj common.NamedObject, impact string) []Change {
	var changes []Change

	// rated appends an entry for a field that changes what the alias matches.
	rated := func(field, title, oldValue, newValue string, summarized bool) {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionAliases,
			Path:           aliasPath(name) + "." + field,
			Description:    title + " changed for alias " + aliasText(name),
			OldValue:       oldValue,
			NewValue:       newValue,
			SecurityImpact: impact,
			summarized:     summarized,
		})
	}

	if old.Type != newObj.Type {
		rated("type", "Type", aliasText(string(old.Type)), aliasText(string(newObj.Type)), false)
	}

	if !slices.Equal(old.Members, newObj.Members) {
		rated("members", "Members", formatMembers(old.Members), formatMembers(newObj.Members), true)
	}

	if old.Disabled != newObj.Disabled {
		rated("enabled", "Enable state",
			strconv.FormatBool(!old.Disabled), strconv.FormatBool(!newObj.Disabled), false)
	}

	if old.Proto != newObj.Proto {
		rated("proto", "Address families", aliasText(old.Proto), aliasText(newObj.Proto), false)
	}

	if old.Interface != newObj.Interface {
		rated("interface", "Interface", aliasText(old.Interface), aliasText(newObj.Interface), false)
	}

	if old.PathExpression != newObj.PathExpression {
		rated("path_expression", "Path expression",
			aliasText(old.PathExpression), aliasText(newObj.PathExpression), false)
	}

	if old.Expire != newObj.Expire {
		rated("expire", "Expire time", aliasText(old.Expire), aliasText(newObj.Expire), false)
	}

	if old.Description != newObj.Description {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionAliases,
			Path:        aliasPath(name) + ".description",
			Description: "Description changed for alias " + aliasText(name),
			OldValue:    aliasText(old.Description),
			NewValue:    aliasText(newObj.Description),
		})
	}

	return changes
}

// activeAliases returns the aliases that an enabled firewall rule, outbound NAT
// rule or port forward names, directly or through an alias that has it as a
// member. Every alias reference on those rules counts;
// TestActiveAliases_EveryRuleReferenceCounts fails when one is added to the
// model and not here.
//
// Rules of every action count, not only pass rules: an alias that a block rule
// names losing a member lets that member through to the rules below it, and an
// alias on a no-rdr port forward losing one sends it on to the forwards below.
// Disabled rules are left out, unlike the unused-object roots: a change to an
// alias that only a disabled rule names changes no traffic until the rule is
// enabled, and that is reported as a change to the rule. Outbound NAT rules are
// left out for the same reason in a mode that does not load them; a change of
// mode is reported at nat.outbound.mode.
func activeAliases(cfg *common.CommonDevice) map[string]bool {
	var roots []string

	addRef := func(ref *common.ObjectRef) {
		if ref != nil && ref.Name != "" {
			roots = append(roots, ref.Name)
		}
	}
	addEndpoint := func(ep common.RuleEndpoint) {
		addRef(ep.AddressRef)
		addRef(ep.PortRef)
		for i := range ep.AddressRefs {
			addRef(&ep.AddressRefs[i])
		}
	}

	for _, rule := range cfg.FirewallRules {
		if rule.Disabled {
			continue
		}
		addEndpoint(rule.Source)
		addEndpoint(rule.Destination)
		addRef(rule.TargetRef)
	}

	if loadsOutboundRules(cfg.NAT.OutboundMode) {
		for _, rule := range cfg.NAT.OutboundRules {
			if rule.Disabled {
				continue
			}
			addEndpoint(rule.Source)
			addEndpoint(rule.Destination)
			addRef(rule.TargetRef)
			addRef(rule.SourcePortRef)
			addRef(rule.NatPortRef)
		}
	}

	for _, rule := range cfg.NAT.InboundRules {
		if rule.Disabled {
			continue
		}
		addEndpoint(rule.Source)
		addEndpoint(rule.Destination)
		addRef(rule.InternalIPRef)
		addRef(rule.InternalPortRef)
		addRef(rule.ExternalPortRef)
		addRef(rule.LocalPortRef)
	}

	return analysis.ReachableObjects(cfg.NamedObjects, roots)
}

// loadsOutboundRules reports whether a firewall in the given outbound NAT mode
// loads the manual outbound rules: only advanced and hybrid do, on both vendors
// (filter_configure_sync in OPNsense's filter.inc, filter_nat_rules_generate in
// pfSense's). Any other value, or none, leaves them unloaded.
func loadsOutboundRules(mode common.NATOutboundMode) bool {
	return mode == common.OutboundAdvanced || mode == common.OutboundHybrid
}

// aliasImpact rates a change to an alias's presence or to a field that changes
// what it matches: medium when an enabled rule or port forward uses it, since
// the change can widen what the firewall passes or exposes, and low otherwise. A
// description change is not rated.
func aliasImpact(active bool) string {
	if active {
		return string(SecurityImpactMedium)
	}

	return string(SecurityImpactLow)
}

// aliasPath returns the diff path of the alias with the given name.
func aliasPath(name string) string {
	return fmt.Sprintf("aliases.alias[%s]", aliasText(name))
}

// aliasDescription returns the alias name, with its description when it has one.
func aliasDescription(name string, obj common.NamedObject) string {
	if obj.Description == "" {
		return aliasText(name)
	}

	return fmt.Sprintf("%s (%s)", aliasText(name), aliasText(obj.Description))
}

// formatAlias summarizes an alias as its type and members.
func formatAlias(obj common.NamedObject) string {
	return fmt.Sprintf("%s: %s", aliasText(string(obj.Type)), formatMembers(obj.Members))
}

// aliasText returns a value read from an alias as it can be shown on a line of
// the diff: unchanged, or quoted if it holds a character that does not print. A
// line feed would forge a line of the output, a carriage return would overwrite
// the one it is on, and a bidirectional override would reorder how it reads. The
// terminal formatters print every section raw, so until they escape it this is
// what protects alias entries.
func aliasText(s string) string {
	if strings.ContainsFunc(s, doesNotPrint) {
		return strconv.Quote(s)
	}

	return s
}

// doesNotPrint reports a rune that strconv.Quote would escape as not printable.
func doesNotPrint(r rune) bool {
	return !strconv.IsPrint(r)
}

// formatMembers joins alias members for display. The parsers keep a comma, a
// double quote or a character that does not print inside a member, so when one
// holds any of these every member is quoted; otherwise []string{"a, b"} and
// []string{"a", "b"} would both read "a, b", []string{`"a`, `b"`} would read like
// the first one quoted, and aliasText's hazards would apply. An empty member is
// quoted too, or []string{""} would read like no members at all; neither parser
// produces one, so that clause only serves a device built another way.
func formatMembers(members []string) string {
	if !slices.ContainsFunc(members, memberNeedsQuoting) {
		return strings.Join(members, ", ")
	}

	quoted := make([]string, 0, len(members))
	for _, m := range members {
		quoted = append(quoted, strconv.Quote(m))
	}

	return strings.Join(quoted, ", ")
}

// memberNeedsQuoting reports whether a member cannot be shown as it stands.
func memberNeedsQuoting(m string) bool {
	return m == "" || strings.ContainsAny(m, `,"`) || strings.ContainsFunc(m, doesNotPrint)
}
