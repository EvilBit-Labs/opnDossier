package diff

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"

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
			summarized:     true,
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
			summarized:     true,
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

	if old.Type != newObj.Type {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionAliases,
			Path:           aliasPath(name) + ".type",
			Description:    "Type changed for alias " + name,
			OldValue:       string(old.Type),
			NewValue:       string(newObj.Type),
			SecurityImpact: impact,
		})
	}

	if !slices.Equal(old.Members, newObj.Members) {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionAliases,
			Path:           aliasPath(name) + ".members",
			Description:    "Members changed for alias " + name,
			OldValue:       formatMembers(old.Members),
			NewValue:       formatMembers(newObj.Members),
			SecurityImpact: impact,
			summarized:     true,
		})
	}

	if old.Description != newObj.Description {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionAliases,
			Path:        aliasPath(name) + ".description",
			Description: "Description changed for alias " + name,
			OldValue:    old.Description,
			NewValue:    newObj.Description,
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
// enabled, and that is reported as a change to the rule.
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

// aliasImpact rates a change to an alias's type, members or presence: medium
// when an enabled rule or port forward uses it, since the change can widen what
// the firewall passes or exposes, and low otherwise. A description change is not
// rated.
func aliasImpact(active bool) string {
	if active {
		return string(SecurityImpactMedium)
	}

	return string(SecurityImpactLow)
}

// aliasPath returns the diff path of the alias with the given name.
func aliasPath(name string) string {
	return fmt.Sprintf("aliases.alias[%s]", name)
}

// aliasDescription returns the alias name, with its description when it has one.
func aliasDescription(name string, obj common.NamedObject) string {
	if obj.Description == "" {
		return name
	}

	return fmt.Sprintf("%s (%s)", name, obj.Description)
}

// formatAlias summarizes an alias as its type and members.
func formatAlias(obj common.NamedObject) string {
	return fmt.Sprintf("%s: %s", obj.Type, formatMembers(obj.Members))
}

// formatMembers joins alias members for display. The parsers keep a comma, a
// double quote or a control character inside a member, so when one holds any of
// these, or is empty, every member is quoted; otherwise []string{"a, b"} and
// []string{"a", "b"} would both read "a, b", []string{`"a`, `b"`} would read like
// the first one quoted, []string{""} would read like no members at all, and a
// carriage return would overwrite the terminal line.
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
	return m == "" || strings.ContainsAny(m, `,"`) || strings.ContainsFunc(m, unicode.IsControl)
}
