package opnsense

import (
	"cmp"
	"fmt"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// convertNamedObjects builds common.NamedObjects (ADR-0002) from OPNsense
// firewall alias definitions. Two independent sources are merged into one
// registry:
//
//  1. The MVC-model path: doc.OPNsense.Firewall.Alias.Aliases.Alias.
//  2. The legacy top-level path: doc.Aliases.Alias (older configs that
//     predate the MVC Firewall/Alias subsystem).
//
// A real-world config populates at most one of these; both are read
// defensively. If the same alias name appears in both (not expected in
// practice), the legacy entry wins because it is processed last and
// map-key assignment overwrites — this is not a documented invariant,
// just deterministic tie-breaking for a case that should never occur.
//
// An alias is disabled when <enabled> is present and is 0 or empty: that is what
// the alias table template and filter_core_get_port_alias both load as no
// members, the template because a config parse drops an empty element and its
// default for a missing one is 0, and the port alias code through !empty(). Any
// other value is enabled, including no, which is why this is modelFlagSet and
// not shared.IsValueTrue.
//
// An absent <enabled> reads as enabled, although the template alone would read it
// as disabled. The model's default is 1 and OPNsense writes the element on every
// save, so only a hand edit or a legacy alias lacks it. Reading absent as enabled
// keeps a legacy alias, and every pfSense alias, the same as an enabled one, so
// that a config adding the element reports nothing (GOTCHAS §3.6).
//
// An external or internal alias still reads as disabled, although the alias
// loader skips those types and leaves their tables as they are. Disabled says
// what the config asks for.
func (c *converter) convertNamedObjects(doc *schema.OpnSenseDocument) common.NamedObjects {
	var entries []schema.Alias

	if doc.OPNsense.Firewall != nil {
		entries = append(entries, doc.OPNsense.Firewall.Alias.Aliases.Alias...)
	}
	entries = append(entries, doc.Aliases.Alias...)

	if len(entries) == 0 {
		return nil
	}

	result := make(common.NamedObjects, len(entries))
	for i, a := range entries {
		if a.Name == "" {
			c.addWarning(
				fmt.Sprintf("NamedObjects[%d]", i),
				a.UUID,
				"firewall alias has empty name",
				common.SeverityMedium,
			)
			continue
		}

		objType := common.NamedObjectType(a.Type)
		if a.Type != "" && !objType.IsValid() {
			c.addWarning(
				fmt.Sprintf("NamedObjects[%s].Type", a.Name),
				a.Type,
				"unrecognized named-object type",
				common.SeverityLow,
			)
		}

		result[a.Name] = common.NamedObject{
			Name:           a.Name,
			Type:           objType,
			Members:        aliasMembers(a),
			Description:    cmp.Or(a.ModelDescription, a.Description),
			Disabled:       a.Enabled != nil && !modelFlagSet(*a.Enabled),
			Proto:          a.Proto,
			Interface:      a.Interface,
			PathExpression: a.PathExpression,
			Expire:         a.Expire,
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// aliasMembers extracts an alias's member list from the elements that hold it.
//
// content (the modern MVC <content> element) is newline-separated, mirroring
// KeaSubnet.Pools (GOTCHAS §18.2), and takes priority: the model writes no other
// source.
//
// A legacy alias keeps every source it holds, in the order migration M1_0_0
// tries them: <url>, each <aliasurl>, <address>. The release decides which one
// the firewall loads. On a url alias, OPNsense up to 17.7 loads <address>, where
// it kept what it last fetched. A url_ports alias loads it at the 17.1 tag and
// nothing from 17.1.11 through 17.7. From 18.1 both fetch <aliasurl> and ignore
// <address>. A change to either can change what a rule matches, so neither may
// hide the other. Reporting a url_ports change the firewall ignored on those
// releases errs in the safe direction. A config holding both reports a
// members change when it migrates, since the model keeps the URLs alone, and that
// is what the firewall then loads.
//
// address (the legacy field name) may use either newline or space separation
// depending on config vintage. strings.Fields splits on any run of whitespace,
// so both conventions are handled without guessing which one a given legacy
// config used.
func aliasMembers(a schema.Alias) []string {
	if a.Content != "" {
		return splitNonEmpty(a.Content, "\n")
	}

	members := splitNonEmpty(a.URL, "\n")
	members = append(members, splitNonEmpty(strings.Join(a.AliasURLs, "\n"), "\n")...)

	return append(members, strings.Fields(a.Address)...)
}
