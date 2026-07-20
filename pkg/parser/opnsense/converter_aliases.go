package opnsense

import (
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
			Name:        a.Name,
			Type:        objType,
			Members:     splitAliasMembers(a.Content, a.Address),
			Description: a.Description,
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// splitAliasMembers extracts an alias's member list from whichever of
// content/address is populated. content (the modern MVC <content> element)
// is newline-separated, mirroring KeaSubnet.Pools (GOTCHAS §18.2), and takes
// priority when non-empty. address (the legacy field name) may use either
// newline or space separation depending on config vintage — strings.Fields
// splits on any run of whitespace, so both conventions are handled without
// guessing which one a given legacy config used.
func splitAliasMembers(content, address string) []string {
	if content != "" {
		return splitNonEmpty(content, "\n")
	}
	if address == "" {
		return nil
	}
	return strings.Fields(address)
}
