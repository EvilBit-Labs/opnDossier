package pfsense

import (
	"fmt"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// convertNamedObjects builds common.NamedObjects (ADR-0002) from pfSense
// firewall alias definitions at the top-level doc.Aliases.Alias. Unlike
// OPNsense (which has both an MVC-model path and a legacy top-level path),
// pfSense has a single top-level <aliases> element.
func (c *converter) convertNamedObjects(doc *pfsense.Document) common.NamedObjects {
	entries := doc.Aliases.Alias
	if len(entries) == 0 {
		return nil
	}

	result := make(common.NamedObjects, len(entries))
	for i, a := range entries {
		if a.Name == "" {
			c.addWarning(
				fmt.Sprintf("NamedObjects[%d]", i),
				"",
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
			Members:     splitAliasMembers(a.Address),
			Description: a.Descr,
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// splitAliasMembers extracts an alias's member list from address. pfSense
// stores members SPACE-separated in <address> (unlike OPNsense's MVC model,
// which uses a newline-separated <content> element) — strings.Fields splits
// on any run of whitespace.
func splitAliasMembers(address string) []string {
	if address == "" {
		return nil
	}

	return strings.Fields(address)
}

// resolveObjectRef returns a *common.ObjectRef when name matches a key in
// objs, or nil when objs is empty/nil, name is empty, or name does not
// resolve to a known named object (i.e. it is a literal address/port, not an
// alias reference).
func resolveObjectRef(objs common.NamedObjects, name string) *common.ObjectRef {
	if name == "" || len(objs) == 0 {
		return nil
	}
	if _, ok := objs[name]; !ok {
		return nil
	}

	return &common.ObjectRef{Name: name}
}
