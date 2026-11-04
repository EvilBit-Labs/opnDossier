package opnsense

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// gatewayGroupItems returns a group's members as name|tier entries, read as
// GatewayGroupItemField reads a group the GUI wrote. In the legacy form, where
// an <item> carries a tier, each entry keeps its name and tier and overrides
// the 26.7 list for that tier; any other list is split into one entry per
// gateway.
//
// The 26.1 GUI writes legacy entries in gateway order, but the 26.1 reader
// and the 26.7 migration both take them tier by tier, so entries are returned
// in tier order and a group the GUI wrote exports as its migration does. Within
// a tier entries keep their document order, and a tier that is not a number
// sorts last. Tiers the GUI does not write are kept, where the migration would
// move or drop them.
//
// Two hand-edited shapes follow the migration, which stores a legacy name in
// its tier field as it stands: a comma list there is one entry per gateway, and
// a nameless entry adds no gateway yet still overrides that tier's list.
// Trimming a legacy entry does not follow the vendor, which keeps the padding;
// it keeps padding out of the export and stops a padded tier from sorting last.
func gatewayGroupItems(g schema.GatewayGroup) []string {
	type member struct {
		entry string
		tier  int
	}

	lists := []string{strings.Join(g.Item, ","), g.Item2, g.Item3, g.Item4, g.Item5}

	var members []member
	if slices.ContainsFunc(g.Item, func(item string) bool { return strings.Contains(item, "|") }) {
		lists[0] = ""
		for _, item := range g.Item {
			name, rest, _ := strings.Cut(item, "|")
			tier, _, _ := strings.Cut(rest, "|")
			tier = cmp.Or(strings.TrimSpace(tier), "1")
			n, err := strconv.Atoi(tier)
			if err != nil {
				n = math.MaxInt
			} else if n >= 2 && n <= len(lists) {
				lists[n-1] = ""
			}
			for _, gateway := range splitNonEmpty(name, ",") {
				members = append(members, member{entry: gateway + "|" + tier, tier: n})
			}
		}
	}

	for i, list := range lists {
		for _, name := range splitNonEmpty(list, ",") {
			members = append(members, member{entry: fmt.Sprintf("%s|%d", name, i+1), tier: i + 1})
		}
	}

	if len(members) == 0 {
		return nil
	}

	slices.SortStableFunc(members, func(a, b member) int { return cmp.Compare(a.tier, b.tier) })

	items := make([]string, 0, len(members))
	for _, m := range members {
		items = append(items, m.entry)
	}

	return items
}
