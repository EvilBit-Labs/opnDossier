package diff

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompareAlias_ComparesEveryNamedObjectField fails when a field of
// common.NamedObject is added without a comparison in compareAlias, which would
// make a change to it produce no diff entry (GOTCHAS §4.2).
func TestCompareAlias_ComparesEveryNamedObjectField(t *testing.T) {
	t.Parallel()

	equal := func(a, b common.NamedObject) bool {
		return len(compareAlias("x", a, b, "")) == 0
	}

	assertEqualityCoversEveryField(t, equal, map[string]string{
		"Name": "aliases are paired by name, so a different name is an addition and a removal",
	})
}

// aliasDiffDevice returns a device holding one pass rule from SERVERS to PORTS and
// three aliases, PORTS, SERVERS and SPARE, that no other rule names.
func aliasDiffDevice() *common.CommonDevice {
	return &common.CommonDevice{
		NamedObjects: common.NamedObjects{
			"PORTS":   {Name: "PORTS", Type: common.NamedObjectTypePort, Members: []string{"80", "443"}},
			"SERVERS": {Name: "SERVERS", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.1"}},
			"SPARE":   {Name: "SPARE", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.9"}},
		},
		FirewallRules: []common.FirewallRule{{
			Type:        common.RuleTypePass,
			Interfaces:  []string{"wan"},
			Source:      common.RuleEndpoint{Address: "SERVERS", AddressRef: &common.ObjectRef{Name: "SERVERS"}},
			Destination: common.RuleEndpoint{Address: "lan", Port: "PORTS", PortRef: &common.ObjectRef{Name: "PORTS"}},
		}},
	}
}

// compareAliasesCase is one row of TestCompareAliases: mutate edits the two
// devices aliasDiffDevice returns, and want lists the entries expected in order.
type compareAliasesCase struct {
	name   string
	mutate func(old, newCfg *common.CommonDevice)
	want   []Change
}

func TestCompareAliases(t *testing.T) {
	t.Parallel()

	for _, tt := range compareAliasesCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			old, newCfg := aliasDiffDevice(), aliasDiffDevice()
			tt.mutate(old, newCfg)

			got := NewAnalyzer().CompareAliases(old, newCfg)

			require.Len(t, got, len(tt.want), "%+v", got)
			for i, want := range tt.want {
				assert.Equal(t, want.Type, got[i].Type)
				assert.Equal(t, SectionAliases, got[i].Section)
				assert.Equal(t, want.Path, got[i].Path)
				assert.Equal(t, want.Description, got[i].Description)
				assert.Equal(t, want.OldValue, got[i].OldValue)
				assert.Equal(t, want.NewValue, got[i].NewValue)
				assert.Equal(t, want.SecurityImpact, got[i].SecurityImpact)
			}
		})
	}
}

// TestCompareAliases_SortedByName pins that entries come out removals first,
// then additions, then modifications, each by name. Several names per group,
// since Go's map order can pass a test of two by chance.
func TestCompareAliases_SortedByName(t *testing.T) {
	t.Parallel()

	alias := func(name, member string) common.NamedObject {
		return common.NamedObject{Name: name, Type: common.NamedObjectTypeHost, Members: []string{member}}
	}

	old := &common.CommonDevice{NamedObjects: common.NamedObjects{}}
	newCfg := &common.CommonDevice{NamedObjects: common.NamedObjects{}}

	var want []string

	const names = 8
	for i := range names {
		name := fmt.Sprintf("REMOVED_%d", i)
		old.NamedObjects[name] = alias(name, "10.0.0.1")
		want = append(want, aliasPath(name))
	}
	for i := range names {
		name := fmt.Sprintf("ADDED_%d", i)
		newCfg.NamedObjects[name] = alias(name, "10.0.0.1")
		want = append(want, aliasPath(name))
	}
	for i := range names {
		name := fmt.Sprintf("CHANGED_%d", i)
		old.NamedObjects[name] = alias(name, "10.0.0.1")
		newCfg.NamedObjects[name] = alias(name, "10.0.0.2")
		want = append(want, aliasPath(name)+".members")
	}

	got := NewAnalyzer().CompareAliases(old, newCfg)

	paths := make([]string, 0, len(got))
	for i := range got {
		paths = append(paths, got[i].Path)
	}
	assert.Equal(t, want, paths)
}

func compareAliasesCases() []compareAliasesCase {
	cases := compareAliasesFieldCases()
	cases = append(cases, compareAliasesModelFieldCases()...)
	cases = append(cases, compareAliasesTextCases()...)
	cases = append(cases, compareAliasesUnprintableCases()...)
	cases = append(cases, compareAliasesNameTextCases()...)
	cases = append(cases, compareAliasesPresenceCases()...)

	return append(cases, compareAliasesReferenceCases()...)
}

// compareAliasesFieldCases are the TestCompareAliases rows that change a field
// of an alias both configs hold.
func compareAliasesFieldCases() []compareAliasesCase {
	return []compareAliasesCase{
		{
			name:   "unchanged",
			mutate: func(_, _ *common.CommonDevice) {},
		},
		{
			name: "members widened on an alias a pass rule names",
			mutate: func(_, n *common.CommonDevice) {
				n.NamedObjects["PORTS"] = common.NamedObject{
					Name: "PORTS", Type: common.NamedObjectTypePort, Members: []string{"1:65535"},
				}
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[PORTS].members",
				Description: "Members changed for alias PORTS",
				OldValue:    "80, 443", NewValue: "1:65535", SecurityImpact: "medium",
			}},
		},
		{
			name: "type and members changed on an alias no rule names",
			mutate: func(_, n *common.CommonDevice) {
				n.NamedObjects["SPARE"] = common.NamedObject{
					Name: "SPARE", Type: common.NamedObjectTypeNetwork, Members: []string{"0.0.0.0/0"},
				}
			},
			want: []Change{
				{
					Type: ChangeModified, Path: "aliases.alias[SPARE].type",
					Description: "Type changed for alias SPARE",
					OldValue:    "host", NewValue: "network", SecurityImpact: "low",
				},
				{
					Type: ChangeModified, Path: "aliases.alias[SPARE].members",
					Description: "Members changed for alias SPARE",
					OldValue:    "10.0.0.9", NewValue: "0.0.0.0/0", SecurityImpact: "low",
				},
			},
		},
		{
			name: "members reordered",
			mutate: func(_, n *common.CommonDevice) {
				n.NamedObjects["PORTS"] = common.NamedObject{
					Name: "PORTS", Type: common.NamedObjectTypePort, Members: []string{"443", "80"},
				}
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[PORTS].members",
				Description: "Members changed for alias PORTS",
				OldValue:    "80, 443", NewValue: "443, 80", SecurityImpact: "medium",
			}},
		},
		{
			name: "description changed",
			mutate: func(_, n *common.CommonDevice) {
				spare := n.NamedObjects["SPARE"]
				spare.Description = "spare hosts"
				n.NamedObjects["SPARE"] = spare
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].description",
				Description: "Description changed for alias SPARE",
				NewValue:    "spare hosts",
			}},
		},
	}
}

// compareAliasesModelFieldCases are the TestCompareAliases rows for the fields
// only OPNsense's alias model has.
func compareAliasesModelFieldCases() []compareAliasesCase {
	return []compareAliasesCase{
		{
			name: "alias disabled",
			mutate: func(_, n *common.CommonDevice) {
				servers := n.NamedObjects["SERVERS"]
				servers.Disabled = true
				n.NamedObjects["SERVERS"] = servers
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SERVERS].enabled",
				Description: "Enable state changed for alias SERVERS",
				OldValue:    "true", NewValue: "false", SecurityImpact: "medium",
			}},
		},
		{
			name: "alias enabled",
			mutate: func(o, _ *common.CommonDevice) {
				spare := o.NamedObjects["SPARE"]
				spare.Disabled = true
				o.NamedObjects["SPARE"] = spare
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].enabled",
				Description: "Enable state changed for alias SPARE",
				OldValue:    "false", NewValue: "true", SecurityImpact: "low",
			}},
		},
		{
			name: "address families widened",
			mutate: func(o, n *common.CommonDevice) {
				servers := o.NamedObjects["SERVERS"]
				servers.Proto = "IPv4"
				o.NamedObjects["SERVERS"] = servers
				servers.Proto = "IPv4,IPv6"
				n.NamedObjects["SERVERS"] = servers
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SERVERS].proto",
				Description: "Address families changed for alias SERVERS",
				OldValue:    "IPv4", NewValue: "IPv4,IPv6", SecurityImpact: "medium",
			}},
		},
		{
			name: "tracked interface changed",
			mutate: func(o, n *common.CommonDevice) {
				servers := o.NamedObjects["SERVERS"]
				servers.Interface = "lan"
				o.NamedObjects["SERVERS"] = servers
				servers.Interface = "opt1"
				n.NamedObjects["SERVERS"] = servers
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SERVERS].interface",
				Description: "Interface changed for alias SERVERS",
				OldValue:    "lan", NewValue: "opt1", SecurityImpact: "medium",
			}},
		},
		{
			name: "path expression changed",
			mutate: func(o, n *common.CommonDevice) {
				servers := o.NamedObjects["SERVERS"]
				servers.PathExpression = ".a"
				o.NamedObjects["SERVERS"] = servers
				servers.PathExpression = ".b"
				n.NamedObjects["SERVERS"] = servers
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SERVERS].path_expression",
				Description: "Path expression changed for alias SERVERS",
				OldValue:    ".a", NewValue: ".b", SecurityImpact: "medium",
			}},
		},
		{
			name: "expire time lowered",
			mutate: func(o, n *common.CommonDevice) {
				servers := o.NamedObjects["SERVERS"]
				servers.Expire = "2592000"
				o.NamedObjects["SERVERS"] = servers
				servers.Expire = "60"
				n.NamedObjects["SERVERS"] = servers
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SERVERS].expire",
				Description: "Expire time changed for alias SERVERS",
				OldValue:    "2592000", NewValue: "60", SecurityImpact: "medium",
			}},
		},
		{
			name: "expire time removed from an alias no rule names",
			mutate: func(o, _ *common.CommonDevice) {
				spare := o.NamedObjects["SPARE"]
				spare.Expire = "60"
				o.NamedObjects["SPARE"] = spare
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].expire",
				Description: "Expire time changed for alias SPARE",
				OldValue:    "60", SecurityImpact: "low",
			}},
		},
	}
}

// compareAliasesTextCases are the TestCompareAliases rows that pin how a value
// is shown when it cannot be printed as it stands.
func compareAliasesTextCases() []compareAliasesCase {
	spareWith := func(members ...string) common.NamedObject {
		return common.NamedObject{Name: "SPARE", Type: common.NamedObjectTypeHost, Members: members}
	}
	memberChange := func(oldValue, newValue string) []Change {
		return []Change{{
			Type: ChangeModified, Path: "aliases.alias[SPARE].members",
			Description: "Members changed for alias SPARE",
			OldValue:    oldValue, NewValue: newValue, SecurityImpact: "low",
		}}
	}

	return []compareAliasesCase{
		{
			// The parsers keep a comma inside a member, so joining alone would
			// show both sides as "a, b".
			name: "member split at its comma",
			mutate: func(o, n *common.CommonDevice) {
				o.NamedObjects["SPARE"] = spareWith("a, b")
				n.NamedObjects["SPARE"] = spareWith("a", "b")
			},
			want: memberChange(`"a, b"`, "a, b"),
		},
		{
			// Unquoted, the new members would read `"a, b"`, the same as the
			// old member quoted.
			name: "members holding double quotes",
			mutate: func(o, n *common.CommonDevice) {
				o.NamedObjects["SPARE"] = spareWith("a, b")
				n.NamedObjects["SPARE"] = spareWith(`"a`, `b"`)
			},
			want: memberChange(`"a, b"`, `"\"a", "b\""`),
		},
		{
			// The parsers trim a member, so a carriage return reaches here only
			// from inside one. Unquoted, it would overwrite the terminal line.
			name:   "member holding a carriage return",
			mutate: func(_, n *common.CommonDevice) { n.NamedObjects["SPARE"] = spareWith("10.0\r.0.9") },
			want:   memberChange("10.0.0.9", `"10.0\r.0.9"`),
		},
		{
			// U+009B is a control character that is not whitespace.
			name:   "member holding a control character",
			mutate: func(_, n *common.CommonDevice) { n.NamedObjects["SPARE"] = spareWith("10.0.0.9\u009b") },
			want:   memberChange("10.0.0.9", `"10.0.0.9\u009b"`),
		},
		{
			// A format character, which unicode.IsControl does not report.
			name:   "member holding a bidirectional override",
			mutate: func(_, n *common.CommonDevice) { n.NamedObjects["SPARE"] = spareWith("10.0.0.9\u202eEVIL") },
			want:   memberChange("10.0.0.9", `"10.0.0.9\u202eEVIL"`),
		},
		{
			// Neither parser produces an empty member. Unquoted, it would read
			// the same as no members.
			name: "empty member added to an empty list",
			mutate: func(o, n *common.CommonDevice) {
				o.NamedObjects["SPARE"] = spareWith()
				n.NamedObjects["SPARE"] = spareWith("")
			},
			want: memberChange("", `""`),
		},
		{
			name: "description holding a line feed on either side",
			mutate: func(o, n *common.CommonDevice) {
				spare := o.NamedObjects["SPARE"]
				spare.Description = "plain\n  - OLD"
				o.NamedObjects["SPARE"] = spare
				spare.Description = "plain\n  ~ FORGED"
				n.NamedObjects["SPARE"] = spare
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].description",
				Description: "Description changed for alias SPARE",
				OldValue:    `"plain\n  - OLD"`, NewValue: `"plain\n  ~ FORGED"`,
			}},
		},
		{
			name: "type holding a carriage return on either side",
			mutate: func(o, n *common.CommonDevice) {
				spare := o.NamedObjects["SPARE"]
				spare.Type = "network\rOLD"
				o.NamedObjects["SPARE"] = spare
				spare.Type = "host\rEVIL"
				n.NamedObjects["SPARE"] = spare
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].type",
				Description: "Type changed for alias SPARE",
				OldValue:    `"network\rOLD"`, NewValue: `"host\rEVIL"`, SecurityImpact: "low",
			}},
		},
	}
}

// compareAliasesUnprintableCases pin one rune of each kind strconv.IsPrint rejects
// and unicode.IsControl does not, with the text the entry must show. Each is a
// literal, so a test of the display cannot narrow along with the code it tests.
func compareAliasesUnprintableCases() []compareAliasesCase {
	spareWith := func(member string) common.NamedObject {
		return common.NamedObject{Name: "SPARE", Type: common.NamedObjectTypeHost, Members: []string{member}}
	}

	tests := []struct {
		kind   string
		member string
		want   string
	}{
		{"a left-to-right mark", "10.0.0.9\u200eEVIL", `"10.0.0.9\u200eEVIL"`},
		{"an Arabic letter mark", "10.0.0.9\u061cEVIL", `"10.0.0.9\u061cEVIL"`},
		{"a bidirectional isolate", "10.0.0.9\u2066EVIL", `"10.0.0.9\u2066EVIL"`},
		{"a non-breaking space", "10.0.0.9\u00a0EVIL", `"10.0.0.9\u00a0EVIL"`},
		{"a line separator", "10.0.0.9\u2028EVIL", `"10.0.0.9\u2028EVIL"`},
	}

	cases := make([]compareAliasesCase, 0, len(tests))
	for _, tt := range tests {
		cases = append(cases, compareAliasesCase{
			name:   "member holding " + tt.kind,
			mutate: func(_, n *common.CommonDevice) { n.NamedObjects["SPARE"] = spareWith(tt.member) },
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].members",
				Description: "Members changed for alias SPARE",
				OldValue:    "10.0.0.9", NewValue: tt.want, SecurityImpact: "low",
			}},
		})
	}

	return cases
}

// compareAliasesNameTextCases are the TestCompareAliases rows that pin how an
// alias name is shown when it cannot be printed as it stands.
func compareAliasesNameTextCases() []compareAliasesCase {
	return []compareAliasesCase{
		{
			name: "name holding a line feed on an alias with no description",
			mutate: func(_, n *common.CommonDevice) {
				n.NamedObjects["ODD\nNAME"] = common.NamedObject{Name: "ODD\nNAME", Type: common.NamedObjectTypeHost}
			},
			want: []Change{{
				Type: ChangeAdded, Path: `aliases.alias["ODD\nNAME"]`,
				Description: `Added alias: "ODD\nNAME"`,
				NewValue:    "host: ", SecurityImpact: "low",
			}},
		},
		{
			name: "name holding a line feed on a description change",
			mutate: func(o, n *common.CommonDevice) {
				o.NamedObjects["ODD\nNAME"] = common.NamedObject{Name: "ODD\nNAME", Description: "old"}
				n.NamedObjects["ODD\nNAME"] = common.NamedObject{Name: "ODD\nNAME", Description: "new"}
			},
			want: []Change{{
				Type: ChangeModified, Path: `aliases.alias["ODD\nNAME"].description`,
				Description: `Description changed for alias "ODD\nNAME"`,
				OldValue:    "old", NewValue: "new",
			}},
		},
		{
			name: "name, description and type holding a line feed on an added alias",
			mutate: func(_, n *common.CommonDevice) {
				n.NamedObjects["ODD\nNAME"] = common.NamedObject{
					Name: "ODD\nNAME", Type: "host\nEVIL", Members: []string{"10.0.0.1"}, Description: "note\nEVIL",
				}
			},
			want: []Change{{
				Type: ChangeAdded, Path: `aliases.alias["ODD\nNAME"]`,
				Description: `Added alias: "ODD\nNAME" ("note\nEVIL")`,
				NewValue:    `"host\nEVIL": 10.0.0.1`, SecurityImpact: "low",
			}},
		},
		{
			name: "name holding a line feed on a modified alias",
			mutate: func(o, n *common.CommonDevice) {
				o.NamedObjects["ODD\nNAME"] = common.NamedObject{Name: "ODD\nNAME", Members: []string{"10.0.0.1"}}
				n.NamedObjects["ODD\nNAME"] = common.NamedObject{Name: "ODD\nNAME", Members: []string{"10.0.0.2"}}
			},
			want: []Change{{
				Type: ChangeModified, Path: `aliases.alias["ODD\nNAME"].members`,
				Description: `Members changed for alias "ODD\nNAME"`,
				OldValue:    "10.0.0.1", NewValue: "10.0.0.2", SecurityImpact: "low",
			}},
		},
	}
}

// compareAliasesPresenceCases are the TestCompareAliases rows that add or
// remove an alias no rule's change is involved in.
func compareAliasesPresenceCases() []compareAliasesCase {
	return []compareAliasesCase{
		{
			name:   "alias no rule names removed",
			mutate: func(_, n *common.CommonDevice) { delete(n.NamedObjects, "SPARE") },
			want: []Change{{
				Type: ChangeRemoved, Path: "aliases.alias[SPARE]",
				Description: "Removed alias: SPARE",
				OldValue:    "host: 10.0.0.9", SecurityImpact: "low",
			}},
		},
		{
			name: "alias with a description removed",
			mutate: func(o, n *common.CommonDevice) {
				spare := o.NamedObjects["SPARE"]
				spare.Description = "spare hosts"
				o.NamedObjects["SPARE"] = spare
				delete(n.NamedObjects, "SPARE")
			},
			want: []Change{{
				Type: ChangeRemoved, Path: "aliases.alias[SPARE]",
				Description: "Removed alias: SPARE (spare hosts)",
				OldValue:    "host: 10.0.0.9", SecurityImpact: "low",
			}},
		},
		{
			name:   "alias added",
			mutate: func(o, _ *common.CommonDevice) { delete(o.NamedObjects, "SPARE") },
			want: []Change{{
				Type: ChangeAdded, Path: "aliases.alias[SPARE]",
				Description: "Added alias: SPARE",
				NewValue:    "host: 10.0.0.9", SecurityImpact: "low",
			}},
		},
		{
			name: "alias with a description added",
			mutate: func(o, n *common.CommonDevice) {
				delete(o.NamedObjects, "SPARE")
				spare := n.NamedObjects["SPARE"]
				spare.Description = "spare hosts"
				n.NamedObjects["SPARE"] = spare
			},
			want: []Change{{
				Type: ChangeAdded, Path: "aliases.alias[SPARE]",
				Description: "Added alias: SPARE (spare hosts)",
				NewValue:    "host: 10.0.0.9", SecurityImpact: "low",
			}},
		},
		{
			// A config with no aliases at all: there is no section-level guard,
			// so each alias gets its own entry and its own rating.
			name:   "every alias removed",
			mutate: func(_, n *common.CommonDevice) { n.NamedObjects = nil },
			want: []Change{
				{
					Type: ChangeRemoved, Path: "aliases.alias[PORTS]",
					Description: "Removed alias: PORTS",
					OldValue:    "port: 80, 443", SecurityImpact: "medium",
				},
				{
					Type: ChangeRemoved, Path: "aliases.alias[SERVERS]",
					Description: "Removed alias: SERVERS",
					OldValue:    "host: 10.0.0.1", SecurityImpact: "medium",
				},
				{
					Type: ChangeRemoved, Path: "aliases.alias[SPARE]",
					Description: "Removed alias: SPARE",
					OldValue:    "host: 10.0.0.9", SecurityImpact: "low",
				},
			},
		},
		{
			name:   "every alias added",
			mutate: func(o, _ *common.CommonDevice) { o.NamedObjects = nil },
			want: []Change{
				{
					Type: ChangeAdded, Path: "aliases.alias[PORTS]",
					Description: "Added alias: PORTS",
					NewValue:    "port: 80, 443", SecurityImpact: "medium",
				},
				{
					Type: ChangeAdded, Path: "aliases.alias[SERVERS]",
					Description: "Added alias: SERVERS",
					NewValue:    "host: 10.0.0.1", SecurityImpact: "medium",
				},
				{
					Type: ChangeAdded, Path: "aliases.alias[SPARE]",
					Description: "Added alias: SPARE",
					NewValue:    "host: 10.0.0.9", SecurityImpact: "low",
				},
			},
		},
		{
			name: "alias added with a member holding a comma",
			mutate: func(o, n *common.CommonDevice) {
				delete(o.NamedObjects, "SPARE")
				n.NamedObjects["SPARE"] = common.NamedObject{
					Name: "SPARE", Type: common.NamedObjectTypeHost, Members: []string{"a, b"},
				}
			},
			want: []Change{{
				Type: ChangeAdded, Path: "aliases.alias[SPARE]",
				Description: "Added alias: SPARE",
				NewValue:    `host: "a, b"`, SecurityImpact: "low",
			}},
		},
	}
}

// compareAliasesReferenceCases are the TestCompareAliases rows where the rule
// that names the alias decides the rating, on one side or both.
func compareAliasesReferenceCases() []compareAliasesCase {
	return []compareAliasesCase{
		{
			// The rule keeps naming SERVERS after the alias is gone, so the
			// removal is rated by the old config, where the rule passed traffic
			// through it.
			name:   "alias a pass rule names removed",
			mutate: func(_, n *common.CommonDevice) { delete(n.NamedObjects, "SERVERS") },
			want: []Change{{
				Type: ChangeRemoved, Path: "aliases.alias[SERVERS]",
				Description: "Removed alias: SERVERS",
				OldValue:    "host: 10.0.0.1", SecurityImpact: "medium",
			}},
		},
		{
			name: "alias a pass rule named only before the change",
			mutate: func(_, n *common.CommonDevice) {
				n.FirewallRules[0].Source = common.RuleEndpoint{Address: "any"}
				n.NamedObjects["SERVERS"] = common.NamedObject{
					Name: "SERVERS", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.2"},
				}
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SERVERS].members",
				Description: "Members changed for alias SERVERS",
				OldValue:    "10.0.0.1", NewValue: "10.0.0.2", SecurityImpact: "medium",
			}},
		},
		{
			name: "alias a pass rule names only after the change",
			mutate: func(_, n *common.CommonDevice) {
				n.FirewallRules[0].Source = common.RuleEndpoint{
					Address:    "SPARE",
					AddressRef: &common.ObjectRef{Name: "SPARE"},
				}
				n.NamedObjects["SPARE"] = common.NamedObject{
					Name: "SPARE", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.0/8"},
				}
			},
			want: []Change{{
				Type: ChangeModified, Path: "aliases.alias[SPARE].members",
				Description: "Members changed for alias SPARE",
				OldValue:    "10.0.0.9", NewValue: "10.0.0.0/8", SecurityImpact: "medium",
			}},
		},
		{
			name: "alias added with the rule that names it",
			mutate: func(o, n *common.CommonDevice) {
				delete(o.NamedObjects, "SPARE")
				n.FirewallRules[0].Source = common.RuleEndpoint{
					Address:    "SPARE",
					AddressRef: &common.ObjectRef{Name: "SPARE"},
				}
			},
			want: []Change{{
				Type: ChangeAdded, Path: "aliases.alias[SPARE]",
				Description: "Added alias: SPARE",
				NewValue:    "host: 10.0.0.9", SecurityImpact: "medium",
			}},
		},
	}
}

// TestCompareAliases_Impact pins which references make an alias change medium:
// an enabled firewall rule of any action, outbound NAT rule or port forward that
// names it, directly or through a group that has it as a member. An outbound NAT
// rule counts only in a mode that loads it.
func TestCompareAliases_Impact(t *testing.T) {
	t.Parallel()

	for _, tt := range append(aliasImpactFirewallCases(), aliasImpactNATCases()...) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			build := func(members ...string) *common.CommonDevice {
				d := &common.CommonDevice{NamedObjects: common.NamedObjects{
					"T": {Name: "T", Type: common.NamedObjectTypeHost, Members: members},
				}}
				tt.cfg(d)

				return d
			}

			got := NewAnalyzer().CompareAliases(build("10.0.0.1"), build("10.0.0.0/8"))

			require.Len(t, got, 1, "%+v", got)
			assert.Equal(t, tt.want, got[0].SecurityImpact)
		})
	}
}

// aliasImpactCase is one row of TestCompareAliases_Impact: cfg sets up the rules
// of a device holding the alias T, on both sides of the diff.
type aliasImpactCase struct {
	name string
	cfg  func(d *common.CommonDevice)
	want string
}

// aliasRef returns a reference to the named alias.
func aliasRef(name string) *common.ObjectRef {
	return &common.ObjectRef{Name: name}
}

func aliasImpactFirewallCases() []aliasImpactCase {
	return []aliasImpactCase{
		{"named by no rule", func(_ *common.CommonDevice) {}, "low"},
		{"destination address of a pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Destination: common.RuleEndpoint{AddressRef: aliasRef("T")},
			}}
		}, "medium"},
		{"source port of a pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Source: common.RuleEndpoint{PortRef: aliasRef("T")},
			}}
		}, "medium"},
		{"entry in an address list of a pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Source: common.RuleEndpoint{AddressRefs: []common.ObjectRef{{Name: "T"}}},
			}}
		}, "medium"},
		{"member of a group a pass rule names", func(d *common.CommonDevice) {
			d.NamedObjects["GROUP"] = common.NamedObject{Name: "GROUP", Type: "networkgroup", Members: []string{"T"}}
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Source: common.RuleEndpoint{AddressRef: aliasRef("GROUP")},
			}}
		}, "medium"},
		{"member of a group two levels under the one a pass rule names", func(d *common.CommonDevice) {
			d.NamedObjects["OUTER"] = common.NamedObject{
				Name:    "OUTER",
				Type:    "networkgroup",
				Members: []string{"INNER"},
			}
			d.NamedObjects["INNER"] = common.NamedObject{Name: "INNER", Type: "networkgroup", Members: []string{"T"}}
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Source: common.RuleEndpoint{AddressRef: aliasRef("OUTER")},
			}}
		}, "medium"},
		{"disabled pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Disabled: true, Source: common.RuleEndpoint{AddressRef: aliasRef("T")},
			}}
		}, "low"},
		{"disabled firewall rule above the enabled one that names it", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{
				{Type: common.RuleTypePass, Disabled: true, Source: common.RuleEndpoint{AddressRef: aliasRef("OTHER")}},
				{Type: common.RuleTypePass, Source: common.RuleEndpoint{AddressRef: aliasRef("T")}},
			}
		}, "medium"},
		{"block rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypeBlock, Source: common.RuleEndpoint{AddressRef: aliasRef("T")},
			}}
		}, "medium"},
		{"redirect target of a firewall rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{Type: common.RuleTypePass, TargetRef: aliasRef("T")}}
		}, "medium"},
	}
}

func aliasImpactNATCases() []aliasImpactCase {
	otherEndpoint := common.RuleEndpoint{AddressRef: aliasRef("OTHER")}
	aliasEndpoint := common.RuleEndpoint{AddressRef: aliasRef("T")}
	outbound := func(mode common.NATOutboundMode, rules ...common.NATRule) func(d *common.CommonDevice) {
		return func(d *common.CommonDevice) {
			d.NAT.OutboundMode = mode
			d.NAT.OutboundRules = rules
		}
	}

	return []aliasImpactCase{
		{
			"translation target of an outbound NAT rule",
			outbound(common.OutboundAdvanced, common.NATRule{TargetRef: aliasRef("T")}),
			"medium",
		},
		{
			"outbound NAT rule in hybrid mode",
			outbound(common.OutboundHybrid, common.NATRule{Source: aliasEndpoint}),
			"medium",
		},
		{
			"outbound NAT rule in advanced mode",
			outbound(common.OutboundAdvanced, common.NATRule{Source: aliasEndpoint}),
			"medium",
		},
		{
			"outbound NAT rule in automatic mode",
			outbound(common.OutboundAutomatic, common.NATRule{Source: aliasEndpoint}),
			"low",
		},
		{
			"outbound NAT rule in disabled mode",
			outbound(common.OutboundDisabled, common.NATRule{Source: aliasEndpoint}),
			"low",
		},
		{"outbound NAT rule with no mode", outbound("", common.NATRule{Source: aliasEndpoint}), "low"},
		{
			"disabled outbound NAT rule",
			outbound(common.OutboundAdvanced, common.NATRule{Disabled: true, TargetRef: aliasRef("T")}),
			"low",
		},
		{
			"disabled outbound NAT rule above the enabled one that names it",
			outbound(common.OutboundAdvanced,
				common.NATRule{Disabled: true, Source: otherEndpoint},
				common.NATRule{Source: aliasEndpoint}),
			"medium",
		},
		{"redirect target of a port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{InternalIPRef: aliasRef("T")}}
		}, "medium"},
		{"external port of a port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{ExternalPortRef: aliasRef("T")}}
		}, "medium"},
		{"disabled port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{Disabled: true, InternalIPRef: aliasRef("T")}}
		}, "low"},
		{"disabled port forward above the enabled one that names it", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{
				{Disabled: true, InternalIPRef: aliasRef("OTHER")},
				{InternalIPRef: aliasRef("T")},
			}
		}, "medium"},
		{"no-redirect port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{NoRDR: true, InternalIPRef: aliasRef("T")}}
		}, "medium"},
	}
}

// TestActiveAliases_EveryRuleReferenceCounts sets each alias reference that a
// firewall rule, an outbound NAT rule and a port forward can hold, one at a
// time, and requires activeAliases to count it. A reference field added to the
// model without a line in activeAliases fails here, rather than rating changes
// to the aliases it names low.
func TestActiveAliases_EveryRuleReferenceCounts(t *testing.T) {
	t.Parallel()

	// ruleList returns the slice of d that holds rules of the named type.
	ruleList := func(d *common.CommonDevice, typeName string) reflect.Value {
		return map[string]reflect.Value{
			"FirewallRule":   reflect.ValueOf(&d.FirewallRules).Elem(),
			"NATRule":        reflect.ValueOf(&d.NAT.OutboundRules).Elem(),
			"InboundNATRule": reflect.ValueOf(&d.NAT.InboundRules).Elem(),
		}[typeName]
	}
	ruleTypes := []reflect.Type{
		reflect.TypeFor[common.FirewallRule](),
		reflect.TypeFor[common.NATRule](),
		reflect.TypeFor[common.InboundNATRule](),
	}

	for _, rt := range ruleTypes {
		for _, path := range aliasRefPaths(t, rt) {
			t.Run(rt.Name()+"."+strings.Join(path, "."), func(t *testing.T) {
				t.Parallel()

				rule := reflect.New(rt).Elem()
				setAliasRef(rule, path, "T")
				d := &common.CommonDevice{
					NamedObjects: common.NamedObjects{
						"T": {Name: "T", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.1"}},
					},
					NAT: common.NATConfig{OutboundMode: common.OutboundAdvanced},
				}
				list := ruleList(d, rt.Name())
				list.Set(reflect.Append(list, rule))

				assert.True(t, activeAliases(d)["T"], "a reference in %s.%s is not counted",
					rt.Name(), strings.Join(path, "."))
			})
		}
	}
}

var (
	objectRefType      = reflect.TypeFor[common.ObjectRef]()
	objectRefPtrType   = reflect.TypeFor[*common.ObjectRef]()
	objectRefSliceType = reflect.TypeFor[[]common.ObjectRef]()
)

// aliasRefPaths returns the field paths of every alias reference in rt: a
// *ObjectRef or []ObjectRef field, found in rt or in any struct it holds,
// directly or through a pointer, slice or array, embedded or not. A field that
// holds an ObjectRef in any other way, a map or a bare ObjectRef, fails the
// test, so a new shape of reference cannot be skipped silently.
func aliasRefPaths(t *testing.T, rt reflect.Type) [][]string {
	t.Helper()

	var paths [][]string
	for f := range rt.Fields() {
		elem := f.Type
		for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice || elem.Kind() == reflect.Array {
			elem = elem.Elem()
		}

		switch {
		case f.Type == objectRefPtrType || f.Type == objectRefSliceType:
			paths = append(paths, []string{f.Name})
		case !holdsObjectRef(f.Type, map[reflect.Type]bool{}):
		case elem.Kind() == reflect.Struct && elem != objectRefType:
			for _, sub := range aliasRefPaths(t, elem) {
				paths = append(paths, append([]string{f.Name}, sub...))
			}
		default:
			t.Fatalf("%s.%s has type %s, which this test cannot set; extend it", rt.Name(), f.Name, f.Type)
		}
	}

	return paths
}

// holdsObjectRef reports whether a value of type rt can hold an ObjectRef.
func holdsObjectRef(rt reflect.Type, seen map[reflect.Type]bool) bool {
	if rt == objectRefType {
		return true
	}
	if seen[rt] {
		return false
	}
	seen[rt] = true

	switch rt.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return holdsObjectRef(rt.Elem(), seen)
	case reflect.Map:
		return holdsObjectRef(rt.Key(), seen) || holdsObjectRef(rt.Elem(), seen)
	case reflect.Struct:
		for f := range rt.Fields() {
			if holdsObjectRef(f.Type, seen) {
				return true
			}
		}

		return false
	default:
		return false
	}
}

// setAliasRef sets the reference at path in v to name, allocating any pointer
// on the way. A list, whether of references or of structs holding one, gets
// the reference in its second entry, so a reader of the first entry alone
// does not pass.
func setAliasRef(v reflect.Value, path []string, name string) {
	f := v.FieldByName(path[0])
	if len(path) == 1 {
		if f.Type() == objectRefSliceType {
			f.Set(reflect.ValueOf([]common.ObjectRef{{Name: "OTHER"}, {Name: name}}))

			return
		}
		f.Set(reflect.ValueOf(&common.ObjectRef{Name: name}))

		return
	}

	for f.Kind() != reflect.Struct {
		switch f.Kind() {
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
			f = f.Elem()
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 2, 2))
			f = f.Index(1)
		default:
			f = f.Index(f.Len() - 1)
		}
	}
	setAliasRef(f, path[1:], name)
}
