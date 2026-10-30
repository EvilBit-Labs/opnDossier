package diff

import (
	"context"
	"path/filepath"
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
				assert.Equal(t, want.OldValue, got[i].OldValue)
				assert.Equal(t, want.NewValue, got[i].NewValue)
				assert.Equal(t, want.SecurityImpact, got[i].SecurityImpact)
			}
		})
	}
}

func compareAliasesCases() []compareAliasesCase {
	return append(compareAliasesFieldCases(), compareAliasesPresenceCases()...)
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
				OldValue: "80, 443", NewValue: "1:65535", SecurityImpact: "medium",
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
					OldValue: "host", NewValue: "network", SecurityImpact: "low",
				},
				{
					Type: ChangeModified, Path: "aliases.alias[SPARE].members",
					OldValue: "10.0.0.9", NewValue: "0.0.0.0/0", SecurityImpact: "low",
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
				OldValue: "80, 443", NewValue: "443, 80", SecurityImpact: "medium",
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
				NewValue: "spare hosts",
			}},
		},
	}
}

// compareAliasesPresenceCases are the TestCompareAliases rows that add or
// remove an alias, or change which rules name it.
func compareAliasesPresenceCases() []compareAliasesCase {
	return []compareAliasesCase{
		{
			name:   "alias no rule names removed",
			mutate: func(_, n *common.CommonDevice) { delete(n.NamedObjects, "SPARE") },
			want: []Change{{
				Type: ChangeRemoved, Path: "aliases.alias[SPARE]",
				OldValue: "host: 10.0.0.9", SecurityImpact: "low",
			}},
		},
		{
			name:   "alias added",
			mutate: func(o, _ *common.CommonDevice) { delete(o.NamedObjects, "SPARE") },
			want: []Change{{
				Type: ChangeAdded, Path: "aliases.alias[SPARE]",
				NewValue: "host: 10.0.0.9", SecurityImpact: "low",
			}},
		},
		{
			// The rule keeps naming SERVERS after the alias is gone, so the
			// removal is rated by the old config, where the rule passed traffic
			// through it.
			name:   "alias a pass rule names removed",
			mutate: func(_, n *common.CommonDevice) { delete(n.NamedObjects, "SERVERS") },
			want: []Change{{
				Type: ChangeRemoved, Path: "aliases.alias[SERVERS]",
				OldValue: "host: 10.0.0.1", SecurityImpact: "medium",
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
				OldValue: "10.0.0.1", NewValue: "10.0.0.2", SecurityImpact: "medium",
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
				OldValue: "10.0.0.9", NewValue: "10.0.0.0/8", SecurityImpact: "medium",
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
				NewValue: "host: 10.0.0.9", SecurityImpact: "medium",
			}},
		},
	}
}

// TestCompareAliases_Impact pins which references make an alias change medium:
// an enabled firewall rule of any action or an enabled port forward that names
// it, directly or through a group that has it as a member.
func TestCompareAliases_Impact(t *testing.T) {
	t.Parallel()

	ref := func(name string) *common.ObjectRef { return &common.ObjectRef{Name: name} }

	tests := []struct {
		name string
		cfg  func(d *common.CommonDevice)
		want string
	}{
		{"named by no rule", func(_ *common.CommonDevice) {}, "low"},
		{"destination address of a pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Destination: common.RuleEndpoint{AddressRef: ref("T")},
			}}
		}, "medium"},
		{"source port of a pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Source: common.RuleEndpoint{PortRef: ref("T")},
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
				Type: common.RuleTypePass, Source: common.RuleEndpoint{AddressRef: ref("GROUP")},
			}}
		}, "medium"},
		{"disabled pass rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypePass, Disabled: true, Source: common.RuleEndpoint{AddressRef: ref("T")},
			}}
		}, "low"},
		{"block rule", func(d *common.CommonDevice) {
			d.FirewallRules = []common.FirewallRule{{
				Type: common.RuleTypeBlock, Source: common.RuleEndpoint{AddressRef: ref("T")},
			}}
		}, "medium"},
		{"redirect target of a port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{InternalIPRef: ref("T")}}
		}, "medium"},
		{"external port of a port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{ExternalPortRef: ref("T")}}
		}, "medium"},
		{"disabled port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{Disabled: true, InternalIPRef: ref("T")}}
		}, "low"},
		{"no-redirect port forward", func(d *common.CommonDevice) {
			d.NAT.InboundRules = []common.InboundNATRule{{NoRDR: true, InternalIPRef: ref("T")}}
		}, "medium"},
	}

	for _, tt := range tests {
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

// TestEngine_Compare_Aliases_ParsedFixture runs the case #953 reported through
// the parser and the engine: widening the port alias the fixture's only pass
// rule names used to report no changes.
func TestEngine_Compare_Aliases_ParsedFixture(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "testdata", "pfsense", aliasFixture)
	old, newCfg := parseFixture(t, path), parseFixture(t, path)

	require.Contains(t, newCfg.NamedObjects, "WEB_PORTS")
	require.NotNil(t, newCfg.FirewallRules[0].Destination.PortRef)
	require.Equal(t, "WEB_PORTS", newCfg.FirewallRules[0].Destination.PortRef.Name)

	ports := newCfg.NamedObjects["WEB_PORTS"]
	ports.Members = []string{"1:65535"}
	newCfg.NamedObjects["WEB_PORTS"] = ports

	result, err := NewEngine(old, newCfg, Options{}, nil).Compare(context.Background())
	require.NoError(t, err)

	require.Len(t, result.Changes, 1, "%+v", result.Changes)
	got := result.Changes[0]
	assert.Equal(t, SectionAliases, got.Section)
	assert.Equal(t, "aliases.alias[WEB_PORTS].members", got.Path)
	assert.Equal(t, "1:65535", got.NewValue)
	assert.Equal(t, "medium", got.SecurityImpact)

	filtered, err := NewEngine(old, newCfg, Options{Sections: []string{"firewall"}}, nil).
		Compare(context.Background())
	require.NoError(t, err)
	assert.Empty(t, filtered.Changes, "--section firewall must leave the alias change out")
}

// TestEngine_Compare_Normalize_KeepsAliasMemberChange pins that a members
// change is never dropped as formatting only. Joined for display, a member that
// gained a trailing space reads the same as before once whitespace is
// normalized (GOTCHAS §4.5).
func TestEngine_Compare_Normalize_KeepsAliasMemberChange(t *testing.T) {
	t.Parallel()

	old, newCfg := aliasDiffDevice(), aliasDiffDevice()
	newCfg.NamedObjects["SPARE"] = common.NamedObject{
		Name: "SPARE", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.9 "},
	}

	result, err := NewEngine(old, newCfg, Options{Normalize: true}, nil).Compare(context.Background())
	require.NoError(t, err)

	require.Len(t, result.Changes, 1, "%+v", result.Changes)
	assert.Equal(t, "aliases.alias[SPARE].members", result.Changes[0].Path)
}
