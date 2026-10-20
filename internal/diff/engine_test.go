package diff

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPathInterfacesWanIP = "interfaces.wan.ipAddress"

func TestNewEngine(t *testing.T) {
	old := &common.CommonDevice{}
	newCfg := &common.CommonDevice{}
	opts := Options{}

	engine := NewEngine(old, newCfg, opts, nil)

	require.NotNil(t, engine)
	assert.Equal(t, old, engine.oldConfig)
	assert.Equal(t, newCfg, engine.newConfig)
	assert.NotNil(t, engine.analyzer)
}

func TestEngine_Compare_IdenticalConfigs(t *testing.T) {
	old := &common.CommonDevice{}
	old.System.Hostname = "firewall"
	old.System.Domain = "example.com"

	newCfg := &common.CommonDevice{}
	newCfg.System.Hostname = "firewall"
	newCfg.System.Domain = "example.com"

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges())
	assert.Equal(t, 0, result.Summary.Total)
}

func TestEngine_Compare_HostnameChanged(t *testing.T) {
	old := &common.CommonDevice{}
	old.System.Hostname = "old-firewall"

	newCfg := &common.CommonDevice{}
	newCfg.System.Hostname = "new-firewall"

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Modified)

	// Find the hostname change
	var found bool
	for _, change := range result.Changes {
		if change.Path == "system.hostname" {
			found = true
			assert.Equal(t, ChangeModified, change.Type)
			assert.Equal(t, "old-firewall", change.OldValue)
			assert.Equal(t, "new-firewall", change.NewValue)
		}
	}
	assert.True(t, found, "hostname change not found")
}

func TestEngine_Compare_SectionFiltering(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1"},
		},
	}
	old.System.Hostname = "old-firewall"

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.2"},
		},
	}
	newCfg.System.Hostname = "new-firewall"

	// Only compare system section
	engine := NewEngine(old, newCfg, Options{Sections: []string{"system"}}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())

	// Should only have system changes, not interface changes
	for _, change := range result.Changes {
		assert.Equal(t, SectionSystem, change.Section)
	}
}

func TestEngine_Compare_ContextCancellation(t *testing.T) {
	old := &common.CommonDevice{}
	newCfg := &common.CommonDevice{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	engine := NewEngine(old, newCfg, Options{}, nil)
	_, err := engine.Compare(ctx)

	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestEngine_Compare_FirewallRuleAdded(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				UUID:        "test-uuid-1",
				Type:        common.RuleTypePass,
				Description: "Allow SSH",
				Protocol:    "tcp",
				Destination: common.RuleEndpoint{
					Port: "22",
				},
			},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Added)
}

func TestEngine_Compare_FirewallRuleRemoved(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{
				UUID:        "test-uuid-1",
				Type:        common.RuleTypePass,
				Description: "Legacy FTP",
				Protocol:    "tcp",
			},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Removed)
}

func TestEngine_Compare_InterfaceAdded(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1", Description: "WAN"},
			{Name: "opt1", IPAddress: "192.168.10.1", Description: "DMZ"},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Added)

	bySection := result.ChangesBySection()
	assert.Len(t, bySection[SectionInterfaces], 1)
	assert.Equal(t, ChangeAdded, bySection[SectionInterfaces][0].Type)
}

func TestEngine_Compare_InterfaceIPChanged(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.1", Subnet: "24", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "10.0.0.2", Subnet: "24", Description: "WAN"},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Modified)

	// Find the IP change
	var found bool
	for _, change := range result.Changes {
		if change.Path == testPathInterfacesWanIP {
			found = true
			assert.Equal(t, "10.0.0.1", change.OldValue)
			assert.Equal(t, "10.0.0.2", change.NewValue)
		}
	}
	assert.True(t, found, "interface IP change not found")
}

func TestEngine_Compare_EmptyConfigs(t *testing.T) {
	old := &common.CommonDevice{}
	newCfg := &common.CommonDevice{}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges())
	assert.NotNil(t, result.Metadata)
	assert.NotZero(t, result.Metadata.ComparedAt)
	assert.Equal(t, constants.Version, result.Metadata.ToolVersion)
}

func TestEngine_Compare_DetectOrder_ReorderedRules(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
			{UUID: "uuid-3", Type: common.RuleTypePass, Description: "Allow DNS", Protocol: "udp"},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-3", Type: common.RuleTypePass, Description: "Allow DNS", Protocol: "udp"},
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
		},
	}

	engine := NewEngine(old, newCfg, Options{DetectOrder: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Positive(t, result.Summary.Reordered, "should detect reordered rules")

	// Verify reorder changes have ChangeReordered type
	for _, c := range result.Changes {
		if c.Type == ChangeReordered {
			assert.Equal(t, SectionFirewall, c.Section)
			assert.Contains(t, c.Path, "filter.rule[uuid=")
		}
	}
}

func TestEngine_Compare_DetectOrder_Disabled(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
		},
	}

	// DetectOrder is false (default), so no reorder changes
	engine := NewEngine(old, newCfg, Options{DetectOrder: false}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, result.Summary.Reordered, "should not detect reorders when disabled")
}

func TestEngine_Compare_DetectOrder_ExcludesContentChanges(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTP", Protocol: "tcp"},
		},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			// uuid-2 moved to position 0 AND its description changed
			{UUID: "uuid-2", Type: common.RuleTypePass, Description: "Allow HTTPS", Protocol: "tcp"},
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow SSH", Protocol: "tcp"},
		},
	}

	engine := NewEngine(old, newCfg, Options{DetectOrder: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())

	// uuid-2 should appear as modified (content change), not also as reordered
	for _, c := range result.Changes {
		if c.Type == ChangeReordered && c.Path == "filter.rule[uuid=uuid-2]" {
			t.Error("uuid-2 should not appear as reordered when it also has content changes")
		}
	}
}

// TestEngine_Compare_DetectOrder_SharedUUID covers rules that share a uuid, as
// a rule and the copy OPNsense's migration assistant makes of it do until the
// operator removes the original. A reorder of the copies is reported; one
// identifier for both kept only the last place of each, so it was not.
func TestEngine_Compare_DetectOrder_SharedUUID(t *testing.T) {
	rule := func(uuid, description string) common.FirewallRule {
		return common.FirewallRule{UUID: uuid, Type: common.RuleTypePass, Description: description}
	}

	old := &common.CommonDevice{FirewallRules: []common.FirewallRule{
		rule("u1", "SSH"), rule("u2", "HTTP"), rule("u1", "SSH"), rule("u2", "HTTP"),
	}}
	newCfg := &common.CommonDevice{FirewallRules: []common.FirewallRule{
		rule("u2", "HTTP"), rule("u1", "SSH"), rule("u1", "SSH"), rule("u2", "HTTP"),
	}}

	result, err := NewEngine(old, newCfg, Options{DetectOrder: true}, nil).Compare(context.Background())
	require.NoError(t, err)

	var moved []string

	for _, c := range result.Changes {
		require.Equal(t, ChangeReordered, c.Type)
		moved = append(moved, c.Path)
	}

	assert.Equal(t, []string{"filter.rule[uuid=u1]", "filter.rule[uuid=u2]"}, moved)

	changesByPath := func(t *testing.T, oldRules, newRules []common.FirewallRule) map[string][]ChangeType {
		t.Helper()

		result, err := NewEngine(
			&common.CommonDevice{FirewallRules: oldRules},
			&common.CommonDevice{FirewallRules: newRules},
			Options{DetectOrder: true}, nil,
		).Compare(context.Background())
		require.NoError(t, err)

		got := make(map[string][]ChangeType)
		for _, c := range result.Changes {
			got[c.Path] = append(got[c.Path], c.Type)
		}

		return got
	}

	t.Run("a content change to one copy hides the moves of all of them", func(t *testing.T) {
		// Both u2 copies move, and the one edited is the second.
		got := changesByPath(t, old.FirewallRules, []common.FirewallRule{
			rule("u2", "HTTPS"), rule("u1", "SSH"), rule("u2", "HTTP"), rule("u1", "SSH"),
		})

		assert.Equal(t, map[string][]ChangeType{
			"filter.rule[uuid=u1]":        {ChangeReordered},
			"filter.rule[uuid=u1,copy=1]": {ChangeReordered},
			"filter.rule[uuid=u2]":        {ChangeModified},
		}, got)
	})

	t.Run("a second copy that moved is named by its count", func(t *testing.T) {
		got := changesByPath(t, old.FirewallRules, []common.FirewallRule{
			rule("u1", "SSH"), rule("u2", "HTTP"), rule("u2", "HTTPS"), rule("u1", "SSH"),
		})

		assert.Equal(t, map[string][]ChangeType{
			"filter.rule[uuid=u1,copy=1]": {ChangeReordered},
			"filter.rule[uuid=u2]":        {ChangeModified},
		}, got)
	})

	t.Run("copies that differ keep their names when they swap places", func(t *testing.T) {
		// The content diff pairs each copy with itself, so the swap shows only
		// here. Numbering the copies by place would give both sides the same
		// names and report nothing.
		got := changesByPath(t,
			[]common.FirewallRule{rule("u1", "SSH"), rule("u2", "HTTP"), rule("u1", "SSH, migrated")},
			[]common.FirewallRule{rule("u1", "SSH, migrated"), rule("u2", "HTTP"), rule("u1", "SSH")},
		)

		assert.Equal(t, map[string][]ChangeType{
			"filter.rule[uuid=u1]":        {ChangeReordered},
			"filter.rule[uuid=u1,copy=1]": {ChangeReordered},
		}, got)
	})
}

func TestEngine_Compare_Normalize_IPAddresses(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "010.000.001.001", Subnet: "24", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "010.000.001.002", Subnet: "24", Description: "WAN"},
		},
	}

	engine := NewEngine(old, newCfg, Options{Normalize: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())

	// Find the IP change - values should be normalized
	for _, c := range result.Changes {
		if c.Path == testPathInterfacesWanIP {
			assert.Equal(t, "10.0.1.1", c.OldValue, "old IP should be normalized")
			assert.Equal(t, "10.0.1.2", c.NewValue, "new IP should be normalized")
		}
	}
}

func TestEngine_Compare_Normalize_SkipsCosmeticDiffs(t *testing.T) {
	old := &common.CommonDevice{
		Interfaces: []common.Interface{
			{Name: "wan", IPAddress: "010.000.001.001", Subnet: "24", Description: "WAN"},
		},
	}

	newCfg := &common.CommonDevice{
		Interfaces: []common.Interface{
			// Same IP with different leading zeros - normalization makes them equal
			{Name: "wan", IPAddress: "10.0.1.1", Subnet: "24", Description: "WAN"},
		},
	}

	engine := NewEngine(old, newCfg, Options{Normalize: true}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)

	// The IP change should be skipped because normalized values are equal
	for _, c := range result.Changes {
		if c.Path == testPathInterfacesWanIP {
			t.Error("cosmetic IP difference should be skipped when normalize is enabled")
		}
	}
}

func TestEngine_Compare_RiskSummary_Populated(t *testing.T) {
	old := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{},
	}

	newCfg := &common.CommonDevice{
		FirewallRules: []common.FirewallRule{
			{UUID: "uuid-1", Type: common.RuleTypePass, Description: "Allow any", Protocol: "any"},
		},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	// Risk summary should be computed (score may vary based on patterns)
	assert.NotNil(t, result.RiskSummary)
}
