package diff

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEngine(t *testing.T) {
	old := schema.NewOpnSenseDocument()
	newCfg := schema.NewOpnSenseDocument()
	opts := Options{}

	engine := NewEngine(old, newCfg, opts, nil)

	require.NotNil(t, engine)
	assert.Equal(t, old, engine.oldConfig)
	assert.Equal(t, newCfg, engine.newConfig)
	assert.NotNil(t, engine.analyzer)
}

func TestEngine_Compare_IdenticalConfigs(t *testing.T) {
	old := schema.NewOpnSenseDocument()
	old.System.Hostname = "firewall"
	old.System.Domain = "example.com"

	newCfg := schema.NewOpnSenseDocument()
	newCfg.System.Hostname = "firewall"
	newCfg.System.Domain = "example.com"

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges())
	assert.Equal(t, 0, result.Summary.Total)
}

func TestEngine_Compare_HostnameChanged(t *testing.T) {
	old := schema.NewOpnSenseDocument()
	old.System.Hostname = "old-firewall"

	newCfg := schema.NewOpnSenseDocument()
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
	old := schema.NewOpnSenseDocument()
	old.System.Hostname = "old-firewall"
	old.Interfaces.Items = map[string]schema.Interface{
		"wan": {IPAddr: "10.0.0.1"},
	}

	newCfg := schema.NewOpnSenseDocument()
	newCfg.System.Hostname = "new-firewall"
	newCfg.Interfaces.Items = map[string]schema.Interface{
		"wan": {IPAddr: "10.0.0.2"},
	}

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
	old := schema.NewOpnSenseDocument()
	newCfg := schema.NewOpnSenseDocument()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	engine := NewEngine(old, newCfg, Options{}, nil)
	_, err := engine.Compare(ctx)

	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestEngine_Compare_FirewallRuleAdded(t *testing.T) {
	old := schema.NewOpnSenseDocument()
	old.Filter.Rule = []schema.Rule{}

	newCfg := schema.NewOpnSenseDocument()
	newCfg.Filter.Rule = []schema.Rule{
		{
			UUID:     "test-uuid-1",
			Type:     "pass",
			Descr:    "Allow SSH",
			Protocol: "tcp",
			Destination: schema.Destination{
				Port: "22",
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
	old := schema.NewOpnSenseDocument()
	old.Filter.Rule = []schema.Rule{
		{
			UUID:     "test-uuid-1",
			Type:     "pass",
			Descr:    "Legacy FTP",
			Protocol: "tcp",
		},
	}

	newCfg := schema.NewOpnSenseDocument()
	newCfg.Filter.Rule = []schema.Rule{}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Removed)
}

func TestEngine_Compare_InterfaceAdded(t *testing.T) {
	old := schema.NewOpnSenseDocument()
	old.Interfaces.Items = map[string]schema.Interface{
		"wan": {IPAddr: "10.0.0.1", Descr: "WAN"},
	}

	newCfg := schema.NewOpnSenseDocument()
	newCfg.Interfaces.Items = map[string]schema.Interface{
		"wan":  {IPAddr: "10.0.0.1", Descr: "WAN"},
		"opt1": {IPAddr: "192.168.10.1", Descr: "DMZ"},
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
	old := schema.NewOpnSenseDocument()
	old.Interfaces.Items = map[string]schema.Interface{
		"wan": {IPAddr: "10.0.0.1", Subnet: "24", Descr: "WAN"},
	}

	newCfg := schema.NewOpnSenseDocument()
	newCfg.Interfaces.Items = map[string]schema.Interface{
		"wan": {IPAddr: "10.0.0.2", Subnet: "24", Descr: "WAN"},
	}

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.True(t, result.HasChanges())
	assert.Equal(t, 1, result.Summary.Modified)

	// Find the IP change
	var found bool
	for _, change := range result.Changes {
		if change.Path == "interfaces.wan.ipaddr" {
			found = true
			assert.Equal(t, "10.0.0.1", change.OldValue)
			assert.Equal(t, "10.0.0.2", change.NewValue)
		}
	}
	assert.True(t, found, "interface IP change not found")
}

func TestEngine_Compare_EmptyConfigs(t *testing.T) {
	old := schema.NewOpnSenseDocument()
	newCfg := schema.NewOpnSenseDocument()

	engine := NewEngine(old, newCfg, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges())
	assert.NotNil(t, result.Metadata)
	assert.NotZero(t, result.Metadata.ComparedAt)
	assert.Equal(t, constants.Version, result.Metadata.ToolVersion)
}
