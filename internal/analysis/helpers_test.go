package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindInterface(t *testing.T) {
	t.Parallel()

	interfaces := []common.Interface{
		{Name: "wan", Type: "ethernet", Enabled: true},
		{Name: "lan", Type: "ethernet", Enabled: true},
		{Name: "opt1", Type: "ethernet", Enabled: false},
	}

	tests := []struct {
		name       string
		interfaces []common.Interface
		search     string
		wantNil    bool
		wantName   string
	}{
		{
			name:       "found by name",
			interfaces: interfaces,
			search:     "lan",
			wantNil:    false,
			wantName:   "lan",
		},
		{
			name:       "not found",
			interfaces: interfaces,
			search:     "dmz",
			wantNil:    true,
		},
		{
			name:       "empty slice",
			interfaces: []common.Interface{},
			search:     "wan",
			wantNil:    true,
		},
		{
			name:       "first interface",
			interfaces: interfaces,
			search:     "wan",
			wantNil:    false,
			wantName:   "wan",
		},
		{
			name:       "last interface",
			interfaces: interfaces,
			search:     "opt1",
			wantNil:    false,
			wantName:   "opt1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analysis.FindInterface(tt.interfaces, tt.search)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantName, result.Name)
			}
		})
	}
}

func TestFindInterface_ReturnsPointerToOriginal(t *testing.T) {
	t.Parallel()

	interfaces := []common.Interface{
		{Name: "wan", Type: "ethernet"},
	}

	result := analysis.FindInterface(interfaces, "wan")
	require.NotNil(t, result)
	assert.Equal(t, &interfaces[0], result)
}

func TestFindDHCPScope(t *testing.T) {
	t.Parallel()

	scopes := []common.DHCPScope{
		{Interface: "lan", Enabled: true, Range: common.DHCPRange{From: "192.168.1.100", To: "192.168.1.200"}},
		{Interface: "opt1", Enabled: false},
		{Interface: "opt2", Enabled: true, Range: common.DHCPRange{From: "10.0.0.100", To: "10.0.0.200"}},
	}

	tests := []struct {
		name          string
		scopes        []common.DHCPScope
		ifaceName     string
		wantNil       bool
		wantInterface string
	}{
		{
			name:          "found by interface name",
			scopes:        scopes,
			ifaceName:     "lan",
			wantNil:       false,
			wantInterface: "lan",
		},
		{
			name:      "not found",
			scopes:    scopes,
			ifaceName: "dmz",
			wantNil:   true,
		},
		{
			name:      "empty slice",
			scopes:    []common.DHCPScope{},
			ifaceName: "lan",
			wantNil:   true,
		},
		{
			name:          "last scope",
			scopes:        scopes,
			ifaceName:     "opt2",
			wantNil:       false,
			wantInterface: "opt2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := analysis.FindDHCPScope(tt.scopes, tt.ifaceName)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantInterface, result.Interface)
			}
		})
	}
}

func TestIndexedRule(t *testing.T) {
	t.Parallel()

	rule := common.FirewallRule{
		Type:       "pass",
		Interfaces: []string{"wan"},
	}

	ir := analysis.IndexedRule{
		Index: 5,
		Rule:  rule,
	}

	assert.Equal(t, 5, ir.Index)
	assert.Equal(t, "pass", ir.Rule.Type)
	assert.Equal(t, []string{"wan"}, ir.Rule.Interfaces)
}
