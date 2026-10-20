package diff

import (
	"context"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEngine_Compare_SecurityOnly_KeepsInterfaceEnableChange scores the path
// the analyzer emits, so a rename on either side fails here.
func TestEngine_Compare_SecurityOnly_KeepsInterfaceEnableChange(t *testing.T) {
	tests := []struct {
		name       string
		oldEnabled bool
		newEnabled bool
	}{
		{name: "disabled", oldEnabled: true, newEnabled: false},
		{name: "enabled", oldEnabled: false, newEnabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := &common.CommonDevice{
				Interfaces: []common.Interface{{Name: "wan", Enabled: tt.oldEnabled}},
			}
			newCfg := &common.CommonDevice{
				Interfaces: []common.Interface{{Name: "wan", Enabled: tt.newEnabled}},
			}

			engine := NewEngine(old, newCfg, Options{SecurityOnly: true}, nil)
			result, err := engine.Compare(context.Background())

			require.NoError(t, err)
			require.Len(t, result.Changes, 1)
			assert.Equal(t, "interfaces.wan.enabled", result.Changes[0].Path)
			assert.Equal(t, "medium", result.Changes[0].SecurityImpact)
			assert.Equal(t, 1, result.RiskSummary.Medium)
		})
	}
}
