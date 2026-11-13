package diff

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestCompareSystem_ImplicitFilterSettings checks that turning packet filtering
// or the anti-lockout rule on or off is reported, with turning packet filtering
// off rated high. Both settings change what the firewall enforces without any
// rule changing, so a diff that misses them reads "No changes detected".
func TestCompareSystem_ImplicitFilterSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		old, newCfg  common.System
		path, impact string
		description  string
		oldV, newV   string
	}{
		{
			name:   "packet filtering disabled",
			newCfg: common.System{PacketFilterDisabled: true},
			path:   "system.disablefilter", impact: "high",
			description: "Packet filtering disabled", oldV: "false", newV: "true",
		},
		{
			name: "packet filtering enabled",
			old:  common.System{PacketFilterDisabled: true},
			path: "system.disablefilter", impact: "medium",
			description: "Packet filtering enabled", oldV: "true", newV: "false",
		},
		{
			name:   "anti-lockout disabled",
			newCfg: common.System{WebGUI: common.WebGUI{NoAntiLockout: true}},
			path:   "system.webgui.noantilockout", impact: "low",
			description: "Anti-lockout rule disabled", oldV: "false", newV: "true",
		},
		{
			name: "anti-lockout enabled",
			old:  common.System{WebGUI: common.WebGUI{NoAntiLockout: true}},
			path: "system.webgui.noantilockout", impact: "medium",
			description: "Anti-lockout rule enabled", oldV: "true", newV: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			changes := NewAnalyzer().CompareSystem(&tt.old, &tt.newCfg)
			if len(changes) != 1 {
				t.Fatalf("changes = %+v, want one", changes)
			}

			got := changes[0]
			if got.Path != tt.path || got.SecurityImpact != tt.impact || got.Description != tt.description ||
				got.OldValue != tt.oldV || got.NewValue != tt.newV {
				t.Errorf("change = %q %s at %s (%s -> %s), want %q %s at %s (%s -> %s)",
					got.Description, got.SecurityImpact, got.Path, got.OldValue, got.NewValue,
					tt.description, tt.impact, tt.path, tt.oldV, tt.newV)
			}
		})
	}

	same := common.System{PacketFilterDisabled: true, WebGUI: common.WebGUI{NoAntiLockout: true}}
	if changes := NewAnalyzer().CompareSystem(&same, &same); len(changes) != 0 {
		t.Errorf("unchanged settings reported: %+v", changes)
	}
}
