package firewall_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFirewallPlugin_LogRetention_UnknownOnPfSense keeps FIREWALL-042 from
// failing on pfSense, whose converter does not read syslog settings yet, while
// an OPNsense device with no retention still fails it.
func TestFirewallPlugin_LogRetention_UnknownOnPfSense(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		deviceType    common.DeviceType
		wantEvaluated bool
		wantFinding   bool
	}{
		{name: "pfSense reports unknown", deviceType: common.DeviceTypePfSense},
		{
			name:          "OPNsense without retention fails",
			deviceType:    common.DeviceTypeOPNsense,
			wantEvaluated: true,
			wantFinding:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, evaluated, err := firewall.NewPlugin().RunChecks(&common.CommonDevice{DeviceType: tt.deviceType})
			require.NoError(t, err)

			assert.Equal(t, tt.wantEvaluated, slices.Contains(evaluated, "FIREWALL-042"))
			found := false
			for _, f := range findings {
				if slices.Contains(f.References, "FIREWALL-042") {
					found = true
				}
			}
			assert.Equal(t, tt.wantFinding, found)
		})
	}
}
