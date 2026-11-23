package firewall_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFirewallPlugin_SysctlControls_Verdicts tells pass from unknown for
// FIREWALL-033 and FIREWALL-034, which assertFindingPresence cannot. A missing
// tunable resolves to OPNsense's default only on OPNsense; the pfSense converter
// does not read tunables, so there, and on a device of unknown type, a missing
// row means unread and must stay unknown rather than pass. Off OPNsense a row is
// read as written, so the keyword fails.
func TestFirewallPlugin_SysctlControls_Verdicts(t *testing.T) {
	t.Parallel()

	const (
		sr   = "net.inet.ip.sourceroute"
		sc   = "net.inet.tcp.syncookies"
		pass = "pass"
		fail = "fail"
		unk  = "unknown"
	)

	rows := func(srValue, scValue string) []common.SysctlItem {
		return []common.SysctlItem{{Tunable: sr, Value: srValue}, {Tunable: sc, Value: scValue}}
	}

	tests := []struct {
		name   string
		device common.DeviceType
		sysctl []common.SysctlItem
		want   string
	}{
		{"pfsense without tunables", common.DeviceTypePfSense, nil, unk},
		{"unknown device without tunables", common.DeviceTypeUnknown, nil, unk},
		{"unknown device keyword read as written", common.DeviceTypeUnknown, rows("default", "default"), fail},
		{"unknown device safe values", common.DeviceTypeUnknown, rows("0", "1"), pass},
		{"opnsense without tunables", common.DeviceTypeOPNsense, nil, pass},
		{"opnsense keyword", common.DeviceTypeOPNsense, rows("default", "default"), pass},
		{"opnsense unsafe values", common.DeviceTypeOPNsense, rows("1", "0"), fail},
	}

	fp := firewall.NewPlugin()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{DeviceType: tt.device, Sysctl: tt.sysctl}
			findings, evaluated, err := fp.RunChecks(device)
			require.NoError(t, err)

			for _, control := range []string{"FIREWALL-033", "FIREWALL-034"} {
				got := unk
				if slices.Contains(evaluated, control) {
					got = pass
					if slices.ContainsFunc(findings, func(f compliance.Finding) bool {
						return f.Reference == control
					}) {
						got = fail
					}
				}

				assert.Equal(t, tt.want, got, control)
			}
		})
	}
}
