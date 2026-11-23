package sans_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSANSPlugin_SourceRouting covers SANS-FW-013. On OPNsense a tunable left
// at its default reads as the value in effect on the firewall, which is 0 for
// both source-route tunables in every release; on any other device a row is
// read as written and a missing row is unknown.
func TestSANSPlugin_SourceRouting(t *testing.T) {
	t.Parallel()

	const (
		sr   = "net.inet.ip.sourceroute"
		asr  = "net.inet.ip.accept_sourceroute"
		pass = "pass"
		fail = "fail"
		unk  = "unknown"
	)

	rows := func(pairs ...string) []common.SysctlItem {
		items := make([]common.SysctlItem, 0, len(pairs)/2)
		for i := 0; i+1 < len(pairs); i += 2 {
			items = append(items, common.SysctlItem{Tunable: pairs[i], Value: pairs[i+1]})
		}

		return items
	}

	tests := []struct {
		name   string
		device common.DeviceType
		sysctl []common.SysctlItem
		want   string
	}{
		{"unknown device without tunables", common.DeviceTypeUnknown, nil, unk},
		{"unknown device both 0", common.DeviceTypeUnknown, rows(asr, "0", sr, "0"), pass},
		{"unknown device one missing", common.DeviceTypeUnknown, rows(asr, "0"), fail},
		{"unknown device one set to 1", common.DeviceTypeUnknown, rows(asr, "0", sr, "1"), fail},
		{"unknown device keyword read as written", common.DeviceTypeUnknown, rows(asr, "0", sr, "default"), fail},
		{
			"unknown device keyword in asr read as written",
			common.DeviceTypeUnknown,
			rows(sr, "0", asr, "default"),
			fail,
		},
		{"pfsense without tunables", common.DeviceTypePfSense, nil, unk},
		{"opnsense without tunables", common.DeviceTypeOPNsense, nil, pass},
		{"opnsense keyword on both", common.DeviceTypeOPNsense, rows(asr, "default", sr, "default"), pass},
		{"opnsense empty on both", common.DeviceTypeOPNsense, rows(asr, "", sr, ""), pass},
		{"opnsense one listed", common.DeviceTypeOPNsense, rows(asr, "0"), pass},
		{"opnsense accept_sourceroute set to 1", common.DeviceTypeOPNsense, rows(sr, "default", asr, "1"), fail},
		{"opnsense sourceroute set to 1", common.DeviceTypeOPNsense, rows(asr, "", sr, "1"), fail},
		{"opnsense later row wins", common.DeviceTypeOPNsense, rows(sr, "0", sr, "1"), fail},
		{"opnsense later keyword wins", common.DeviceTypeOPNsense, rows(sr, "1", sr, "default"), pass},
	}

	plugin := sans.NewPlugin()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{DeviceType: tt.device, Sysctl: tt.sysctl}
			findings, evaluated, err := plugin.RunChecks(device)
			require.NoError(t, err)

			got := unk
			if slices.Contains(evaluated, "SANS-FW-013") {
				got = pass
				if slices.ContainsFunc(findings, func(f compliance.Finding) bool {
					return f.Reference == "SANS-FW-013"
				}) {
					got = fail
				}
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
