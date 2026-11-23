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
				assert.Equal(t, tt.want, controlVerdict(findings, evaluated, control), control)
			}
		})
	}
}

// controlVerdict reads one control's verdict from RunChecks: "unknown" when it
// was not evaluated, "fail" when it has a finding, and "pass" otherwise.
func controlVerdict(findings []compliance.Finding, evaluated []string, control string) string {
	if !slices.Contains(evaluated, control) {
		return "unknown"
	}

	if slices.ContainsFunc(findings, func(f compliance.Finding) bool { return f.Reference == control }) {
		return "fail"
	}

	return "pass"
}

// TestFirewallPlugin_SysctlControls_PaddedRowsReadAsBefore pins FIREWALL-033
// and FIREWALL-034 on OPNsense when a padded row names their tunable. OPNsense
// 16.7 to 20.1 apply that row and later releases skip it, so the value in
// effect depends on the release, and both checks read the tunable as they did
// before tunables were resolved: the first row naming it exactly, as written,
// and unknown with no such row. A tunable without a padded row keeps the
// resolved reading.
func TestFirewallPlugin_SysctlControls_PaddedRowsReadAsBefore(t *testing.T) {
	t.Parallel()

	const (
		sr   = "net.inet.ip.sourceroute"
		sc   = "net.inet.tcp.syncookies"
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
		name    string
		sysctl  []common.SysctlItem
		want033 string
		want034 string
	}{
		// 16.7 to 20.1 apply the exact name where its first row stands, with
		// its last value, and then the padded name, so they run 1; 20.7 and
		// later run 0.
		{"padded row between two exact rows", rows(sr, "1", sr+" ", "1", sr, "0", sc, "1"), fail, pass},
		{"exact 1 then padded 0", rows(sr, "1", sr+" ", "0", sc, "1"), fail, pass},
		{"exact 0 then padded 1", rows(sr, "0", sr+".", "1", sc, "1"), pass, pass},
		{"keyword then padded 1", rows(sr, "default", sr+" ", "1", sc, "default"), fail, pass},
		{"empty then padded 0", rows(sr, "", sr+"\t", "0", sc, ""), fail, pass},
		{"padded row only", rows(sr+" ", "0", sc, "1"), unk, pass},
		{"syncookies empty then padded 0", rows(sc, "", sc+"\t", "0", sr, "0"), pass, fail},
		{"syncookies exact 1 then padded 0", rows(sc, "1", sc+". ", "0", sr, "0"), pass, pass},
		{"syncookies keyword then padded 1", rows(sc, "default", sc+" ", "1", sr, "0"), pass, fail},
		{"syncookies padded row only", rows(sc+".", "1", sr, "0"), pass, unk},
		{
			"first exact row decides both",
			rows(sr, "0", sr+" ", "1", sr, "1", sc, "0", sc+" ", "1", sc, "1"),
			pass, fail,
		},
	}

	fp := firewall.NewPlugin()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{DeviceType: common.DeviceTypeOPNsense, Sysctl: tt.sysctl}
			findings, evaluated, err := fp.RunChecks(device)
			require.NoError(t, err)

			assert.Equal(t, tt.want033, controlVerdict(findings, evaluated, "FIREWALL-033"), "FIREWALL-033")
			assert.Equal(t, tt.want034, controlVerdict(findings, evaluated, "FIREWALL-034"), "FIREWALL-034")
		})
	}
}
