package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// sysctlRows builds tunable rows from name, value pairs.
func sysctlRows(pairs ...string) []common.SysctlItem {
	rows := make([]common.SysctlItem, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		rows = append(rows, common.SysctlItem{Tunable: pairs[i], Value: pairs[i+1]})
	}

	return rows
}

func TestEffectiveSysctl(t *testing.T) {
	t.Parallel()

	const (
		sr  = "net.inet.ip.sourceroute"
		asr = "net.inet.ip.accept_sourceroute"
		sc  = "net.inet.tcp.syncookies"
		tb  = "net.inet.tcp.blackhole"
		ub  = "net.inet.udp.blackhole"
		fwd = "net.inet.ip.forwarding"
		kw  = "default"
	)

	opn := common.DeviceTypeOPNsense
	pf := common.DeviceTypePfSense
	unk := common.DeviceTypeUnknown
	r := sysctlRows

	tests := []struct {
		name      string
		device    common.DeviceType
		rows      []common.SysctlItem
		tunable   string
		wantValue string
		wantKnown bool
	}{
		// An explicit value is that value on every device.
		{"opnsense explicit 0", opn, r(sr, "0"), sr, "0", true},
		{"opnsense explicit 1", opn, r(sr, "1"), sr, "1", true},
		{"pfsense explicit 1", pf, r(sr, "1"), sr, "1", true},
		{"unknown device explicit 0", unk, r(sc, "0"), sc, "0", true},

		// OPNsense: the keyword, an empty value and a missing row all select
		// the default, which matches the kernel's for these three tunables.
		{"opnsense keyword sourceroute", opn, r(sr, kw), sr, "0", true},
		{"opnsense empty sourceroute", opn, r(sr, ""), sr, "0", true},
		{"opnsense absent sourceroute", opn, nil, sr, "0", true},
		{"opnsense keyword accept_sourceroute", opn, r(asr, kw), asr, "0", true},
		{"opnsense empty accept_sourceroute", opn, r(asr, ""), asr, "0", true},
		{"opnsense absent accept_sourceroute", opn, r(sr, "1"), asr, "0", true},
		{"opnsense keyword syncookies", opn, r(sc, kw), sc, "1", true},
		{"opnsense empty syncookies", opn, r(sc, ""), sc, "1", true},
		{"opnsense absent syncookies", opn, nil, sc, "1", true},

		// Blackhole: the keyword resolves in every release, while an empty
		// value or a missing row depends on the release.
		{"opnsense keyword tcp blackhole", opn, r(tb, kw), tb, "2", true},
		{"opnsense keyword udp blackhole", opn, r(ub, kw), ub, "1", true},
		{"opnsense empty tcp blackhole", opn, r(tb, ""), tb, "", false},
		{"opnsense empty udp blackhole", opn, r(ub, ""), ub, "", false},
		{"opnsense absent tcp blackhole", opn, nil, tb, "", false},
		{"opnsense explicit tcp blackhole", opn, r(tb, "0"), tb, "0", true},

		// A tunable outside the table is unknown unless it holds a value.
		{"opnsense keyword forwarding", opn, r(fwd, kw), fwd, "", false},
		{"opnsense empty forwarding", opn, r(fwd, ""), fwd, "", false},
		{"opnsense absent forwarding", opn, nil, fwd, "", false},
		{"opnsense explicit forwarding", opn, r(fwd, "0"), fwd, "0", true},

		// Any other device reads a row as written; a missing row is unknown.
		{"pfsense keyword read as written", pf, r(sc, kw), sc, kw, true},
		{"pfsense empty read as written", pf, r(sr, ""), sr, "", true},
		{"pfsense absent", pf, nil, sr, "", false},
		{"unknown device keyword read as written", unk, r(sr, kw), sr, kw, true},
		{"unknown device empty read as written", unk, r(sc, ""), sc, "", true},
		{"unknown device absent", unk, nil, sc, "", false},

		// The last row naming a tunable wins.
		{"opnsense later explicit wins", opn, r(sr, "0", sr, "1"), sr, "1", true},
		{"opnsense later keyword wins", opn, r(sr, "1", sr, kw), sr, "0", true},
		{"opnsense later empty wins", opn, r(sc, "0", sc, ""), sc, "1", true},
		{"unknown device later row wins", unk, r(sc, "1", sc, "0"), sc, "0", true},
		{"pfsense later empty wins", pf, r(sr, "0", sr, ""), sr, "", true},

		// A name with leading whitespace or in upper case is another tunable:
		// the firewall keys rows by name as written, and the kernel matches each
		// component exactly, accepting only one trailing dot (below). A value
		// other than the exact keyword is read as written.
		{"opnsense padded name is another tunable", opn, r(" "+sr, "1"), sr, "0", true},
		{"opnsense padded on both sides is another tunable", opn, r(" "+sr+" ", "1"), sr, "0", true},
		{"opnsense upper-case name is another tunable", opn, r("NET.INET.IP.SOURCEROUTE", "1"), sr, "0", true},
		{"opnsense upper-case padded name is another tunable", opn, r("NET.INET.IP.SOURCEROUTE ", "1"), sr, "0", true},
		{"opnsense upper-case keyword read as written", opn, r(sc, "DEFAULT"), sc, "DEFAULT", true},
		{"opnsense padded keyword read as written", opn, r(sc, " default"), sc, " default", true},

		// On OPNsense a padded row (TestSysctlNamePadded) makes the value
		// depend on the release, so the tunable is unknown here and each
		// control falls back to the reading it had before. A padded row of
		// another tunable changes nothing.
		{"opnsense trailing space, no exact row", opn, r(sr+" ", "1"), sr, "", false},
		{"opnsense trailing tab, no exact row", opn, r(sc+"\t", "0"), sc, "", false},
		{"opnsense trailing newline, no exact row", opn, r(asr+"\n", "1"), asr, "", false},
		{"opnsense keyword then trailing-space row", opn, r(sr, kw, sr+" ", "1"), sr, "", false},
		{"opnsense empty then trailing-space row", opn, r(sc, "", sc+" ", "0"), sc, "", false},
		{"opnsense trailing-space row then keyword", opn, r(sr+"\r", "1", sr, kw), sr, "", false},
		{"opnsense blackhole keyword with trailing-space row", opn, r(tb, kw, tb+" ", "0"), tb, "", false},
		{"opnsense exact value then trailing-space row", opn, r(sr, "1", sr+" ", "0"), sr, "", false},
		{"opnsense exact and padded rows agreeing", opn, r(sr, "0", sr+" ", "0"), sr, "", false},
		{"opnsense padded row between two exact rows", opn, r(sr, "1", sr+" ", "1", sr, "0"), sr, "", false},
		{"opnsense trailing-space row of another tunable", opn, r(sc+" ", "0"), sr, "0", true},
		{"opnsense trailing dot, no exact row", opn, r(sr+".", "1"), sr, "", false},
		{"opnsense keyword then trailing-dot row", opn, r(sr, kw, sr+".", "1"), sr, "", false},
		{"opnsense two trailing dots is another tunable", opn, r(sr+"..", "1"), sr, "0", true},
		{"opnsense space then dot is another tunable", opn, r(sr+" .", "1"), sr, "0", true},
		// Any other device ignores a padded row and reads the last exact row as
		// written.
		{"pfsense trailing-space row", pf, r(sr+" ", "1"), sr, "", false},
		{"pfsense keyword with trailing-space row", pf, r(sc, kw, sc+" ", "0"), sc, kw, true},
		{"pfsense padded row between two exact rows", pf, r(sr, "1", sr+" ", "1", sr, "0"), sr, "0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{DeviceType: tt.device, Sysctl: tt.rows}
			value, known := analysis.EffectiveSysctl(device, tt.tunable)
			assert.Equal(t, tt.wantKnown, known, "known")
			assert.Equal(t, tt.wantValue, value, "value")
		})
	}
}

func TestEffectiveSysctl_NilDevice(t *testing.T) {
	t.Parallel()

	value, known := analysis.EffectiveSysctl(nil, "net.inet.ip.sourceroute")
	assert.False(t, known)
	assert.Empty(t, value)
}

// TestSysctlNamePadded pins which rows count as padded. FreeBSD's sysctl drops
// trailing whitespace from a name and the kernel then accepts one trailing
// dot, so OPNsense 16.7 to 20.1 apply such a row to the tunable. Leading
// whitespace, a second dot, a dot after a space and upper case name another
// tunable. Off OPNsense rows are read as written, so nothing is padded.
func TestSysctlNamePadded(t *testing.T) {
	t.Parallel()

	const sr = "net.inet.ip.sourceroute"

	opn := common.DeviceTypeOPNsense
	r := sysctlRows

	tests := []struct {
		name   string
		device common.DeviceType
		rows   []common.SysctlItem
		want   bool
	}{
		{"trailing space", opn, r(sr+" ", "0"), true},
		{"trailing tab", opn, r(sr+"\t", "0"), true},
		{"trailing newline", opn, r(sr+"\n", "0"), true},
		{"trailing carriage return", opn, r(sr+"\r", "0"), true},
		{"trailing vertical tab and form feed", opn, r(sr+"\v\f", "0"), true},
		{"trailing dot", opn, r(sr+".", "0"), true},
		{"trailing dot then spaces", opn, r(sr+".  ", "0"), true},
		{"padded row beside an exact row", opn, r(sr, "1", sr+" ", "1"), true},
		{"exact row only", opn, r(sr, "1"), false},
		{"no rows", opn, nil, false},
		{"leading space", opn, r(" "+sr, "0"), false},
		{"two trailing dots", opn, r(sr+"..", "0"), false},
		{"space then dot", opn, r(sr+" .", "0"), false},
		{"upper case", opn, r("NET.INET.IP.SOURCEROUTE ", "0"), false},
		{"another tunable padded", opn, r("net.inet.ip.accept_sourceroute ", "0"), false},
		{"pfsense trailing space", common.DeviceTypePfSense, r(sr+" ", "0"), false},
		{"unknown device trailing space", common.DeviceTypeUnknown, r(sr+" ", "0"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{DeviceType: tt.device, Sysctl: tt.rows}
			assert.Equal(t, tt.want, analysis.SysctlNamePadded(device, sr))
		})
	}

	assert.False(t, analysis.SysctlNamePadded(nil, sr), "nil device")
}
