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

		// Trailing whitespace is dropped by FreeBSD's sysctl, so OPNsense 16.7
		// to 20.1 apply that row as well, and from 20.7 OPNsense skips it. The
		// value then depends on the release: the tunable is read as written,
		// and an exact row with a value still decides.
		{"opnsense trailing space, no exact row", opn, r(sr+" ", "1"), sr, "", false},
		{"opnsense trailing tab, no exact row", opn, r(sc+"\t", "0"), sc, "", false},
		{"opnsense trailing newline, no exact row", opn, r(asr+"\n", "1"), asr, "", false},
		{"opnsense keyword then trailing-space row", opn, r(sr, kw, sr+" ", "1"), sr, kw, true},
		{"opnsense empty then trailing-space row", opn, r(sc, "", sc+" ", "0"), sc, "", true},
		{"opnsense trailing-space row then keyword", opn, r(sr+"\r", "1", sr, kw), sr, kw, true},
		{"opnsense blackhole keyword with trailing-space row", opn, r(tb, kw, tb+" ", "0"), tb, kw, true},
		{"opnsense exact value then trailing-space row", opn, r(sr, "1", sr+" ", "0"), sr, "1", true},
		{"opnsense trailing-space row of another tunable", opn, r(sc+" ", "0"), sr, "0", true},
		// The kernel also accepts one trailing dot after sysctl has dropped the
		// whitespace (sys/kern/kern_sysctl.c name2oid), so such a row stops the
		// resolution the same way. Two dots, or a dot after a space, name no
		// tunable.
		{"opnsense trailing dot, no exact row", opn, r(sr+".", "1"), sr, "", false},
		{"opnsense trailing dot then space, no exact row", opn, r(sc+". ", "0"), sc, "", false},
		{"opnsense keyword then trailing-dot row", opn, r(sr, kw, sr+".", "1"), sr, kw, true},
		{"opnsense two trailing dots is another tunable", opn, r(sr+"..", "1"), sr, "0", true},
		{"opnsense space then dot is another tunable", opn, r(sr+" .", "1"), sr, "0", true},
		{"pfsense trailing-space row", pf, r(sr+" ", "1"), sr, "", false},
		{"pfsense keyword with trailing-space row", pf, r(sc, kw, sc+" ", "0"), sc, kw, true},
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
