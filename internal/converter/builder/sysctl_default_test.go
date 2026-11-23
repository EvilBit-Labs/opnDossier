package builder

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestBuildSysctlTableSet_EmptyValueShowsDefault covers a tunable left at its
// default: OPNsense 25.1.3 and later store it with an empty value, earlier
// releases with the keyword, and the report shows both as "default".
func TestBuildSysctlTableSet_EmptyValueShowsDefault(t *testing.T) {
	t.Parallel()

	tableSet := BuildSysctlTableSet([]common.SysctlItem{
		{Tunable: "net.inet.tcp.syncookies", Value: "0", Description: "SYN cookies"},
		{Tunable: "net.inet.ip.sourceroute", Value: "", Description: "Source routing"},
		{Tunable: "net.inet.ip.accept_sourceroute", Value: "default", Description: "Accept source routes"},
	})

	want := []string{"0", "default", "default"}
	if len(tableSet.Rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(tableSet.Rows), len(want))
	}

	for i, row := range tableSet.Rows {
		if row[1] != want[i] {
			t.Errorf("row %d (%s) value = %q, want %q", i, row[0], row[1], want[i])
		}
	}
}
