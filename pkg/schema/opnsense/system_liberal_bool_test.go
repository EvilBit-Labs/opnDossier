package opnsense_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
)

// TestSystem_LiberalBoolean_Issue558 is the regression test for
// https://github.com/EvilBit-Labs/opnDossier/issues/558 where OPNsense 26.1
// emitted <dnsallowoverride>on</dnsallowoverride> into a schema field
// previously typed as Go int, causing strconv.ParseInt to abort the whole
// parse. After migrating toggle-int fields to BoolFlag with liberal-body
// parsing via shared.IsValueTrue, the scenario parses cleanly.
func TestSystem_LiberalBoolean_Issue558(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/system_liberal_bool.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	doc, err := cfgparser.NewXMLParser().Parse(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("#558 regression: OPNsense config with 'on' in a toggle "+
			"field should parse without error, got: %v", err)
	}

	cases := []struct {
		name  string
		field func() bool
		want  bool
		body  string
	}{
		// Truthy string values → true.
		{"DNSAllowOverride", func() bool { return bool(doc.System.DNSAllowOverride) }, true, "on"},
		{"UseVirtualTerminal", func() bool { return bool(doc.System.UseVirtualTerminal) }, true, "yes"},
		{"DisableVLANHWFilter", func() bool { return bool(doc.System.DisableVLANHWFilter) }, true, "1"},
		{"DisableChecksumOffloading", func() bool { return bool(doc.System.DisableChecksumOffloading) }, true, "true"},
		{
			"DisableSegmentationOffloading",
			func() bool { return bool(doc.System.DisableSegmentationOffloading) },
			true,
			"ENABLED (case-insensitive)",
		},
		// Falsy string values → false.
		{"PfShareForward", func() bool { return bool(doc.System.PfShareForward) }, false, "0"},
		{"LbUseSticky", func() bool { return bool(doc.System.LbUseSticky) }, false, "off"},
		{"RrdBackup", func() bool { return bool(doc.System.RrdBackup) }, false, "no"},
		// Absent element → false (Go zero value).
		{"NetflowBackup", func() bool { return bool(doc.System.NetflowBackup) }, false, "absent"},
	}

	for _, tc := range cases {
		if got := tc.field(); got != tc.want {
			t.Errorf("%s: want %v (body=%q), got %v", tc.name, tc.want, tc.body, got)
		}
	}

	// Belt-and-suspenders: the schema must still be addressable as a pointer
	// so future changes don't silently regress the migrated field types.
	_ = &doc.System
}
