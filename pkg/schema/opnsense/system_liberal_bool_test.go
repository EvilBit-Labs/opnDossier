package opnsense_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// TestIssue558_LiberalBooleanParsing is the regression test for
// https://github.com/EvilBit-Labs/opnDossier/issues/558 where OPNsense 26.1
// emitted <dnsallowoverride>on</dnsallowoverride> into a schema field
// previously typed as Go int, causing strconv.ParseInt to abort the whole
// parse. After migrating toggle-int fields to BoolFlag with liberal-body
// parsing via shared.IsValueTrue, the scenario parses cleanly.
func TestIssue558_LiberalBooleanParsing(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/system_liberal_bool.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	p := cfgparser.NewXMLParser()
	doc, err := p.Parse(context.Background(), bytesReader(data))
	if err != nil {
		t.Fatalf("parse failed: %v\n\n#558 regression: OPNsense 26.1 config with "+
			"'on' in a toggle field should parse without error, but got: %v", err, err)
	}

	// Truthy string values → true.
	if !bool(doc.System.DNSAllowOverride) {
		t.Errorf("DNSAllowOverride: want true (body=on), got false")
	}
	if !bool(doc.System.UseVirtualTerminal) {
		t.Errorf("UseVirtualTerminal: want true (body=yes), got false")
	}
	if !bool(doc.System.DisableVLANHWFilter) {
		t.Errorf("DisableVLANHWFilter: want true (body=1), got false")
	}
	if !bool(doc.System.DisableChecksumOffloading) {
		t.Errorf("DisableChecksumOffloading: want true (body=true), got false")
	}
	if !bool(doc.System.DisableSegmentationOffloading) {
		t.Errorf("DisableSegmentationOffloading: want true (body=ENABLED, case-insensitive), got false")
	}

	// Falsy string values → false.
	if bool(doc.System.PfShareForward) {
		t.Errorf("PfShareForward: want false (body=0), got true")
	}
	if bool(doc.System.LbUseSticky) {
		t.Errorf("LbUseSticky: want false (body=off), got true")
	}
	if bool(doc.System.RrdBackup) {
		t.Errorf("RrdBackup: want false (body=no), got true")
	}

	// Absent field → false (Go zero value).
	if bool(doc.System.NetflowBackup) {
		t.Errorf("NetflowBackup: want false (absent), got true")
	}
}
