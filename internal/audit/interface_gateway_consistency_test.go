package audit

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
)

// TestDetectConsistency_InterfaceGatewayByName drives sample.config.2.xml,
// whose wan selects its gateway by name as OPNsense stores it, through the
// parser and the consistency check. The shipped shape is not a finding; a name
// no gateway defines, and a name defined only on another interface, are.
func TestDetectConsistency_InterfaceGatewayByName(t *testing.T) {
	t.Parallel()

	const (
		selection = "<gateway>WAN_GW</gateway>"
		item      = "<interface>wan</interface>\n      <gateway>192.0.2.1</gateway>"
	)

	raw := readFixture(t, "sample.config.2.xml")
	requireFixtureHolds(t, raw, map[string]int{selection: 1, item: 1})

	tests := []struct {
		name   string
		config string
		want   []string
	}{
		{name: "selects a gateway on the interface", config: raw},
		{
			name:   "selects a name no gateway defines",
			config: strings.Replace(raw, selection, "<gateway>GONE_GW</gateway>", 1),
			want:   []string{"Undefined Interface Gateway"},
		},
		{
			name:   "selects a gateway defined on another interface",
			config: strings.Replace(raw, item, "<interface>lan</interface>\n      <gateway>192.0.2.1</gateway>", 1),
			want:   []string{"Interface Gateway on Another Interface"},
		},
		{
			name:   "selects an address",
			config: strings.Replace(raw, selection, "<gateway>192.0.2.1</gateway>", 1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []string

			for _, finding := range analysis.DetectConsistency(parseConfig(t, tt.config)) {
				if finding.Component == "interfaces.wan.gateway" {
					got = append(got, finding.Issue)
				}
			}

			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("wan gateway findings = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDetectConsistency_InterfaceGatewayPfSense drives pfSense's 2.7 fixture
// with lan rewritten to select GW_WAN, which the fixture defines on wan.
// pfSense resolves the name among every gateway, so that is not a fault there;
// a name no gateway defines still is.
func TestDetectConsistency_InterfaceGatewayPfSense(t *testing.T) {
	t.Parallel()

	const lan = "<ipaddr>10.0.0.1</ipaddr>\n      <subnet>24</subnet>\n    </lan>"

	raw := readFixture(t, "pfsense/config-2.7.x.xml")
	requireFixtureHolds(t, raw, map[string]int{lan: 1, "<name>GW_WAN</name>": 1})

	selecting := func(gateway string) string {
		return strings.Replace(raw, lan,
			"<ipaddr>10.0.0.1</ipaddr>\n      <subnet>24</subnet>\n      <gateway>"+gateway+"</gateway>\n    </lan>", 1)
	}

	for _, tt := range []struct {
		name   string
		config string
		want   []string
	}{
		{name: "selects a gateway defined on another interface", config: selecting("GW_WAN")},
		{name: "selects a name no gateway defines", config: selecting("GONE_GW"), want: []string{"Undefined Interface Gateway"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []string

			for _, finding := range analysis.DetectConsistency(parseConfig(t, tt.config)) {
				if finding.Component == "interfaces.lan.gateway" {
					got = append(got, finding.Issue)
				}
			}

			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("lan gateway findings = %q, want %q", got, tt.want)
			}
		})
	}
}
