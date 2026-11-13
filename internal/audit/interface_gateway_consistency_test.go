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
