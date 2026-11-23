package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
)

// sysctlConfig is an OPNsense config holding the given <sysctl> block.
func sysctlConfig(sysctl string) string {
	return `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.org</domain>
  </system>
` + sysctl + `
</opnsense>
`
}

// sysctlItem is one tunable row as the 1.0.2 model writes it.
func sysctlItem(uuid, tunable, value string) string {
	return `    <item uuid="` + uuid + `">
      <tunable>` + tunable + `</tunable>
      ` + value + `
      <descr/>
    </item>
`
}

// TestSourceRouteAndSYNCookieControls_TunableDefaults_EndToEnd drives tunables
// through parse and convert to the three controls that read them. OPNsense
// applies its default to a tunable set to "default", from 25.1.3 on also to
// one whose value is empty, and from 25.1.4 on to one the config does not
// list. Before those releases the two leave the kernel's value, as the keyword does
// for the source-route tunables on 15.1 and 15.7, which list no default for
// them. The kernel's value agrees for these tunables, so all three controls
// pass on each shape. An explicit value still decides, and the later of two
// rows wins. A row naming a tunable with trailing whitespace, which OPNsense
// 16.7 to 20.1 apply and later releases skip, leaves that tunable read as
// written: unknown with no exact row, and not the value a control asks for
// when the exact row holds the keyword or is empty.
func TestSourceRouteAndSYNCookieControls_TunableDefaults_EndToEnd(t *testing.T) {
	t.Parallel()

	const (
		sr  = "net.inet.ip.sourceroute"
		asr = "net.inet.ip.accept_sourceroute"
		sc  = "net.inet.tcp.syncookies"
	)

	block := func(items ...string) string {
		return `  <sysctl version="1.0.2">
` + strings.Join(items, "") + `  </sysctl>`
	}

	tests := []struct {
		name        string
		sysctl      string
		wantFail    []string
		wantUnknown []string
	}{
		{
			name: "empty and keyword values",
			sysctl: block(
				sysctlItem("a1", asr, "<value>default</value>"),
				sysctlItem("a2", sr, "<value/>"),
				sysctlItem("a3", sc, "<value></value>"),
			),
		},
		{
			name: "no sysctl element",
		},
		{
			name: "explicit non-default values",
			sysctl: block(
				sysctlItem("b1", asr, "<value>default</value>"),
				sysctlItem("b2", sr, "<value>1</value>"),
				sysctlItem("b3", sc, "<value>0</value>"),
			),
			wantFail: []string{"FIREWALL-033", "FIREWALL-034", "SANS-FW-013"},
		},
		{
			name: "later row wins",
			sysctl: block(
				sysctlItem("c1", sr, "<value>0</value>"),
				sysctlItem("c2", sr, "<value>1</value>"),
				sysctlItem("c3", sc, "<value>1</value>"),
				sysctlItem("c4", sc, "<value>0</value>"),
			),
			wantFail: []string{"FIREWALL-033", "FIREWALL-034", "SANS-FW-013"},
		},
		{
			name: "trailing-space name with no exact row",
			sysctl: block(
				sysctlItem("d1", asr, "<value>default</value>"),
				sysctlItem("d2", sr+" ", "<value>1</value>"),
				sysctlItem("d3", sc, "<value>default</value>"),
			),
			wantFail:    []string{"SANS-FW-013"},
			wantUnknown: []string{"FIREWALL-033"},
		},
		{
			name: "keyword and empty rows with trailing-padded twins",
			sysctl: block(
				sysctlItem("e1", asr, "<value>default</value>"),
				sysctlItem("e2", sr, "<value>default</value>"),
				sysctlItem("e3", sr+" ", "<value>1</value>"),
				sysctlItem("e4", sc, "<value/>"),
				sysctlItem("e5", sc+"\t", "<value>0</value>"),
			),
			wantFail: []string{"FIREWALL-033", "FIREWALL-034", "SANS-FW-013"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseConfig(t, sysctlConfig(tt.sysctl))

			fwFindings, fwEvaluated, err := firewall.NewPlugin().RunChecks(device)
			if err != nil {
				t.Fatal(err)
			}

			sansFindings, sansEvaluated, err := sans.NewPlugin().RunChecks(device)
			if err != nil {
				t.Fatal(err)
			}

			findings := slices.Concat(fwFindings, sansFindings)
			evaluated := slices.Concat(fwEvaluated, sansEvaluated)

			for _, control := range []string{"FIREWALL-033", "FIREWALL-034", "SANS-FW-013"} {
				wantEvaluated := !slices.Contains(tt.wantUnknown, control)
				if got := slices.Contains(evaluated, control); got != wantEvaluated {
					t.Errorf("%s evaluated = %v, want %v", control, got, wantEvaluated)
				}

				failed := slices.ContainsFunc(findings, func(finding compliance.Finding) bool {
					return finding.Reference == control
				})
				if want := slices.Contains(tt.wantFail, control); failed != want {
					t.Errorf("%s failed = %v, want %v", control, failed, want)
				}
			}
		})
	}
}
