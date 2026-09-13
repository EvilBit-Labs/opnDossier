package converter

import (
	"context"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// injectionMarker brackets each payload so a test failure points at the exact
// field that leaked, rather than at "some HTML appeared somewhere".
const injectionMarker = "OPNDOSSIERPROBE"

// injectionPayloads are the markup shapes a config value could carry into a
// report. Each is a real vector rather than a generic "bad string": an image
// with an error handler, an inline script, an event handler that needs no
// external fetch, and a markdown link with a javascript URL, which goldmark
// turns into a live anchor without any raw HTML being involved at all.
var injectionPayloads = []string{
	injectionMarker + `<img src=x onerror=alert(1)>`,
	injectionMarker + `<script>alert(2)</script>`,
	injectionMarker + `<div onmouseover="alert(3)">hover</div>`,
	injectionMarker + `[click](javascript:alert(4))`,
}

// forbiddenInHTML are substrings that must never appear in a generated HTML
// report, because each one means a config value was parsed as markup instead of
// text.
//
// Each entry includes the opening angle bracket or the attribute quoting, so it
// matches only real markup. Once escaping works the report contains
// "&lt;img src=x onerror=alert(1)&gt;" as visible text, and an event-handler
// substring on its own would match that harmless case too.
var forbiddenInHTML = []string{
	"<img src=x",
	"<script>",
	"<div onmouseover",
	`href="javascript:`,
}

// newInjectionTestDevice returns a device whose config-derived string fields all
// carry payload. The fields chosen are the ones that reach the report through
// the non-table paths (bullet lists and PlainTextf lines) plus a representative
// set of table cells, which is where the escaping gap lived.
func newInjectionTestDevice(payload string) *common.CommonDevice {
	return &common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		System: common.System{
			Hostname:     payload,
			Domain:       payload,
			Optimization: payload,
			Timezone:     payload,
			Language:     payload,
			TimeServers:  []string{payload},
			DNSServers:   []string{payload},
			WebGUI:       common.WebGUI{Protocol: payload},
			Firmware:     common.Firmware{Version: payload},
			SSH:          common.SSH{Group: payload},
			Bogons:       common.Bogons{Interval: payload},
		},
		Interfaces: []common.Interface{{
			Name:        "lan",
			PhysicalIf:  payload,
			Description: payload,
			Enabled:     true,
			IPAddress:   payload,
			Subnet:      payload,
			IPv6Address: payload,
			SubnetV6:    payload,
			Gateway:     payload,
			MTU:         payload,
		}},
		FirewallRules: []common.FirewallRule{{
			Type:        common.RuleTypePass,
			Description: payload,
			Interfaces:  []string{"lan"},
			Protocol:    payload,
			Target:      payload,
			Source:      common.RuleEndpoint{Address: payload, Port: payload},
			Destination: common.RuleEndpoint{Address: payload, Port: payload},
		}},
		SNMP: common.SNMPConfig{
			SysLocation: payload,
			SysContact:  payload,
			ROCommunity: payload,
		},
		NTP: common.NTPConfig{PreferredServer: payload},
		// IDS and NAT reached their tables with no escaper at all. They are
		// separate render paths from the interface and firewall tables above, so
		// the fixture has to carry them or the escaping there goes unguarded.
		IDS: &common.IDSConfig{
			Enabled:           true,
			Interfaces:        []string{payload},
			HomeNetworks:      []string{payload},
			MPMAlgo:           payload,
			DefaultPacketSize: payload,
			LogPayload:        payload,
			Verbosity:         payload,
			AlertLogrotate:    payload,
			AlertSaveLogs:     payload,
			Detect:            common.IDSDetect{Profile: payload},
		},
		// The VLAN and static route tables are built in builder_network.go and
		// emitted from the comprehensive report only, so they are a render path
		// the standard report never touches. Their tag and timestamp columns
		// went in raw.
		VLANs: []common.VLAN{{
			VLANIf:      payload,
			PhysicalIf:  payload,
			Tag:         payload,
			Description: payload,
			Created:     payload,
			Updated:     payload,
		}},
		Routing: common.Routing{
			StaticRoutes: []common.StaticRoute{{
				Network:     payload,
				Gateway:     payload,
				Description: payload,
				Created:     payload,
				Updated:     payload,
			}},
		},
		NAT: common.NATConfig{
			OutboundRules: []common.NATRule{{
				Interfaces:  []string{"lan"},
				Protocol:    payload,
				Target:      payload,
				Description: payload,
				Source:      common.RuleEndpoint{Address: payload, Port: payload},
				Destination: common.RuleEndpoint{Address: payload, Port: payload},
			}},
			InboundRules: []common.InboundNATRule{{
				Interfaces:   []string{"lan"},
				Protocol:     payload,
				ExternalPort: payload,
				InternalIP:   payload,
				InternalPort: payload,
				Description:  payload,
			}},
		},
	}
}

// TestReportHTMLDoesNotExecuteConfigValues is the regression test for the
// report injection bug.
//
// A config.xml is untrusted input. It arrives from a customer firewall, an
// incident-response capture, or a backup of unknown provenance, and the whole
// point of the tool is to turn it into a report someone then opens. Before the
// fix, values such as the hostname were concatenated into markdown unescaped
// and the HTML renderer was configured to pass raw HTML through, so a payload
// in config.xml became live markup in report.html.
//
// The test asserts the outcome rather than the mechanism, so it keeps working
// if the escaping moves: no dangerous construct survives into the HTML, and the
// value is still visible in escaped form so the fix cannot be mistaken for
// silently dropping data.
func TestReportHTMLDoesNotExecuteConfigValues(t *testing.T) {
	t.Parallel()

	for _, payload := range injectionPayloads {
		t.Run(payload, func(t *testing.T) {
			t.Parallel()

			for _, comprehensive := range []bool{false, true} {
				device := newInjectionTestDevice(payload)
				opts := DefaultOptions()
				opts.Format = FormatHTML
				opts.Comprehensive = comprehensive

				gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
				require.NoError(t, err)

				out, err := gen.Generate(context.Background(), device, opts)
				require.NoError(t, err)

				for _, forbidden := range forbiddenInHTML {
					assert.NotContains(t, out, forbidden,
						"comprehensive=%v: config value rendered as live markup", comprehensive)
				}

				assert.Contains(t, out, injectionMarker,
					"comprehensive=%v: config value disappeared instead of being escaped", comprehensive)
			}
		})
	}
}

// TestReportMarkdownEscapesConfigValues covers the markdown deliverable. HTML is
// where the security consequence lands, but an unescaped value also silently
// reformats the markdown report: a stray asterisk turns the rest of a line into
// emphasis, and a bare pipe splits a table row into extra columns.
func TestReportMarkdownEscapesConfigValues(t *testing.T) {
	t.Parallel()

	const payload = injectionMarker + `<b>*emph*|pipe|[link](x)`

	device := newInjectionTestDevice(payload)

	// Each table gets its own tail marker. A shared payload cannot prove a
	// specific cell survived: an unescaped pipe truncates the cell at the pipe,
	// and everything before it, including the leading marker, still renders. Any
	// one of the dozens of non-table fields would then satisfy a check for text
	// common to all of them. The tail sits after the first pipe, so it is present
	// only if that cell was contained rather than cut.
	tails := map[string]func(string){
		"IFACE":  func(v string) { device.Interfaces[0].Description = v },
		"FWRULE": func(v string) { device.FirewallRules[0].Description = v },
		"VLAN":   func(v string) { device.VLANs[0].Description = v },
		"ROUTE":  func(v string) { device.Routing.StaticRoutes[0].Description = v },
		"NATOUT": func(v string) { device.NAT.OutboundRules[0].Description = v },
		"NATIN":  func(v string) { device.NAT.InboundRules[0].Description = v },
		"IDS":    func(v string) { device.IDS.Verbosity = v },
	}
	for tag, set := range tails {
		set(injectionMarker + `<b>*emph*|` + tag + `-SURVIVED|[link](x)`)
	}

	// Both variants. The VLAN, static route and NAT tables are emitted by the
	// comprehensive report only, so a standard-only check leaves them unguarded.
	for _, comprehensive := range []bool{false, true} {
		opts := DefaultOptions()
		opts.Format = FormatMarkdown
		opts.Comprehensive = comprehensive

		gen, err := NewHybridGenerator(builder.NewMarkdownBuilder(), nil)
		require.NoError(t, err)

		out, err := gen.Generate(context.Background(), device, opts)
		require.NoError(t, err)

		require.Contains(t, out, injectionMarker,
			"comprehensive=%v: payload should be present in the report", comprehensive)

		// Assert on the rendered result rather than on the markdown spelling.
		// There are two valid ways to contain a value: backslash-escape the
		// metacharacters, or put it in a correctly fenced code span, where the
		// characters are literal and must appear verbatim. Checking the markdown
		// text for "<b>" would fail the code span form even though it is inert,
		// and would say nothing about whether the escaping actually worked.
		rendered, err := RenderMarkdownToHTML(out)
		require.NoError(t, err)

		assert.NotContains(t, rendered, "<b>",
			"comprehensive=%v: angle brackets became live markup", comprehensive)
		assert.NotContains(t, rendered, "<em>emph</em>",
			"comprehensive=%v: asterisks were parsed as emphasis", comprehensive)
		assert.NotContains(t, rendered, `<a href="x"`,
			"comprehensive=%v: brackets were parsed as a link", comprehensive)

		// Containment is only half of it. A value can also be silently
		// truncated, which is what an unescaped pipe does to a table cell.
		for tag := range tails {
			if !comprehensive && (tag == "VLAN" || tag == "ROUTE" || tag == "NATOUT" || tag == "NATIN") {
				continue // these tables are comprehensive-only
			}

			assert.Containsf(t, rendered, tag+"-SURVIVED",
				"comprehensive=%v: the %s cell was truncated at its pipe rather than escaped",
				comprehensive, tag)
		}
	}
}
