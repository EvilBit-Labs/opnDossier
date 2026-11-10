package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/audit"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/builder"
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditMetadata_StructuredValuesRenderLabeled drives both audit modes over
// a real fixture, through the same report-to-ComplianceResults mapping the
// audit command uses, and fails when any struct or list-of-struct metadata
// value reaches the markdown through fmt's default %v formatting, which is how
// configuration_summary read as "{54 51 51 1}" and admin_portals as
// "[{webgui 443 lan}]" (#949, #990). It reflects over the report's metadata
// rather than naming keys, so a structured key added later is covered too.
func TestAuditMetadata_StructuredValuesRenderLabeled(t *testing.T) {
	// Do NOT use t.Parallel() — cmd package uses package-level flag globals.
	// See GOTCHAS §1.1.
	logger, err := logging.New(logging.Config{Level: "error"})
	require.NoError(t, err)

	ctx := context.Background()

	configFile, err := os.Open(filepath.Join("..", "testdata", "sample.config.6.xml"))
	require.NoError(t, err)
	defer configFile.Close()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(ctx, configFile, "", false)
	require.NoError(t, err)

	cases := []struct {
		mode     audit.ReportMode
		headings []string
	}{
		{
			mode: audit.ModeBlue,
			headings: []string{
				"### Configuration Summary",
				"| Firewall Rules | ",
				"### Recommendations",
				"- **",
				"| compliance\\_frameworks | FIREWALL, SANS, STIG |",
			},
		},
		{
			mode: audit.ModeRed,
			headings: []string{
				"### Admin Portals",
				"| Name | Port | Reachability |",
				"### Enumeration Data",
				"| WAN Interfaces | ",
			},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			// Do NOT use t.Parallel() — see the parent test.
			pm := audit.NewPluginManager(logger, nil)
			require.NoError(t, pm.InitializePlugins(ctx))

			report, err := audit.NewModeController(pm.GetRegistry(), logger).
				GenerateReport(ctx, device, &audit.ModeConfig{Mode: tc.mode})
			require.NoError(t, err)

			cc := mapAuditReportToComplianceResults(report)
			rendered := builder.NewMarkdownBuilder().BuildAuditSection(&common.CommonDevice{ComplianceResults: cc})

			assert.NotRegexp(t, `\{\d|\[\{`, rendered, "rendered audit section contains a Go struct dump")

			structured := 0
			for key, value := range cc.Metadata {
				if !isStructOrStructList(value) {
					continue
				}
				structured++
				dump := fmt.Sprintf("%v", value)
				assert.NotContains(t, rendered, dump, "metadata %q rendered with default formatting", key)
				assert.NotContains(t, rendered, formatters.EscapeTableContent(dump),
					"metadata %q rendered with default formatting in a table cell", key)
			}
			assert.Positive(t, structured, "fixture should yield structured metadata, or this gate is vacuous")

			for _, heading := range tc.headings {
				assert.Contains(t, rendered, heading)
			}
		})
	}
}

// isStructOrStructList reports whether a metadata value is a struct or a list
// of structs, the shapes the key/value table cannot label.
func isStructOrStructList(value any) bool {
	if value == nil {
		return false
	}
	t := reflect.TypeOf(value)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	return t.Kind() == reflect.Struct
}
