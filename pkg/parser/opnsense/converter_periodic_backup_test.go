package opnsense_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_PeriodicBackup_ReadsHourInterval pins how <rrdbackup> and
// <netflowbackup> are read. They hold an hour interval, not a flag: the GUI
// writes 1 to 24 for a backup every N hours, and otherwise -1 or no element
// (0 before 15.7.23). BoolFlag read 24 as false. Each case changes one element
// in testdata/sample.config.1.xml, which follows the config.xml.sample OPNsense
// ships, rather than building XML from the schema.
func TestConverter_PeriodicBackup_ReadsHourInterval(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sample.config.1.xml"))
	require.NoError(t, err)

	fields := []struct {
		element string
		field   string
		get     func(common.System) bool
	}{
		{element: "rrdbackup", field: "System.RrdBackup", get: func(s common.System) bool { return s.RrdBackup }},
		{
			element: "netflowbackup",
			field:   "System.NetflowBackup",
			get:     func(s common.System) bool { return s.NetflowBackup },
		},
	}

	tests := []struct {
		name    string
		value   string // "" removes the element
		want    bool
		warning bool
	}{
		{name: "disabled", value: "-1", want: false},
		{name: "zero", value: "0", want: false},
		{name: "every hour", value: "1", want: true},
		{name: "every 24 hours", value: "24", want: true},
		{name: "above 24", value: "48", want: true},
		{name: "no element", value: "", want: false},
		{name: "not a number", value: "yes", want: false, warning: true},
	}

	for _, f := range fields {
		shipped := []byte("<" + f.element + ">-1</" + f.element + ">")
		require.Equalf(t, 1, bytes.Count(raw, shipped),
			"fixture no longer carries %s; this test is vacuous", shipped)

		for _, tt := range tests {
			t.Run(f.element+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				var replacement []byte
				if tt.value != "" {
					replacement = []byte("<" + f.element + ">" + tt.value + "</" + f.element + ">")
				}

				cfg := bytes.Replace(raw, shipped, replacement, 1)

				device, warnings, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
					context.Background(), bytes.NewReader(cfg), common.DeviceTypeUnknown, false,
				)
				require.NoError(t, err)
				require.NotNil(t, device)

				assert.Equal(t, tt.want, f.get(device.System))

				if tt.warning {
					w := findWarning(warnings, f.field, tt.value)
					require.NotNil(t, w, "a value that is not a whole number of hours is warned about")
					assert.Equal(t, common.SeverityLow, w.Severity)
				} else {
					assert.False(t, slices.ContainsFunc(warnings, func(w common.ConversionWarning) bool {
						return w.Field == f.field
					}), "only a value that is not a whole number of hours is warned about")
				}
			})
		}
	}
}
