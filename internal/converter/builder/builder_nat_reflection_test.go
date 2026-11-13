package builder

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestNATSummary_ReflectionLabelMatchesValue pins the NAT Summary line to the
// value it prints. It printed ReflectionDisabled under the label "NAT
// Reflection", so a firewall with reflection off showed a tick next to "NAT
// Reflection", and the note below it said the opposite. The label also names
// what it covers, so it does not read as a synonym of the System section's
// "Disable NAT Reflection", which is the global flag alone.
func TestNATSummary_ReflectionLabelMatchesValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		disabled bool
		wantNote string
	}{
		{"reflection off", true, "NAT reflection is properly disabled"},
		{"reflection on", false, "NAT reflection is enabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				DeviceType: common.DeviceTypeOPNsense,
				NAT: common.NATConfig{
					OutboundMode:       common.OutboundAutomatic,
					ReflectionDisabled: tt.disabled,
				},
			}

			report, err := NewMarkdownBuilder().BuildStandardReport(device)
			if err != nil {
				t.Fatalf("BuildStandardReport() error = %v", err)
			}

			wantLine := "**NAT Reflection Disabled (global and port forwards)**: " + formatters.FormatBool(tt.disabled)
			if !strings.Contains(report, wantLine) {
				t.Errorf("report does not contain %q", wantLine)
			}
			if strings.Contains(report, "**NAT Reflection**:") {
				t.Errorf("report still labels the disabled flag as %q", "NAT Reflection")
			}
			if !strings.Contains(report, tt.wantNote) {
				t.Errorf("report does not contain the note %q", tt.wantNote)
			}
		})
	}
}
