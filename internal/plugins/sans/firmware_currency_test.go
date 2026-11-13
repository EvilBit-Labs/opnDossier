package sans_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSANSPlugin_FirmwareCurrency_NeverEvaluated pins SANS-FW-008 as a control
// config.xml cannot decide. Whatever the firmware version holds, the control
// is neither evaluated nor reported: a value there used to pass it, although
// no vendor records the installed release in config.xml.
func TestSANSPlugin_FirmwareCurrency_NeverEvaluated(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"", "1.0.1", "26.7.9"} {
		t.Run("version="+version, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				System: common.System{Firmware: common.Firmware{Version: version}},
			}

			findings, evaluated, err := sans.NewPlugin().RunChecks(device)
			require.NoError(t, err)

			assert.NotContains(t, evaluated, "SANS-FW-008")
			for _, f := range findings {
				assert.NotContains(t, f.References, "SANS-FW-008")
			}
		})
	}
}
