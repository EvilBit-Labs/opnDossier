package pfsense_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_ConfigVersion_NotAFirmwareRelease pins that pfSense's
// top-level <version> stays out of System.Firmware.Version. It is the config
// format version (globals.inc latest_config: 21.7 at 2.5.2, 22.2 at 2.6.0,
// 22.9 at 2.7.0), not the installed release, and the report printed it as
// the platform release ("Platform: pfSense 22.9"). CommonDevice.Version
// keeps it.
func TestConverter_ConfigVersion_NotAFirmwareRelease(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../../testdata/pfsense/config-2.7.x.xml")
	require.NoError(t, err)

	shipped := []byte("<version>23.09</version>")
	require.Equal(t, 1, bytes.Count(raw, shipped), "fixture no longer carries its config version")

	for _, version := range []string{"22.9", "23.3"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			cfg := bytes.Replace(raw, shipped, []byte("<version>"+version+"</version>"), 1)
			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), bytes.NewReader(cfg))
			require.NoError(t, err)

			assert.Empty(t, device.System.Firmware.Version)
			assert.Equal(t, version, device.Version)
		})
	}
}
