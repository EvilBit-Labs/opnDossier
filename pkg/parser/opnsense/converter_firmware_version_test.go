package opnsense_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_FirmwareVersionAttribute_NotARelease pins that the version
// attribute on <system><firmware> never reaches System.Firmware.Version.
// OPNsense's BaseModel writes the Firmware model's schema version there, so a
// box running any release carries 1.0.1 (or 1.0.0 on older configs), and the
// report printed it as "Platform: OPNsense 1.0.1".
func TestConverter_FirmwareVersionAttribute_NotARelease(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml"))
	require.NoError(t, err)

	shipped := []byte(`<firmware version="1.0.1">`)
	require.Equal(t, 1, bytes.Count(raw, shipped), "fixture no longer carries the firmware model version")

	for _, version := range []string{"1.0.1", "1.0.0"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			cfg := bytes.Replace(raw, shipped, []byte(`<firmware version="`+version+`">`), 1)
			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(), bytes.NewReader(cfg), common.DeviceTypeUnknown, false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Empty(t, device.System.Firmware.Version)
		})
	}
}
