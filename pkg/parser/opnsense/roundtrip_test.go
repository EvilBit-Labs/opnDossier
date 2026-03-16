package opnsense_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip_SampleConfigs(t *testing.T) {
	t.Parallel()

	pattern := filepath.Join("..", "..", "..", "testdata", "sample.config.*.xml")
	files, err := filepath.Glob(pattern)
	require.NoError(t, err, "failed to glob testdata")
	require.NotEmpty(t, files, "no sample config files found at %s", pattern)

	factory := parser.NewFactory()

	for _, fpath := range files {
		name := filepath.Base(fpath)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(fpath)
			require.NoError(t, err)
			defer f.Close()

			device, _, err := factory.CreateDevice(context.Background(), f, "", false)
			require.NoError(t, err, "CreateDevice failed for %s", name)
			require.NotNil(t, device, "device is nil for %s", name)

			assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
			assert.NotEmpty(t, device.System.Hostname, "hostname empty for %s", name)
			assert.NotEmpty(t, device.System.Domain, "domain empty for %s", name)
			assert.NotEmpty(t, device.Interfaces, "no interfaces for %s", name)
		})
	}
}
