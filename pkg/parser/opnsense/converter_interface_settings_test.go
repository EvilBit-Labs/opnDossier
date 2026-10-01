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

func convertConfig(t *testing.T, cfg []byte) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	device, warnings, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(), bytes.NewReader(cfg), common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", name))
	require.NoError(t, err)

	return raw
}

// TestConverter_IPv6Allow_LegacyElementIsAPresenceToggle covers configs from
// OPNsense releases before 26.1. Those releases test <system><ipv6allow> with
// isset(), and up to 24.1 shipped it as an empty element by default.
func TestConverter_IPv6Allow_LegacyElementIsAPresenceToggle(t *testing.T) {
	t.Parallel()

	raw := readFixture(t, "sample.config.1.xml")
	empty := []byte("<ipv6allow/>")
	require.Equal(t, 1, bytes.Count(raw, empty), "fixture no longer carries an empty <ipv6allow/>")

	tests := []struct {
		name    string
		element string
		want    bool
	}{
		{name: "empty element", element: "<ipv6allow/>", want: true},
		{name: "element with a value", element: "<ipv6allow>1</ipv6allow>", want: true},
		{name: "element absent", element: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _ := convertConfig(t, bytes.Replace(raw, empty, []byte(tt.element), 1))
			assert.Equal(t, tt.want, device.System.IPv6Allow)
		})
	}
}
