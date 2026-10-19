package opnsense_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hardwareSettings is the subset of common.System these tests compare.
type hardwareSettings struct {
	IPv6Allow                     bool
	DisableChecksumOffloading     bool
	DisableSegmentationOffloading bool
	DisableLargeReceiveOffloading bool
	DisableVLANHWFilter           bool
}

func convertConfig(t *testing.T, cfg []byte) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	device, warnings, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(), bytes.NewReader(cfg), common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

func hardwareSettingsOf(sys common.System) hardwareSettings {
	return hardwareSettings{
		IPv6Allow:                     sys.IPv6Allow,
		DisableChecksumOffloading:     sys.DisableChecksumOffloading,
		DisableSegmentationOffloading: sys.DisableSegmentationOffloading,
		DisableLargeReceiveOffloading: sys.DisableLargeReceiveOffloading,
		DisableVLANHWFilter:           sys.DisableVLANHWFilter,
	}
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
		{name: "element with a false-looking value", element: "<ipv6allow>0</ipv6allow>", want: true},
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

// settingsBlockTemplate follows Interfaces/Settings.xml in OPNsense 26.1: the
// attributes BaseModel writes on the mount node and the fields in model order.
const settingsBlockTemplate = `      <settings%s persisted_at="1769600000.00" description="Global interface settings">
        <disablechecksumoffloading>%s</disablechecksumoffloading>
        <disablesegmentationoffloading>%s</disablesegmentationoffloading>
        <disablelargereceiveoffloading>%s</disablelargereceiveoffloading>
        <disablevlanhwfilter>%s</disablevlanhwfilter>
        <disableipv6>%s</disableipv6>
        <dhcp6_norelease>0</dhcp6_norelease>
        <dhcp6_debug>0</dhcp6_debug>
        <dhcp6_duid/>
        <dhcp6_ratimeout>10</dhcp6_ratimeout>
      </settings>
`

// TestConverter_InterfaceSettings_ReadFromMigratedBlock rewrites a fixture the
// way OPNsense 26.1 migration SET1_0_0 does: it deletes the <system> elements
// and writes <OPNsense><Interfaces><settings> in the shape of
// Interfaces/Settings.xml.
func TestConverter_InterfaceSettings_ReadFromMigratedBlock(t *testing.T) {
	t.Parallel()

	raw := readFixture(t, "sample.config.5.xml")
	legacy := []byte("    <disablevlanhwfilter>1</disablevlanhwfilter>\n" +
		"    <disablechecksumoffloading>1</disablechecksumoffloading>\n" +
		"    <disablesegmentationoffloading>1</disablesegmentationoffloading>\n" +
		"    <disablelargereceiveoffloading>1</disablelargereceiveoffloading>\n" +
		"    <ipv6allow>1</ipv6allow>\n")
	anchor := []byte("      <vxlans version=\"1.0.2\"/>\n")
	require.Equal(t, 1, bytes.Count(raw, legacy), "fixture <system> elements changed")
	require.Equal(t, 1, bytes.Count(raw, anchor), "fixture <OPNsense><Interfaces> changed")

	type values struct{ version, csum, tso, lro, vlan, ipv6 string }
	migrated := func(v values, keepLegacy bool) []byte {
		version := ""
		if v.version != "" {
			version = fmt.Sprintf(" version=%q", v.version)
		}

		block := fmt.Appendf(nil, settingsBlockTemplate, version, v.csum, v.tso, v.lro, v.vlan, v.ipv6)
		cfg := bytes.Replace(raw, anchor, append(bytes.Clone(anchor), block...), 1)
		if !keepLegacy {
			cfg = bytes.Replace(cfg, legacy, nil, 1)
		}

		return cfg
	}

	tests := []struct {
		name       string
		values     values
		keepLegacy bool
		want       hardwareSettings
	}{
		{
			// What the migration writes for an absent offload or VLAN key.
			name:   "migration defaults",
			values: values{"1.0.0", "1", "1", "1", "2", "0"},
			want:   hardwareSettings{true, true, true, true, false},
		},
		{
			name:   "IPv6 disabled",
			values: values{"1.0.0", "1", "1", "1", "2", "1"},
			want:   hardwareSettings{false, true, true, true, false},
		},
		{
			name:   "offloading left on",
			values: values{"1.0.0", "0", "0", "0", "2", "0"},
			want:   hardwareSettings{true, false, false, false, false},
		},
		{
			name:   "checksum offloading off only",
			values: values{"1.0.0", "1", "0", "0", "2", "0"},
			want:   hardwareSettings{true, true, false, false, false},
		},
		{
			name:   "segmentation offloading off only",
			values: values{"1.0.0", "0", "1", "0", "2", "0"},
			want:   hardwareSettings{true, false, true, false, false},
		},
		{
			name:   "large receive offloading off only",
			values: values{"1.0.0", "0", "0", "1", "2", "0"},
			want:   hardwareSettings{true, false, false, true, false},
		},
		{
			// OPNsense always writes the attribute; a hand-made block may not.
			name:   "no version attribute",
			values: values{"", "1", "1", "1", "2", "0"},
			want:   hardwareSettings{true, true, true, true, false},
		},
		{
			name:   "VLAN filter disabled",
			values: values{"1.0.0", "0", "0", "0", "1", "0"},
			want:   hardwareSettings{true, false, false, false, true},
		},
		{
			name:   "VLAN filter enabled",
			values: values{"1.0.0", "0", "0", "0", "0", "0"},
			want:   hardwareSettings{true, false, false, false, false},
		},
		{
			// The <system> elements all say on; OPNsense ignores them.
			name:       "block wins over leftover system elements",
			values:     values{"1.0.0", "0", "0", "0", "0", "1"},
			keepLegacy: true,
			want:       hardwareSettings{false, false, false, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := convertConfig(t, migrated(tt.values, tt.keepLegacy))
			assert.Equal(t, tt.want, hardwareSettingsOf(device.System))
			assert.Nil(t, findWarning(warnings, "OPNsense.Interfaces.Settings.Version", tt.values.version))
		})
	}

	t.Run("unrecognized model version warns", func(t *testing.T) {
		t.Parallel()

		_, warnings := convertConfig(t, migrated(values{"1.0.1", "1", "1", "1", "2", "0"}, false))

		warning := findWarning(warnings, "OPNsense.Interfaces.Settings.Version", "1.0.1")
		require.NotNil(t, warning)
		assert.Equal(t, common.SeverityMedium, warning.Severity)
	})
}
