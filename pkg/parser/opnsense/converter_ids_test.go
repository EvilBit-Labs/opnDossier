package opnsense_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseIDs runs a config whose <IDS> carries version and the given <general>
// children through the full parser pipeline.
func parseIDs(t *testing.T, version, general string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	config := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>em0</if></wan></interfaces>
  <OPNsense>
    <IDS version=%q>
      <general><enabled>1</enabled>%s<interfaces>wan</interfaces></general>
    </IDS>
  </OPNsense>
</opnsense>`, version, general)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device.IDS)

	return device, warnings
}

// TestConverter_IDS_Mode pins IPS mode across the OPNsense 26.1 change: IDS
// model 1.1.2 replaced <ips> with <mode>, and its migration drops <ips>.
func TestConverter_IDS_Mode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		general string
		want    bool
	}{
		{"1.1.2", `<mode>netmap</mode>`, true},
		{"1.1.2", `<mode>divert</mode>`, true},
		{"1.1.2", `<mode>pcap</mode>`, false},
		{"1.1.1", `<ips>1</ips>`, true},
		{"1.1.1", `<ips>0</ips>`, false},
	}

	for _, tc := range tests {
		t.Run(tc.version+" "+tc.general, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDs(t, tc.version, tc.general)
			assert.Empty(t, warnings)
			assert.True(t, device.IDS.Enabled)
			assert.Equal(t, tc.want, device.IDS.IPSMode)
		})
	}
}

// TestConverter_IDS_UnknownModelVersion warns when <IDS> carries a model
// version the converter has not been checked against (GOTCHAS 3.7).
func TestConverter_IDS_UnknownModelVersion(t *testing.T) {
	t.Parallel()

	device, warnings := parseIDs(t, "1.1.3", `<mode>netmap</mode>`)
	require.Len(t, warnings, 1)
	assert.Equal(t, "IDS.Version", warnings[0].Field)
	assert.Equal(t, "1.1.3", warnings[0].Value)
	assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
	assert.NotEmpty(t, warnings[0].Message)
	assert.True(t, device.IDS.IPSMode)
}
