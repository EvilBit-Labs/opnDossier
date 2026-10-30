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
// model 1.1.2 replaced <ips> with <mode>, its migration drops <ips>, and its
// templates run pcap without <mode> whatever <ips> holds. An older model reads
// only <ips>, so a <mode> there changes nothing and draws no warning. A config
// without a version reads <mode>, then <ips>.
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
		{"1.1.2", `<ips>1</ips>`, false},
		{"1.1.2", `<mode/><ips>1</ips>`, false},
		{"1.1.2", `<mode>pcap</mode><ips>1</ips>`, false},
		{"1.1.1", `<ips>1</ips>`, true},
		{"1.1.1", `<ips>0</ips>`, false},
		{"1.1.1", `<mode>netmap</mode><ips>0</ips>`, false},
		{"1.1.1", `<mode>divert</mode>`, false},
		{"1.1.1", `<mode>pcap</mode><ips>1</ips>`, true},
		{"1.1.1", `<mode>afpacket</mode><ips>1</ips>`, true},
		{"", `<mode>netmap</mode><ips>0</ips>`, true},
		{"", `<mode>pcap</mode><ips>1</ips>`, false},
		{"", `<ips>1</ips>`, true},
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

// TestConverter_IDS_KnownModelVersions converts <ips>1</ips> under every
// version IDS.xml has carried, listed here from the vendor history rather than
// from idsModelVersions, so an entry dropped or mistyped there fails. None
// warns, and only the models before 1.1.2 read <ips>.
func TestConverter_IDS_KnownModelVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		wantIPS bool
	}{
		{"", true},
		{"1.0.0", true},
		{"1.0.1", true},
		{"1.0.2", true},
		{"1.0.3", true},
		{"1.0.4", true},
		{"1.0.5", true},
		{"1.0.6", true},
		{"1.0.7", true},
		{"1.0.8", true},
		{"1.0.9", true},
		{"1.1.0", true},
		{"1.1.1", true},
		{"1.1.2", false},
	}

	for _, tc := range tests {
		t.Run("version "+tc.version, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDs(t, tc.version, `<ips>1</ips>`)
			assert.Empty(t, warnings)
			assert.Equal(t, tc.wantIPS, device.IDS.IPSMode)
		})
	}
}

// TestConverter_IDS_UnrecognizedMode warns on a <mode> outside the options of
// model 1.1.2 and reports it as IDS, as OPNsense runs it (GOTCHAS 5.2). A
// config without a version is read from <mode>, so it warns as well.
func TestConverter_IDS_UnrecognizedMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		mode    string
	}{
		{"1.1.2", "afpacket"},
		{"1.1.2", "NETMAP"},
		{"", "afpacket"},
	}

	for _, tc := range tests {
		t.Run(tc.version+" "+tc.mode, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDs(t, tc.version, "<mode>"+tc.mode+"</mode>")
			require.Len(t, warnings, 1)
			assert.Equal(t, "IDS.General.Mode", warnings[0].Field)
			assert.Equal(t, tc.mode, warnings[0].Value)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
			assert.NotEmpty(t, warnings[0].Message)
			assert.False(t, device.IDS.IPSMode)
		})
	}
}
