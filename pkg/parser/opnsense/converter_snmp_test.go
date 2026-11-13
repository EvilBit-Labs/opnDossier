package opnsense_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staleLegacySNMP is the block OPNsense factory defaults wrote from 16.7 to
// 25.7. It has no <enable>, so no release starts an agent from it.
const staleLegacySNMP = `
  <snmpd>
    <syslocation/>
    <syscontact/>
    <rocommunity>public</rocommunity>
  </snmpd>`

// netsnmpBlock renders <OPNsense><netsnmp> as the os-net-snmp plugin saves
// it, with the general model's enabled and community values and the given
// user items.
func netsnmpBlock(version, enabled, community, listen, users string) string {
	return `
  <OPNsense>
    <netsnmp>
      <general version="` + version + `">
        <enabled>` + enabled + `</enabled>
        <community>` + community + `</community>
        <syslocation>rack 4</syslocation>
        <syscontact>noc</syscontact>
        <l3visibility>0</l3visibility>
        <versionoid>0</versionoid>
        <enableagentx>0</enableagentx>
        <enableobservium>0</enableobservium>
        <listen>` + listen + `</listen>
      </general>
      <user version="1.0.1">
        <users>` + users + `</users>
      </user>
    </netsnmp>
  </OPNsense>`
}

// snmpUsers holds a disabled read-write user first and an enabled one second,
// each with the cleartext secrets the model stores.
const snmpUsers = `
          <user uuid="6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb001">
            <enabled>0</enabled>
            <username>retired</username>
            <password>RetiredPass123</password>
            <enckey>RetiredKey12345</enckey>
            <readwrite>1</readwrite>
          </user>
          <user uuid="6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb002">
            <enabled>1</enabled>
            <username>monitor</username>
            <password>MonitorPass123</password>
            <enckey>MonitorKey12345</enckey>
            <readwrite>1</readwrite>
          </user>`

func snmpConfig(body string) string {
	return `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <domain>example.com</domain>
  </system>` + body + `
</opnsense>`
}

func convertSNMPConfig(t *testing.T, body string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	device, warnings, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(), strings.NewReader(snmpConfig(body)), common.DeviceTypeUnknown, false)
	require.NoError(t, err)

	var snmpWarnings []common.ConversionWarning
	for _, w := range warnings {
		if strings.HasPrefix(w.Field, "SNMP.") {
			snmpWarnings = append(snmpWarnings, w)
		}
	}

	return device, snmpWarnings
}

func TestConverter_SNMP_AgentTheConfigStarts(t *testing.T) {
	t.Parallel()

	enabledAgent := common.SNMPConfig{
		Enabled:         true,
		ROCommunity:     "public",
		SysLocation:     "rack 4",
		SysContact:      "noc",
		ListenAddresses: []string{"192.0.2.1", "2001:db8::1"},
		Users:           []common.SNMPUser{{Username: "monitor", ReadWrite: true}},
	}

	tests := []struct {
		name         string
		body         string
		want         common.SNMPConfig
		wantWarnings []string
	}{
		{
			name: "net-snmp enabled beside the stale legacy block",
			body: staleLegacySNMP + netsnmpBlock("1.0.7", "1", "public", "192.0.2.1, 2001:db8::1", snmpUsers),
			want: enabledAgent,
		},
		{
			name: "net-snmp enabled with SNMPv3 users only",
			body: netsnmpBlock("1.0.7", "1", "", "", snmpUsers),
			want: common.SNMPConfig{
				Enabled:     true,
				SysLocation: "rack 4",
				SysContact:  "noc",
				Users:       []common.SNMPUser{{Username: "monitor", ReadWrite: true}},
			},
		},
		{
			name: "net-snmp disabled beside the stale legacy block",
			body: staleLegacySNMP + netsnmpBlock("1.0.7", "0", "public", "", snmpUsers),
			want: common.SNMPConfig{},
		},
		{
			name: "net-snmp enabled element empty",
			body: netsnmpBlock("1.0.7", "", "public", "", ""),
			want: common.SNMPConfig{},
		},
		{
			name: "stale legacy block alone",
			body: staleLegacySNMP,
			want: common.SNMPConfig{},
		},
		{
			name: "legacy block with an empty enable element",
			body: `
  <snmpd>
    <syslocation>closet</syslocation>
    <syscontact>ops</syscontact>
    <rocommunity>s3cretcomm</rocommunity>
    <enable/>
  </snmpd>`,
			want: common.SNMPConfig{
				Enabled:     true,
				ROCommunity: "s3cretcomm",
				SysLocation: "closet",
				SysContact:  "ops",
			},
			wantWarnings: []string{"SNMP.Snmpd.Enable"},
		},
		{
			name: "legacy enable beside an enabled net-snmp agent",
			body: `
  <snmpd>
    <rocommunity>legacycomm</rocommunity>
    <enable>1</enable>
  </snmpd>` + netsnmpBlock("1.0.7", "1", "public", "192.0.2.1,2001:db8::1", snmpUsers),
			want:         enabledAgent,
			wantWarnings: []string{"SNMP.Snmpd.Enable"},
		},
		{
			name:         "unrecognized general model version",
			body:         netsnmpBlock("1.0.8", "1", "public", "192.0.2.1,2001:db8::1", snmpUsers),
			want:         enabledAgent,
			wantWarnings: []string{"SNMP.Netsnmp.General.Version"},
		},
		{
			name: "first released general model version",
			body: netsnmpBlock("1.0.0", "1", "public", "192.0.2.1,2001:db8::1", snmpUsers),
			want: enabledAgent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := convertSNMPConfig(t, tc.body)
			assert.Equal(t, tc.want, device.SNMP)
			assert.Equal(t, tc.want.Enabled, device.SNMP.IsEnabled())

			fields := make([]string, 0, len(warnings))
			for _, w := range warnings {
				fields = append(fields, w.Field)
			}
			assert.ElementsMatch(t, tc.wantWarnings, fields)
		})
	}
}

// TestConverter_SNMP_UserDefaults pins the raw-value reading the agent's
// templates apply: a user loads only with <enabled>1</enabled>, and read-write
// access only with <readwrite>1</readwrite>, so an absent element means
// neither, although the model's own default for <enabled> is 1.
func TestConverter_SNMP_UserDefaults(t *testing.T) {
	t.Parallel()

	users := `
          <user uuid="6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb003">
            <username>noenabled</username>
            <readwrite>1</readwrite>
          </user>
          <user uuid="6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb004">
            <enabled>1</enabled>
            <username>readonly</username>
          </user>`

	device, warnings := convertSNMPConfig(t, netsnmpBlock("1.0.7", "1", "", "", users))
	assert.Empty(t, warnings)
	assert.Equal(t, []common.SNMPUser{{Username: "readonly"}}, device.SNMP.Users)
}

// TestConverter_SNMP_SecretsNeverExported checks that the SNMPv3 passwords
// and privacy keys the plugin stores never reach the device model.
func TestConverter_SNMP_SecretsNeverExported(t *testing.T) {
	t.Parallel()

	device, _ := convertSNMPConfig(t, netsnmpBlock("1.0.7", "1", "public", "", snmpUsers))

	raw, err := json.Marshal(device)
	require.NoError(t, err)

	for _, secret := range []string{"RetiredPass123", "RetiredKey12345", "MonitorPass123", "MonitorKey12345"} {
		assert.NotContains(t, string(raw), secret)
	}
	assert.Contains(t, string(raw), `"username":"monitor"`)
}

// TestConverter_SNMP_ModelVersionPins checks every version each os-net-snmp
// model has carried converts without a warning, and that an unknown version
// warns whether or not the agent is enabled: a renamed <enabled> would read
// as an agent that is off, so the check cannot wait for an enabled one.
func TestConverter_SNMP_ModelVersionPins(t *testing.T) {
	t.Parallel()

	for version := range strings.FieldsSeq("1.0.0 1.0.1 1.0.3 1.0.4 1.0.5 1.0.6 1.0.7") {
		_, warnings := convertSNMPConfig(t, netsnmpBlock(version, "1", "public", "", ""))
		assert.Empty(t, warnings, "general model %s", version)
	}

	for _, version := range []string{"1.0.0", "1.0.1"} {
		body := strings.Replace(netsnmpBlock("1.0.7", "1", "public", "", ""),
			`<user version="1.0.1">`, `<user version="`+version+`">`, 1)
		_, warnings := convertSNMPConfig(t, body)
		assert.Empty(t, warnings, "user model %s", version)
	}

	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name:      "unknown general version with the agent off",
			body:      netsnmpBlock("1.0.8", "0", "public", "", ""),
			wantField: "SNMP.Netsnmp.General.Version",
		},
		{
			name: "unknown user version",
			body: strings.Replace(netsnmpBlock("1.0.7", "1", "public", "", ""),
				`<user version="1.0.1">`, `<user version="1.0.2">`, 1),
			wantField: "SNMP.Netsnmp.User.Version",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, warnings := convertSNMPConfig(t, tc.body)
			require.Len(t, warnings, 1)
			assert.Equal(t, tc.wantField, warnings[0].Field)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
		})
	}
}
