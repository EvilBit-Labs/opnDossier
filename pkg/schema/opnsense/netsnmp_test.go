package opnsense

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetsnmp_RoundTrip(t *testing.T) {
	t.Parallel()

	const input = `<netsnmp>
  <general version="1.0.7">
    <enabled>1</enabled>
    <community>public</community>
    <syslocation>rack 4</syslocation>
    <syscontact>noc</syscontact>
    <l3visibility>0</l3visibility>
    <versionoid>1</versionoid>
    <enableagentx>0</enableagentx>
    <enableobservium>1</enableobservium>
    <listen>192.0.2.1,2001:db8::1</listen>
  </general>
  <user version="1.0.1">
    <users>
      <user uuid="6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb001">
        <enabled>0</enabled>
        <username>retired</username>
        <password>RetiredPass123</password>
        <enckey>RetiredKey12345</enckey>
        <readwrite>0</readwrite>
      </user>
      <user uuid="6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb002">
        <enabled>1</enabled>
        <username>monitor</username>
        <password>MonitorPass123</password>
        <enckey>MonitorKey12345</enckey>
        <readwrite>1</readwrite>
      </user>
    </users>
  </user>
</netsnmp>`

	var first Netsnmp
	require.NoError(t, xml.Unmarshal([]byte(input), &first))

	want := Netsnmp{
		General: NetsnmpGeneral{
			Version: "1.0.7", Enabled: "1", Community: "public", SysLocation: "rack 4", SysContact: "noc",
			L3Visibility: "0", VersionOID: "1", EnableAgentX: "0", EnableObservium: "1",
			Listen: "192.0.2.1,2001:db8::1",
		},
		User: NetsnmpUsers{
			Version: "1.0.1",
			Users: []NetsnmpUser{
				{UUID: "6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb001", Enabled: "0", Username: "retired", ReadWrite: "0"},
				{UUID: "6f1c2a52-6d0e-4b8e-9b51-0f3f4cdbb002", Enabled: "1", Username: "monitor", ReadWrite: "1"},
			},
		},
	}
	assert.Equal(t, want, first)

	out, err := xml.Marshal(struct {
		Netsnmp

		XMLName xml.Name `xml:"netsnmp"`
	}{Netsnmp: first})
	require.NoError(t, err)
	assert.NotContains(t, string(out), "Pass123", "secrets are not bound, so they are not written back")

	var second Netsnmp
	require.NoError(t, xml.Unmarshal(out, &second))
	assert.Equal(t, first, second)
}

// TestSnmpd_EnableRoundTrip keeps an absent <enable> apart from an empty one,
// since an empty one starts the legacy agent.
func TestSnmpd_EnableRoundTrip(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		`<snmpd><rocommunity>public</rocommunity></snmpd>`,
		`<snmpd><rocommunity>public</rocommunity><enable/></snmpd>`,
		`<snmpd><rocommunity>public</rocommunity><enable>yes</enable></snmpd>`,
	} {
		var first Snmpd
		require.NoError(t, xml.Unmarshal([]byte(input), &first))

		out, err := xml.Marshal(struct {
			Snmpd

			XMLName xml.Name `xml:"snmpd"`
		}{Snmpd: first})
		require.NoError(t, err)

		var second Snmpd
		require.NoError(t, xml.Unmarshal(out, &second))
		assert.Equal(t, first, second, input)
		assert.Equal(t, first.Enable == nil, second.Enable == nil, input)
	}

	var absent, empty Snmpd
	require.NoError(t, xml.Unmarshal([]byte(`<snmpd/>`), &absent))
	require.NoError(t, xml.Unmarshal([]byte(`<snmpd><enable/></snmpd>`), &empty))
	assert.Nil(t, absent.Enable)
	require.NotNil(t, empty.Enable)
	assert.Empty(t, *empty.Enable)
}
