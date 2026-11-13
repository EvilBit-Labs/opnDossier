package opnsense_test

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyRemoteSyslog is the <syslog> block 19.7's logging page wrote for remote
// logging to one server with system and filter events ticked.
const legacyRemoteSyslog = `<syslog>
    <reverse/>
    <nentries>50</nentries>
    <remoteserver>10.0.0.9</remoteserver>
    <remoteserver2/>
    <remoteserver3/>
    <sourceip/>
    <ipproto>ipv4</ipproto>
    <filter>1</filter>
    <system>1</system>
    <enable>1</enable>
    <nologdefaultpass>1</nologdefaultpass>
  </syslog>`

// syslogModel builds an <OPNsense><Syslog> block as 26.7 writes it.
func syslogModel(version, maxpreserve, destinations string) string {
	return `<OPNsense><Syslog version="` + version + `">
      <general>
        <enabled>1</enabled>
        <loglocal>1</loglocal>
        <maxpreserve>` + maxpreserve + `</maxpreserve>
        <maxfilesize/>
      </general>
      <destinations>` + destinations + `</destinations>
    </Syslog></OPNsense>`
}

// syslogDestination builds a <destination> with the elements 26.7 writes.
func syslogDestination(uuid, enabled, transport, program, level, facility, hostname string) string {
	return `<destination uuid="` + uuid + `">
          <enabled>` + enabled + `</enabled>
          <transport>` + transport + `</transport>
          <program>` + program + `</program>
          <level>` + level + `</level>
          <facility>` + facility + `</facility>
          <hostname>` + hostname + `</hostname>
          <certificate/>
          <port>6514</port>
          <rfc5424>0</rfc5424>
          <suppress>0</suppress>
          <description>siem</description>
        </destination>`
}

// parseSyslogConfig runs a config with the given top-level elements through the
// full parser pipeline.
func parseSyslogConfig(t *testing.T, inner string) (common.SyslogConfig, []common.ConversionWarning) {
	t.Helper()

	config := `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>vtnet0</if></wan><lan><if>vtnet1</if></lan></interfaces>
  ` + inner + `
</opnsense>`

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device.Syslog, warnings
}

// syslogWarnings keeps the warnings the syslog converter emits.
func syslogWarnings(warnings []common.ConversionWarning) []common.ConversionWarning {
	var out []common.ConversionWarning
	for _, w := range warnings {
		if strings.HasPrefix(w.Field, "Syslog.") {
			out = append(out, w)
		}
	}

	return out
}

// TestConverter_Syslog_StaleLegacyRemoteIgnored covers a config upgraded from
// 19.7 that still carries the legacy remote keys. From 20.1 OPNsense forwards
// only to the model's destinations, so with none defined it forwards nothing.
func TestConverter_Syslog_StaleLegacyRemoteIgnored(t *testing.T) {
	t.Parallel()

	sl, warnings := parseSyslogConfig(t, legacyRemoteSyslog+syslogModel("1.0.3", "31", ""))

	assert.False(t, sl.Enabled)
	assert.Empty(t, sl.RemoteServer)
	assert.False(t, sl.FilterLogging)
	assert.False(t, sl.SystemLogging)
	assert.Empty(t, sl.Destinations)

	got := syslogWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "Syslog.RemoteServer", got[0].Field)
	assert.Equal(t, "10.0.0.9", got[0].Value)
	assert.Equal(t, common.SeverityMedium, got[0].Severity)
}

// TestConverter_Syslog_LegacyOnlyConfigReadAsBefore keeps the legacy reading
// for a config with no Syslog model, which predates 19.7.
func TestConverter_Syslog_LegacyOnlyConfigReadAsBefore(t *testing.T) {
	t.Parallel()

	sl, warnings := parseSyslogConfig(t, legacyRemoteSyslog)

	assert.True(t, sl.Enabled)
	assert.Equal(t, "10.0.0.9", sl.RemoteServer)
	assert.True(t, sl.FilterLogging)
	assert.True(t, sl.SystemLogging)
	assert.False(t, sl.AuthLogging)
	assert.Empty(t, syslogWarnings(warnings))
}

// TestConverter_Syslog_ModelDestinations reads the remote targets 20.1 and
// later forward to. The disabled target comes first, so a converter that took
// the first entry would report the wrong server.
func TestConverter_Syslog_ModelDestinations(t *testing.T) {
	t.Parallel()

	destinations := syslogDestination("a1", "0", "udp4", "", "", "", "10.0.0.7") +
		syslogDestination("b2", "1", "tls4", "", "", "", "10.0.0.50")

	sl, warnings := parseSyslogConfig(t, syslogModel("1.0.3", "31", destinations))

	assert.True(t, sl.Enabled)
	assert.Equal(t, "10.0.0.50", sl.RemoteServer)
	assert.Empty(t, sl.RemoteServer2)
	assert.True(t, sl.SystemLogging)
	assert.True(t, sl.AuthLogging)
	assert.True(t, sl.FilterLogging)
	assert.Equal(t, "31", sl.RotateCount)
	assert.Empty(t, syslogWarnings(warnings))

	require.Len(t, sl.Destinations, 2)
	assert.Equal(t, common.SyslogDestination{
		Enabled: false, Transport: "udp4", Hostname: "10.0.0.7", Port: "6514", Description: "siem",
	}, sl.Destinations[0])
	assert.Equal(t, common.SyslogDestination{
		Enabled: true, Transport: "tls4", Hostname: "10.0.0.50", Port: "6514", Description: "siem",
	}, sl.Destinations[1])
}

// TestConverter_Syslog_StaleLegacyBesideDestination reports the model's target,
// not the legacy server the firewall no longer reads.
func TestConverter_Syslog_StaleLegacyBesideDestination(t *testing.T) {
	t.Parallel()

	sl, warnings := parseSyslogConfig(t, legacyRemoteSyslog+
		syslogModel("1.0.3", "31", syslogDestination("b2", "1", "udp4", "", "", "", "10.0.0.50")))

	assert.True(t, sl.Enabled)
	assert.Equal(t, "10.0.0.50", sl.RemoteServer)
	assert.Empty(t, sl.RemoteServer2)
	assert.Len(t, syslogWarnings(warnings), 1)
}

// TestConverter_Syslog_DestinationsThatForwardNothing covers targets the
// template skips or writes no network target for.
func TestConverter_Syslog_DestinationsThatForwardNothing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		destination  string
		wantListed   int
		wantWarnings int
	}{
		{
			name:        "absent enabled element reads as 0 in the template",
			destination: `<destination><transport>udp4</transport><hostname>10.0.0.50</hostname></destination>`,
			wantListed:  1,
		},
		{
			name:        "enabled element other than 1",
			destination: syslogDestination("c3", "yes", "udp4", "", "", "", "10.0.0.50"),
			wantListed:  1,
		},
		{
			name:         "transport outside the template's list",
			destination:  syslogDestination("c3", "1", "udp", "", "", "", "10.0.0.50"),
			wantListed:   1,
			wantWarnings: 1,
		},
		{
			name:        "no hostname",
			destination: syslogDestination("c3", "1", "udp4", "", "", "", ""),
			wantListed:  1,
		},
		{
			name:        "empty placeholder",
			destination: `<destination/>`,
		},
		{
			name:        "placeholder with only a uuid",
			destination: `<destination uuid="d4"></destination>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sl, warnings := parseSyslogConfig(t, syslogModel("1.0.3", "31", tt.destination))

			assert.False(t, sl.Enabled)
			assert.Empty(t, sl.RemoteServer)
			assert.False(t, sl.FilterLogging)
			assert.Len(t, sl.Destinations, tt.wantListed)
			assert.Len(t, syslogWarnings(warnings), tt.wantWarnings)
		})
	}
}

// TestConverter_Syslog_DestinationFilters checks which logging flags a
// filtered target proves. The template ANDs the filters, so a facility filter,
// or a level filter that drops more than debug, proves no category.
func TestConverter_Syslog_DestinationFilters(t *testing.T) {
	t.Parallel()

	type flags struct{ system, auth, filter, dhcp, vpn bool }

	tests := []struct {
		name                     string
		program, level, facility string
		want                     flags
	}{
		{name: "no filter forwards every category", want: flags{true, true, true, true, true}},
		{
			name:  "level filter without debug keeps every event",
			level: "info,notice,warn,err,crit,alert,emerg",
			want:  flags{true, true, true, true, true},
		},
		{name: "level filter dropping info proves nothing", level: "warn,err,crit,alert,emerg"},
		{name: "facility filter proves nothing", facility: "auth,authpriv"},
		{name: "filterlog program proves filter logging only", program: "filterlog", want: flags{filter: true}},
		{
			name:    "program list maps each entry",
			program: "dhcpd,openvpn",
			want:    flags{dhcp: true, vpn: true},
		},
		{name: "program with facility filter proves nothing", program: "filterlog", facility: "local0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A target with no filter would set every flag, so it must stay
			// out of this config; the filtered one sits second.
			destinations := syslogDestination("a1", "0", "udp4", "", "", "", "10.0.0.7") +
				syslogDestination("b2", "1", "udp4", tt.program, tt.level, tt.facility, "10.0.0.50")
			sl, _ := parseSyslogConfig(t, syslogModel("1.0.3", "31", destinations))

			assert.True(t, sl.Enabled)
			assert.Equal(t, "10.0.0.50", sl.RemoteServer)
			got := flags{sl.SystemLogging, sl.AuthLogging, sl.FilterLogging, sl.DHCPLogging, sl.VPNLogging}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestConverter_Syslog_FourDestinations keeps every forwarding target in
// Destinations while the flat fields hold the first three.
func TestConverter_Syslog_FourDestinations(t *testing.T) {
	t.Parallel()

	var destinations strings.Builder
	for _, host := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		destinations.WriteString(syslogDestination(host, "1", "udp4", "", "", "", host))
	}

	sl, _ := parseSyslogConfig(t, syslogModel("1.0.3", "31", destinations.String()))

	assert.Equal(t, "10.0.0.1", sl.RemoteServer)
	assert.Equal(t, "10.0.0.2", sl.RemoteServer2)
	assert.Equal(t, "10.0.0.3", sl.RemoteServer3)
	require.Len(t, sl.Destinations, 4)
	assert.Equal(t, "10.0.0.4", sl.Destinations[3].Hostname)
}

// TestConverter_Syslog_Retention reads retention from where each release keeps
// it: the legacy <syslog> keys up to 24.1 (model 1.0.0 and 1.0.1), the model's
// maxpreserve from 24.7, which leaves the legacy keys behind.
func TestConverter_Syslog_Retention(t *testing.T) {
	t.Parallel()

	const legacyRetention = `<syslog><logfilesize>512000</logfilesize><preservelogs>14</preservelogs></syslog>`

	tests := []struct {
		name         string
		inner        string
		wantRotate   string
		wantFileSize string
	}{
		{
			name:       "24.7 and later read maxpreserve and ignore the legacy keys",
			inner:      legacyRetention + syslogModel("1.0.3", "31", ""),
			wantRotate: "31",
		},
		{
			name:       "1.0.2 is the first model version with retention",
			inner:      legacyRetention + syslogModel("1.0.2", "60", ""),
			wantRotate: "60",
		},
		{
			name:         "24.1 reads the legacy keys",
			inner:        legacyRetention + `<OPNsense><Syslog version="1.0.1"><general><enabled>1</enabled></general><destinations/></Syslog></OPNsense>`,
			wantRotate:   "14",
			wantFileSize: "512000",
		},
		{
			name:         "no model reads the legacy keys",
			inner:        legacyRetention,
			wantRotate:   "14",
			wantFileSize: "512000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sl, _ := parseSyslogConfig(t, tt.inner)

			assert.Equal(t, tt.wantRotate, sl.RotateCount)
			assert.Equal(t, tt.wantFileSize, sl.LogFileSize)
		})
	}
}

// TestConverter_Syslog_UnknownModelVersionWarns pins the model version, as
// GOTCHAS 3.7 asks for a model the converter reads.
func TestConverter_Syslog_UnknownModelVersionWarns(t *testing.T) {
	t.Parallel()

	_, warnings := parseSyslogConfig(t, syslogModel("1.0.9", "31", ""))

	got := syslogWarnings(warnings)
	require.Len(t, got, 1)
	assert.Equal(t, "Syslog.Version", got[0].Field)
	assert.Equal(t, "1.0.9", got[0].Value)
}

// TestConverter_Syslog_SampleConfig5 reads the retention a 24.7 config holds.
func TestConverter_Syslog_SampleConfig5(t *testing.T) {
	t.Parallel()

	f, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml"))
	require.NoError(t, err)
	defer f.Close()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(context.Background(), f, common.DeviceTypeUnknown, false)
	require.NoError(t, err)

	assert.Equal(t, "31", device.Syslog.RotateCount)
	assert.False(t, device.Syslog.Enabled)
	assert.Empty(t, device.Syslog.Destinations)
	assert.Empty(t, syslogWarnings(warnings))
}

// TestSyslogModel_RoundTrip keeps every destination element through a decode,
// an encode and a second decode.
func TestSyslogModel_RoundTrip(t *testing.T) {
	t.Parallel()

	input := `<opnsense>` + syslogModel("1.0.3", "31",
		syslogDestination("a1", "0", "udp6", "filterlog,openvpn", "info,notice", "auth", "fd00::9")+
			syslogDestination("b2", "1", "tls4", "", "", "", "10.0.0.50"),
	) + `</opnsense>`

	var first schema.OpnSenseDocument
	require.NoError(t, xml.Unmarshal([]byte(input), &first))

	encoded, err := xml.Marshal(&first)
	require.NoError(t, err)

	var second schema.OpnSenseDocument
	require.NoError(t, xml.Unmarshal(encoded, &second))

	want := first.OPNsense.SyslogInternal
	got := second.OPNsense.SyslogInternal
	require.Len(t, got.Destinations.Destination, 2)
	assert.Equal(t, want.Version, got.Version)
	assert.Equal(t, want.General.Maxpreserve, got.General.Maxpreserve)
	assert.Equal(t, want.Destinations, got.Destinations)
	assert.Equal(t, schema.SyslogDestination{
		UUID: "a1", Enabled: "0", Transport: "udp6", Program: "filterlog,openvpn", Level: "info,notice",
		Facility: "auth", Hostname: "fd00::9", Port: "6514", RFC5424: "0", Suppress: "0", Description: "siem",
	}, got.Destinations.Destination[0])
}
