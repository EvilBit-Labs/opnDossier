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
// filtered target proves. Filter logging follows what filterlog writes:
// program filterlog, facility local0, level info. The other categories count
// only when no facility filter is set and the level filter drops at most
// debug.
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
		{
			name:  "level filter without emerg keeps filterlog's info entries",
			level: "info,notice,warn,err,crit,alert",
			want:  flags{filter: true},
		},
		{name: "level filter dropping info drops filterlog", level: "warn,err,crit,alert,emerg"},
		{name: "emerg alone drops filterlog", level: "emerg"},
		{name: "facility filter without local0 drops filterlog", facility: "auth,authpriv"},
		{name: "local0 facility keeps filterlog", facility: "local0", want: flags{filter: true}},
		{name: "filterlog program proves filter logging only", program: "filterlog", want: flags{filter: true}},
		{name: "other program drops filterlog", program: "ntpd"},
		{name: "program entry matches as a pattern", program: "ntpd,filter", want: flags{filter: true}},
		{name: "invalid pattern admits nothing", program: "filter(log"},
		{
			name:    "program list maps each entry",
			program: "dhcpd,openvpn",
			want:    flags{dhcp: true, vpn: true},
		},
		{name: "every filter must admit filterlog", program: "filterlog", facility: "local0", level: "err"},
		{
			name:     "filterlog through all three filters",
			program:  "filterlog",
			facility: "local0",
			level:    "info",
			want:     flags{filter: true},
		},
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

// TestConverter_Syslog_LegacyLogAll covers 19.7's logall, which forwarded every
// message whatever the category flags held.
func TestConverter_Syslog_LegacyLogAll(t *testing.T) {
	t.Parallel()

	sl, _ := parseSyslogConfig(t,
		`<syslog><remoteserver>10.0.0.9</remoteserver><enable>1</enable><logall>1</logall></syslog>`)

	assert.True(t, sl.Enabled)
	assert.True(t, sl.FilterLogging)
	assert.True(t, sl.AuthLogging)
	assert.True(t, sl.SystemLogging)

	// 19.7 tests logall with helpers.empty, which reads 0 and an empty element
	// as unset.
	sl, _ = parseSyslogConfig(t,
		`<syslog><remoteserver>10.0.0.9</remoteserver><enable>1</enable><logall>0</logall></syslog>`)

	assert.False(t, sl.FilterLogging)

	sl, _ = parseSyslogConfig(t,
		`<syslog><remoteserver>10.0.0.9</remoteserver><enable>1</enable><logall/></syslog>`)

	assert.False(t, sl.FilterLogging)
}

// TestConverter_Syslog_LegacyRemoteWarning warns only for legacy keys that
// name a server: <enable> alone forwarded nowhere, even on 19.7.
func TestConverter_Syslog_LegacyRemoteWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		legacy string
		want   int
	}{
		{name: "nothing set", legacy: `<syslog><nologdefaultpass>1</nologdefaultpass></syslog>`},
		{name: "enable without a server", legacy: `<syslog><enable>1</enable></syslog>`},
		{name: "server without enable", legacy: `<syslog><remoteserver2>10.0.0.8</remoteserver2></syslog>`, want: 1},
		{name: "enable switched off", legacy: `<syslog><enable>0</enable></syslog>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, warnings := parseSyslogConfig(t, tt.legacy+syslogModel("1.0.3", "31", ""))

			assert.Len(t, syslogWarnings(warnings), tt.want)
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

// TestConverter_Syslog_Retention reads the retention each release applies,
// defaults included: a circular log of 511488 bytes unless <logfilesize> says
// otherwise up to 21.7 (no model, or model 1.0.0), 31 daily archives unless
// <preservelogs> says otherwise from 20.7 to 24.1, and the model's maxpreserve
// and maxfilesize from 24.7. A key the release does not read draws a Low
// warning.
func TestConverter_Syslog_Retention(t *testing.T) {
	t.Parallel()

	model101 := `<OPNsense><Syslog version="1.0.1"><general><enabled>1</enabled></general>` +
		`<destinations/></Syslog></OPNsense>`
	model100 := strings.Replace(model101, "1.0.1", "1.0.0", 1)
	model103 := func(maxpreserve, maxfilesize string) string {
		return strings.Replace(syslogModel("1.0.3", maxpreserve, ""), "<maxfilesize/>",
			"<maxfilesize>"+maxfilesize+"</maxfilesize>", 1)
	}

	tests := []struct {
		name         string
		inner        string
		wantRotate   string
		wantFileSize string
		wantWarnings []string
	}{
		{
			name:         "26.7 reads maxpreserve and maxfilesize in MB",
			inner:        model103("45", "10"),
			wantRotate:   "45",
			wantFileSize: "10485760",
		},
		{
			name:       "26.7 empty maxpreserve takes the model default",
			inner:      model103("", ""),
			wantRotate: "31",
		},
		{
			name: "26.7 ignores a stale clog size and a legacy value it migrated",
			inner: `<syslog><logfilesize>512000</logfilesize><preservelogs>45</preservelogs></syslog>` + model103(
				"45",
				"",
			),
			wantRotate:   "45",
			wantWarnings: []string{"logfilesize=512000"},
		},
		{
			name: "26.7 reports a legacy value that disagrees with the model",
			inner: `<syslog><preservelogs>14</preservelogs><maxfilesize>5</maxfilesize></syslog>` + model103(
				"45",
				"10",
			),
			wantRotate:   "45",
			wantFileSize: "10485760",
			wantWarnings: []string{"preservelogs=14", "maxfilesize=5"},
		},
		{
			name:       "1.0.2 is the first model version with retention",
			inner:      syslogModel("1.0.2", "60", ""),
			wantRotate: "60",
		},
		{
			name:       "24.1 with nothing set keeps 31 archives",
			inner:      `<syslog><nologdefaultblock>1</nologdefaultblock></syslog>` + model101,
			wantRotate: "31",
		},
		{
			name:         "24.1 reads preservelogs and maxfilesize",
			inner:        `<syslog><preservelogs>14</preservelogs><maxfilesize>10</maxfilesize></syslog>` + model101,
			wantRotate:   "14",
			wantFileSize: "10485760",
		},
		{
			name:         "24.1 ignores a stale clog size",
			inner:        `<syslog><logfilesize>512000</logfilesize></syslog>` + model101,
			wantRotate:   "31",
			wantWarnings: []string{"logfilesize=512000"},
		},
		{
			name:         "1.0.0 reads the circular log size",
			inner:        `<syslog><logfilesize>512000</logfilesize></syslog>` + model100,
			wantFileSize: "512000",
		},
		{
			name:         "1.0.0 without a size takes the circular log default",
			inner:        model100,
			wantFileSize: "511488",
		},
		{
			name:       "1.0.0 with circular logs off keeps 31 archives",
			inner:      `<syslog><disable_clog>1</disable_clog><logfilesize>512000</logfilesize></syslog>` + model100,
			wantRotate: "31",
		},
		{
			name:         "no model reads the circular log size",
			inner:        `<syslog><logfilesize>512000</logfilesize></syslog>`,
			wantFileSize: "512000",
		},
		{
			name:       "preservelogs wins over pfSense's rotatecount",
			inner:      `<syslog><rotatecount>7</rotatecount><preservelogs>14</preservelogs></syslog>`,
			wantRotate: "14",
		},
		{
			name:       "rotatecount is read when preservelogs is absent",
			inner:      `<syslog><rotatecount>7</rotatecount></syslog>`,
			wantRotate: "7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sl, warnings := parseSyslogConfig(t, tt.inner)

			assert.Equal(t, tt.wantRotate, sl.RotateCount)
			assert.Equal(t, tt.wantFileSize, sl.LogFileSize)

			var got []string
			for _, w := range syslogWarnings(warnings) {
				got = append(got, w.Value)
			}
			assert.Equal(t, tt.wantWarnings, got)
		})
	}
}

// TestConverter_Syslog_NoRetentionReported leaves retention unset while no
// local log is kept, and when a config without the Syslog model sets none:
// syslog-ng-local.conf writes local logs only when loglocal is 1 from 24.7;
// on 22.1 to 24.1 a <disablelocallogging> that helpers.empty reads as set
// turns them off, and up to 21.7 any <disablelocallogging>, 0 included, does
// (isset() in system.inc). Without the model the release, and so its
// default, is unknown.
func TestConverter_Syslog_NoRetentionReported(t *testing.T) {
	t.Parallel()

	model103 := strings.Replace(syslogModel("1.0.3", "45", ""), "<maxfilesize/>", "<maxfilesize>10</maxfilesize>", 1)
	model101 := `<OPNsense><Syslog version="1.0.1"><general><enabled>1</enabled></general>` +
		`<destinations/></Syslog></OPNsense>`
	model100 := strings.Replace(model101, "1.0.1", "1.0.0", 1)

	tests := map[string]string{
		"26.7 with loglocal 0":        strings.Replace(model103, "<loglocal>1</loglocal>", "<loglocal>0</loglocal>", 1),
		"26.7 without loglocal":       strings.Replace(model103, "<loglocal>1</loglocal>", "", 1),
		"24.1 disabled":               `<syslog><disablelocallogging>1</disablelocallogging><preservelogs>14</preservelogs></syslog>` + model101,
		"1.0.0 empty element":         `<syslog><disablelocallogging/></syslog>` + model100,
		"1.0.0 with 0 in it":          `<syslog><disablelocallogging>0</disablelocallogging></syslog>` + model100,
		"no model empty element":      `<syslog><disablelocallogging/><logfilesize>512000</logfilesize></syslog>`,
		"no model invents no default": `<syslog><nologdefaultblock>1</nologdefaultblock></syslog>`,
		"no model with 0 in it":       `<syslog><disablelocallogging>0</disablelocallogging><logfilesize>512000</logfilesize></syslog>`,
	}

	for name, inner := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sl, _ := parseSyslogConfig(t, inner)

			assert.Empty(t, sl.RotateCount)
			assert.Empty(t, sl.LogFileSize)
		})
	}
}

// TestConverter_Syslog_LegacyFlagsReadAsTheReleaseDoes pins the flags that
// helpers.empty or PHP empty() read: an empty element and 0 are unset there,
// unlike the isset() tests of 21.7 and earlier.
func TestConverter_Syslog_LegacyFlagsReadAsTheReleaseDoes(t *testing.T) {
	t.Parallel()

	model101 := `<OPNsense><Syslog version="1.0.1"><general><enabled>1</enabled></general>` +
		`<destinations/></Syslog></OPNsense>`
	model100 := strings.Replace(model101, "1.0.1", "1.0.0", 1)

	tests := []struct {
		name         string
		inner        string
		wantRotate   string
		wantFileSize string
	}{
		{
			name:       "24.1 disablelocallogging 0 keeps local logs",
			inner:      `<syslog><disablelocallogging>0</disablelocallogging></syslog>` + model101,
			wantRotate: "31",
		},
		{
			name:       "24.1 empty disablelocallogging keeps local logs",
			inner:      `<syslog><disablelocallogging/></syslog>` + model101,
			wantRotate: "31",
		},
		{
			name:       "24.1 disablelocallogging 0 with spaces keeps local logs",
			inner:      `<syslog><disablelocallogging> 0 </disablelocallogging></syslog>` + model101,
			wantRotate: "31",
		},
		{
			name:         "1.0.0 disable_clog 0 keeps circular logs",
			inner:        `<syslog><disable_clog>0</disable_clog></syslog>` + model100,
			wantFileSize: "511488",
		},
		{
			name:         "1.0.0 empty disable_clog keeps circular logs",
			inner:        `<syslog><disable_clog/></syslog>` + model100,
			wantFileSize: "511488",
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

// TestConverter_Syslog_ModelWithoutVersion reads a model with no version
// attribute as the current one: destinations count, retention comes from the
// model, and no version warning is raised.
func TestConverter_Syslog_ModelWithoutVersion(t *testing.T) {
	t.Parallel()

	inner := strings.Replace(
		syslogModel("", "45", syslogDestination("b2", "1", "udp4", "", "", "", "10.0.0.50")),
		` version=""`, "", 1,
	)
	sl, warnings := parseSyslogConfig(t, `<syslog><preservelogs>14</preservelogs></syslog>`+inner)

	assert.True(t, sl.Enabled)
	assert.Equal(t, "10.0.0.50", sl.RemoteServer)
	assert.Equal(t, "45", sl.RotateCount)
	for _, w := range syslogWarnings(warnings) {
		assert.NotEqual(t, "Syslog.Version", w.Field)
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

// roundTrip holds a document as first decoded and as decoded again after an
// encode.
type roundTrip struct {
	first, second schema.OpnSenseDocument
}

// roundTripDocument decodes, encodes and decodes a document again.
func roundTripDocument(t *testing.T, input string) roundTrip {
	t.Helper()

	var rt roundTrip
	require.NoError(t, xml.Unmarshal([]byte(input), &rt.first))

	encoded, err := xml.Marshal(&rt.first)
	require.NoError(t, err)
	require.NoError(t, xml.Unmarshal(encoded, &rt.second))

	return rt
}

// TestSyslogModel_RoundTrip keeps every destination element through a decode,
// an encode and a second decode.
func TestSyslogModel_RoundTrip(t *testing.T) {
	t.Parallel()

	rt := roundTripDocument(t, `<opnsense>`+syslogModel("1.0.3", "31",
		syslogDestination("a1", "0", "udp6", "filterlog,openvpn", "info,notice", "auth", "fd00::9")+
			syslogDestination("b2", "1", "tls4", "", "", "", "10.0.0.50"),
	)+`</opnsense>`)

	want := rt.first.OPNsense.SyslogInternal
	got := rt.second.OPNsense.SyslogInternal
	require.NotNil(t, got)
	require.Len(t, got.Destinations.Destination, 2)
	assert.Equal(t, want, got)
	assert.Equal(t, schema.SyslogDestination{
		UUID: "a1", Enabled: "0", Transport: "udp6", Program: "filterlog,openvpn", Level: "info,notice",
		Facility: "auth", Hostname: "fd00::9", Port: "6514", RFC5424: "0", Suppress: "0", Description: "siem",
	}, got.Destinations.Destination[0])
}

// TestSyslogModel_LegacyOnlyRoundTrip keeps a config with no Syslog model
// without one after an encode, so the legacy remote keys stay the ones read.
func TestSyslogModel_LegacyOnlyRoundTrip(t *testing.T) {
	t.Parallel()

	rt := roundTripDocument(t, `<opnsense>`+legacyRemoteSyslog+
		`</opnsense>`)

	assert.Nil(t, rt.first.OPNsense.SyslogInternal)
	assert.Nil(t, rt.second.OPNsense.SyslogInternal)
	assert.Equal(t, rt.first.Syslog.Remoteserver, rt.second.Syslog.Remoteserver)

	encoded, err := xml.Marshal(&rt.second)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "<Syslog")

	sl, _ := parseSyslogConfig(t, legacyRemoteSyslog)
	assert.True(t, sl.Enabled)
}

// TestSyslogLegacy_RetentionRoundTrip keeps the legacy retention keys through
// an encode.
func TestSyslogLegacy_RetentionRoundTrip(t *testing.T) {
	t.Parallel()

	rt := roundTripDocument(t, `<opnsense><syslog><preservelogs>14</preservelogs>`+
		`<maxfilesize>10</maxfilesize><disable_clog>1</disable_clog><logall>1</logall><disablelocallogging/></syslog></opnsense>`)

	assert.Equal(t, "14", rt.second.Syslog.PreserveLogs)
	assert.Equal(t, "10", rt.second.Syslog.MaxFileSize)
	assert.Equal(t, "1", rt.second.Syslog.DisableClog)
	assert.Equal(t, "1", rt.second.Syslog.LogAll)
	require.NotNil(t, rt.second.Syslog.DisableLocalLogging)
	assert.Equal(t, rt.first.Syslog, rt.second.Syslog)
}
