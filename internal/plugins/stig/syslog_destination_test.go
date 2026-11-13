package stig_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trafficLogControls are the controls that ask what the forwarded traffic log
// records.
var trafficLogControls = []string{"V-206678", "V-206679", "V-206680", "V-206681"}

// TestPlugin_TrafficLogControls_FollowSyslogDestination drives an OPNsense
// Syslog model through the parser: a destination whose filters drop
// filterlog's entries forwards no traffic log, so the controls fail.
func TestPlugin_TrafficLogControls_FollowSyslogDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		program, level  string
		wantNoncomplied bool
	}{
		{name: "destination with no filter", wantNoncomplied: false},
		{name: "destination for ntpd only", program: "ntpd", wantNoncomplied: true},
		{name: "destination for emerg only", level: "emerg", wantNoncomplied: true},
		{name: "destination without emerg keeps filterlog", level: "info,notice,warn,err,crit,alert"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := parseSyslogDestination(t, tt.program, tt.level)
			findings, _, err := stig.NewPlugin().RunChecks(device)
			require.NoError(t, err)

			for _, id := range trafficLogControls {
				found := false
				for _, f := range findings {
					if f.Reference == "STIG "+id {
						found = true
					}
				}
				assert.Equal(t, tt.wantNoncomplied, found, id)
			}
		})
	}
}

// parseSyslogDestination parses a config with one enabled udp4 destination
// carrying the given program and level filters.
func parseSyslogDestination(t *testing.T, program, level string) *common.CommonDevice {
	t.Helper()

	config := `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>vtnet0</if></wan><lan><if>vtnet1</if></lan></interfaces>
  <OPNsense><Syslog version="1.0.3">
    <general><enabled>1</enabled><loglocal>1</loglocal><maxpreserve>31</maxpreserve><maxfilesize/></general>
    <destinations><destination uuid="b2">
      <enabled>1</enabled><transport>udp4</transport>
      <program>` + program + `</program><level>` + level + `</level><facility/>
      <hostname>10.0.0.50</hostname><certificate/><port>514</port>
      <rfc5424>0</rfc5424><suppress>0</suppress><description/>
    </destination></destinations>
  </Syslog></OPNsense>
</opnsense>`

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false,
	)
	require.NoError(t, err)
	require.True(t, device.Syslog.Enabled)

	return device
}
