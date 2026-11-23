package analysis_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// anyPortPfSenseConfig is a pfSense config whose port alias Feed is a URL
// table of ports, which the analysis cannot read. Rule 0 and rule 1 are the
// pair under test, on the interface {{IFACE}}; the trailing pass keeps rule 1
// from being the terminal deny.
const anyPortPfSenseConfig = `<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>fw</hostname><domain>internal</domain></system>
  <interfaces>
    <wan><enable/><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
    <lan><enable/><if>vtnet1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <aliases>
    <alias>
      <name>Feed</name><type>urltable_ports</type><url>https://example.org/ports</url>
      <updatefreq>1</updatefreq><address></address><descr>feed</descr>
    </alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type><interface>{{IFACE}}</interface><ipprotocol>inet</ipprotocol>
      <protocol>{{PROTO0}}</protocol>
      <source>{{SOURCE0}}</source><destination><any/></destination>
      <descr>pass to every port</descr><tracker>1</tracker>
    </rule>
    <rule>
      <type>block</type><interface>{{IFACE}}</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source>{{SOURCE1}}</source><destination><any/><port>Feed</port></destination>
      <descr>block to the feed</descr><tracker>2</tracker>
    </rule>
    <rule>
      <type>pass</type><interface>{{IFACE}}</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><any/><port>53</port></destination>
      <descr>trailing pass</descr><tracker>3</tracker>
    </rule>
  </filter>
</pfsense>`

// TestDetectShadowedRules_AnyPortPassOverUnreadablePortAlias drives a pass to
// every port above a block to a port alias the analysis cannot read through
// parse, convert and the shadow analysis. Every port covers whatever the alias
// holds, so the pair is a confirmed shadow when every other dimension is
// covered. When another dimension cannot be compared, such as a combined
// protocol, an interface network or a narrower or negated network against
// any, the pair is the low-confidence R8 advisory. A dimension proven
// disjoint keeps it silent.
func TestDetectShadowedRules_AnyPortPassOverUnreadablePortAlias(t *testing.T) {
	t.Parallel()

	const anySource = "<any/>"

	tests := []struct {
		name             string
		iface            string
		proto0           string
		source0, source1 string
		wantSeverity     common.Severity
		wantConfidence   common.Confidence
	}{
		{
			name:  "every other dimension covered",
			iface: "wan", proto0: "tcp", source0: anySource, source1: anySource,
			wantSeverity: common.SeverityCritical, wantConfidence: common.ConfidenceHigh,
		},
		{
			name:  "combined protocol",
			iface: "wan", proto0: "tcp/udp", source0: anySource, source1: anySource,
			wantSeverity: common.SeverityHigh, wantConfidence: common.ConfidenceLow,
		},
		{
			name:    "interface network against a host inside it",
			iface:   "lan",
			proto0:  "tcp",
			source0: "<network>lan</network>", source1: "<address>192.168.1.50</address>",
			wantSeverity: common.SeverityMedium, wantConfidence: common.ConfidenceLow,
		},
		{
			name:    "narrower network against any",
			iface:   "wan",
			proto0:  "tcp",
			source0: "<address>10.0.0.0/8</address>", source1: anySource,
			wantSeverity: common.SeverityHigh, wantConfidence: common.ConfidenceLow,
		},
		{
			name:    "negated network against any",
			iface:   "wan",
			proto0:  "tcp",
			source0: "<not/><address>10.0.0.0/8</address>", source1: anySource,
			wantSeverity: common.SeverityHigh, wantConfidence: common.ConfidenceLow,
		},
		{
			name:  "other single protocol",
			iface: "wan", proto0: "udp", source0: anySource, source1: anySource,
		},
		{
			name:    "other literal network",
			iface:   "wan",
			proto0:  "tcp",
			source0: "<address>10.0.0.0/8</address>", source1: "<address>192.168.0.0/16</address>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			xmlData := strings.NewReplacer(
				"{{IFACE}}", tt.iface,
				"{{PROTO0}}", tt.proto0,
				"{{SOURCE0}}", tt.source0,
				"{{SOURCE1}}", tt.source1,
			).Replace(anyPortPfSenseConfig)

			device := parsePfSenseFeedDevice(t, xmlData)

			finding, ok := findSecondShadowedByFirst(analysis.DetectShadowedRules(device))
			if tt.wantConfidence == "" {
				assert.False(t, ok, "a dimension proven disjoint keeps the pair silent")

				return
			}

			require.True(t, ok, "the block below the pass must be reported")
			assert.Equal(t, common.ShadowKindFull, finding.Kind)
			assert.Equal(t, common.ImpactClassSecurity, finding.ImpactClass)
			assert.Equal(t, tt.wantSeverity, finding.Severity)
			assert.Equal(t, tt.wantConfidence, finding.Confidence)
		})
	}
}

func parsePfSenseFeedDevice(t *testing.T, xmlData string) *common.CommonDevice {
	t.Helper()

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(), strings.NewReader(xmlData), common.DeviceTypePfSense, false,
	)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 3)
	require.Contains(t, device.NamedObjects, "Feed")
	require.NotNil(t, device.FirewallRules[1].Destination.PortRef, "the block names the alias")

	return device
}
