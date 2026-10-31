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

const (
	idsModeWarning = "IDS.General.Mode"
	idsIPSWarning  = "IDS.General.Ips"
)

// idsInterfaces holds one interface of each kind the divert rule check tells apart:
// wan is in service, opt1 has Enable unticked, opt2 has no device, opt3 shows that
// OPNsense tests <enable> for presence rather than value, and opt4 holds the empty
// element, which reads as unset here.
const idsInterfaces = `<interfaces>
    <wan><enable>1</enable><if>em0</if></wan>
    <opt1><if>em1</if></opt1>
    <opt2><enable>1</enable></opt2>
    <opt3><enable>0</enable><if>em3</if></opt3>
    <opt4><enable/><if>em4</if></opt4>
  </interfaces>`

// idsFixture holds the parts of a config the IDS tests vary.
type idsFixture struct {
	// version is the <IDS> version attribute, left out when empty.
	version string
	// general holds more children of <general>.
	general string
	// model holds more children of <OPNsense>.
	model string
	// root holds more children of <opnsense>.
	root string
	// off writes <enabled>0</enabled> rather than 1.
	off bool
}

// parseIDsFixture runs the config f describes through the full parser pipeline.
func parseIDsFixture(t *testing.T, f idsFixture) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	attr := ""
	if f.version != "" {
		attr = fmt.Sprintf(" version=%q", f.version)
	}

	enabled := "1"
	if f.off {
		enabled = "0"
	}

	config := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  %s
  %s
  <OPNsense>
    %s
    <IDS%s>
      <general><enabled>%s</enabled>%s<interfaces>wan</interfaces></general>
    </IDS>
  </OPNsense>
</opnsense>`, idsInterfaces, f.root, f.model, attr, enabled, f.general)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, warnings, err := factory.CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.NotNil(t, device.IDS)

	return device, warnings
}

// parseIDs parses a config whose <IDS> carries version and the given <general>
// children.
func parseIDs(t *testing.T, version, general string) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	return parseIDsFixture(t, idsFixture{version: version, general: general})
}

// idsWarnings returns the warnings on the <IDS> element, leaving out those a
// fixture's firewall rules draw.
func idsWarnings(warnings []common.ConversionWarning) []common.ConversionWarning {
	var result []common.ConversionWarning

	for _, warning := range warnings {
		if strings.HasPrefix(warning.Field, "IDS.") {
			result = append(result, warning)
		}
	}

	return result
}

// idsFilterRules returns a filter model holding rules.
func idsFilterRules(rules string) string {
	return `<Firewall><Filter version="1.0.6"><rules>` + rules + `</rules></Filter></Firewall>`
}

// TestConverter_IDS_Mode pins IPS mode across the OPNsense 26.1 change: IDS
// model 1.1.2 replaced <ips> with <mode>, its migration drops <ips>, and its
// templates run pcap without <mode> whatever <ips> holds. An older model is read
// from <ips>, and a <mode> there warns, because the firewall that wrote one reads
// it: a failed migration followed by a save keeps the older version. An <ips> on
// model 1.1.2 warns for the opposite case, a 26.1 config restored onto an older
// release. A config without a version reads <mode>, then <ips>. Divert has its own
// test, since it also depends on the firewall rules.
func TestConverter_IDS_Mode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version  string
		general  string
		want     bool
		wantWarn string
	}{
		{"1.1.2", `<mode>netmap</mode>`, true, ""},
		{"1.1.2", `<mode>pcap</mode>`, false, ""},
		{"1.1.2", `<ips>1</ips>`, false, idsIPSWarning},
		{"1.1.2", `<ips>0</ips>`, false, ""},
		{"1.1.2", `<mode/><ips>1</ips>`, false, idsIPSWarning},
		{"1.1.2", `<mode>pcap</mode><ips>1</ips>`, false, ""},
		{"1.1.1", `<ips>1</ips>`, true, ""},
		{"1.1.1", `<ips>0</ips>`, false, ""},
		{"1.1.1", `<mode>netmap</mode><ips>0</ips>`, false, idsModeWarning},
		{"1.1.1", `<mode>netmap</mode>`, false, idsModeWarning},
		{"1.1.1", `<mode>divert</mode>`, false, idsModeWarning},
		{"1.1.1", `<mode>pcap</mode><ips>1</ips>`, true, idsModeWarning},
		{"1.1.1", `<mode>afpacket</mode><ips>1</ips>`, true, idsModeWarning},
		{"", `<mode>netmap</mode><ips>0</ips>`, true, ""},
		{"", `<mode>pcap</mode><ips>1</ips>`, false, ""},
		{"", `<ips>1</ips>`, true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.version+" "+tc.general, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDs(t, tc.version, tc.general)
			assert.True(t, device.IDS.Enabled)
			assert.Equal(t, tc.want, device.IDS.IPSMode)

			if tc.wantWarn == "" {
				assert.Empty(t, warnings)

				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, tc.wantWarn, warnings[0].Field)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
			assert.NotEmpty(t, warnings[0].Value)
			assert.NotEmpty(t, warnings[0].Message)
		})
	}
}

// TestConverter_IDS_DivertMode pins that divert reads as IPS only with a rule that
// sends Suricata traffic. Without one Suricata receives nothing, so reporting IPS
// would claim blocking that does not happen. A rule counts when it is enabled, passes
// traffic, targets port 8000 and leaves a pf rule behind: OPNsense comments out a rule
// on an interface it has not mapped to a device, which takes both <enable> and <if>,
// and of two rules with one uuid keeps the later. One such rule is enough, wherever
// it stands in the list.
func TestConverter_IDS_DivertMode(t *testing.T) {
	t.Parallel()

	const divert = `<divert-to>8000</divert-to>`

	on := func(iface string) string {
		return `<rule><interface>` + iface + `</interface>` + divert + `</rule>`
	}
	receivedOn := func(list string) string {
		return `<rule><interface>wan</interface><received-on>` + list + `</received-on>` + divert + `</rule>`
	}

	tests := []struct {
		name  string
		rules string
		root  string
		want  bool
	}{
		{name: "no filter model"},
		{name: "rule without divert-to", rules: `<rule><description>plain</description></rule>`},
		{name: "rule takes the defaults", rules: `<rule>` + divert + `</rule>`, want: true},
		{
			name:  "enabled pass rule",
			rules: `<rule><enabled>1</enabled><action>pass</action><interface>wan</interface>` + divert + `</rule>`,
			want:  true,
		},
		{name: "empty action is pass", rules: `<rule><action/>` + divert + `</rule>`, want: true},
		{
			name:  "second rule diverts",
			rules: `<rule><description>plain</description></rule><rule>` + divert + `</rule>`,
			want:  true,
		},
		{
			name:  "first rule diverts and a plain rule follows",
			rules: `<rule>` + divert + `</rule><rule><description>plain</description></rule>`,
			want:  true,
		},
		{name: "two rules divert", rules: `<rule>` + divert + `</rule><rule>` + divert + `</rule>`, want: true},
		{name: "interface not enabled", rules: on("opt1")},
		{name: "interface with no device", rules: on("opt2")},
		{name: "enable holding 0 still counts", rules: on("opt3"), want: true},
		{name: "empty enable reads as unset", rules: on("opt4")},
		{name: "list ending in a mapped interface", rules: on("opt1,wan"), want: true},
		{name: "list starting with a mapped interface", rules: on("wan,opt1"), want: true},
		{name: "list with an empty entry", rules: on("opt1,"), want: true},
		{name: "list with no mapped interface", rules: on("opt1,opt2,opt9")},
		{name: "list entries are not trimmed", rules: on("opt1, wan")},
		{
			name:  "excluded interface not enabled",
			rules: `<rule><interface>opt1</interface><interfacenot>1</interfacenot>` + divert + `</rule>`,
		},
		{name: "rule on an unmapped interface, then one on a mapped one", rules: on("opt1") + on("wan"), want: true},
		{name: "rule on a mapped interface, then one on an unmapped one", rules: on("wan") + on("opt1"), want: true},
		{name: "received-on not enabled", rules: receivedOn("opt1")},
		{name: "received-on with no device", rules: receivedOn("opt2")},
		{name: "received-on list ending in a mapped interface", rules: receivedOn("opt1,wan"), want: true},
		{name: "received-on list with an empty entry", rules: receivedOn("opt1,"), want: true},
		{name: "empty received-on", rules: receivedOn(""), want: true},
		{name: "disabled rule", rules: `<rule><enabled>0</enabled>` + divert + `</rule>`},
		{name: "empty enabled element", rules: `<rule><enabled/>` + divert + `</rule>`},
		{
			name:  "disabled divert rule beside an enabled plain one",
			rules: `<rule><description>plain</description></rule><rule><enabled>0</enabled>` + divert + `</rule>`,
		},
		{name: "block rule", rules: `<rule><action>block</action>` + divert + `</rule>`},
		{name: "reject rule", rules: `<rule><action>reject</action>` + divert + `</rule>`},
		{name: "another port", rules: `<rule><divert-to>9000</divert-to></rule>`},
		{name: "empty divert-to", rules: `<rule><divert-to/><description>plain</description></rule>`},
		{name: "divert-to is compared as written", rules: `<rule><divert-to> 8000 </divert-to></rule>`},
		{name: "undefined interface", rules: `<rule><interface>opt9</interface>` + divert + `</rule>`},
		{name: "undefined received-on", rules: `<rule><received-on>opt9</received-on>` + divert + `</rule>`},
		{
			name:  "replaced by a later rule with its uuid",
			rules: `<rule uuid="a">` + divert + `</rule><rule uuid="a"><description>plain</description></rule>`,
		},
		{
			name:  "replaces an earlier rule with its uuid",
			rules: `<rule uuid="a"><description>plain</description></rule><rule uuid="a">` + divert + `</rule>`,
			want:  true,
		},
		{
			name: "legacy rule is not searched",
			root: `<filter><rule><type>pass</type><interface>wan</interface>` + divert + `</rule></filter>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := idsFixture{
				version: "1.1.2",
				general: `<mode>divert</mode><promisc>1</promisc><homenet>10.0.0.0/8</homenet>`,
				root:    tc.root,
			}
			if tc.rules != "" {
				fixture.model = idsFilterRules(tc.rules)
			}

			device, warnings := parseIDsFixture(t, fixture)
			assert.Equal(t, tc.want, device.IDS.IPSMode)
			assert.True(t, device.IDS.Enabled)

			// Neither setting reaches Suricata in this mode, with or without a rule.
			assert.Empty(t, device.IDS.Interfaces)
			assert.False(t, device.IDS.Promiscuous)
			assert.Equal(t, []string{"10.0.0.0/8"}, device.IDS.HomeNetworks)

			found := idsWarnings(warnings)
			if tc.want {
				assert.Empty(t, found)

				return
			}

			require.Len(t, found, 1)
			assert.Equal(t, idsModeWarning, found[0].Field)
			assert.Equal(t, "divert", found[0].Value)
			assert.Equal(t, common.SeverityHigh, found[0].Severity)
			assert.NotEmpty(t, found[0].Message)
		})
	}
}

// TestConverter_IDS_OtherModesKeepInterfaces pins that only a model reading
// <mode>divert</mode> drops the interface settings, and that a divert-to rule
// changes nothing in another mode. Model 1.1.1 is read from <ips>, so its stray
// <mode>divert</mode> leaves the interfaces reported, as a release shipping that
// model monitors them.
func TestConverter_IDS_OtherModesKeepInterfaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		general string
		wantIPS bool
	}{
		{"netmap", "1.1.2", `<mode>netmap</mode>`, true},
		{"pcap", "1.1.2", `<mode>pcap</mode>`, false},
		{"stray divert on a model that predates mode", "1.1.1", `<mode>divert</mode><ips>1</ips>`, true},
	}

	for _, tc := range tests {
		for _, rules := range []string{"", `<rule><divert-to>8000</divert-to></rule>`} {
			t.Run(tc.name+" rules "+rules, func(t *testing.T) {
				t.Parallel()

				fixture := idsFixture{version: tc.version, general: tc.general + `<promisc>1</promisc>`}
				if rules != "" {
					fixture.model = idsFilterRules(rules)
				}

				device, warnings := parseIDsFixture(t, fixture)
				assert.Equal(t, tc.wantIPS, device.IDS.IPSMode)
				assert.Equal(t, []string{"wan"}, device.IDS.Interfaces)
				assert.True(t, device.IDS.Promiscuous)

				for _, warning := range idsWarnings(warnings) {
					assert.NotEqual(t, common.SeverityHigh, warning.Severity)
				}
			})
		}
	}
}

// TestConverter_IDS_DisabledEngineDrawsNoCaptureWarning pins that the warnings on
// what the engine does with traffic stay quiet while it is off.
func TestConverter_IDS_DisabledEngineDrawsNoCaptureWarning(t *testing.T) {
	t.Parallel()

	settings := `<Interfaces><settings version="1.0.0"/></Interfaces>`

	tests := []struct {
		name    string
		version string
		general string
		model   string
	}{
		{name: "divert with no rule", version: "1.1.2", general: `<mode>divert</mode>`},
		{name: "mode on a model that predates it", version: "1.1.1", general: `<mode>netmap</mode>`},
		{name: "unknown mode on a model that predates it", version: "1.1.1", general: `<mode>afpacket</mode>`},
		{name: "ips on a model that reads mode", version: "1.1.2", general: `<ips>1</ips>`},
		{name: "failed migration", version: "1.1.1", general: `<ips>1</ips>`, model: settings},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDsFixture(t, idsFixture{
				version: tc.version,
				general: tc.general,
				model:   tc.model,
				off:     true,
			})
			assert.False(t, device.IDS.Enabled)
			assert.False(t, device.IDS.IPSMode)
			assert.Empty(t, warnings)
		})
	}
}

// TestConverter_IDS_FailedMigration pins the one sign outside <IDS> of a firewall
// that ignores <ips>. The interface settings block exists only from 26.1 on, so an
// <ips> read beside it shows the IDS migration failed, and without <mode> the
// firewall runs pcap, whatever the version attribute says. A <mode> on such a
// config keeps its own warning.
func TestConverter_IDS_FailedMigration(t *testing.T) {
	t.Parallel()

	settings := `<Interfaces><settings version="1.0.0"><disablechecksumoffloading>1</disablechecksumoffloading></settings></Interfaces>`

	tests := []struct {
		name     string
		version  string
		general  string
		model    string
		want     bool
		wantWarn string
	}{
		{"ips beside the block", "1.1.1", `<ips>1</ips>`, settings, false, idsIPSWarning},
		{"ips without the block", "1.1.1", `<ips>1</ips>`, "", true, ""},
		{"ips off beside the block", "1.1.1", `<ips>0</ips>`, settings, false, ""},
		{"ips without a version beside the block", "", `<ips>1</ips>`, settings, false, idsIPSWarning},
		{"mode beside the block", "1.1.1", `<mode>netmap</mode><ips>1</ips>`, settings, true, idsModeWarning},
		{"migrated model beside the block", "1.1.2", `<mode>netmap</mode>`, settings, true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDsFixture(t, idsFixture{
				version: tc.version,
				general: tc.general,
				model:   tc.model,
			})
			assert.Equal(t, tc.want, device.IDS.IPSMode)

			if tc.wantWarn == "" {
				assert.Empty(t, warnings)

				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, tc.wantWarn, warnings[0].Field)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
			assert.NotEmpty(t, warnings[0].Value)
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
// warns on its version, and IsIPSMode reads <ips> only before 1.1.2, so 1.1.2
// warns on the <ips> alone.
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
			assert.Equal(t, tc.wantIPS, device.IDS.IPSMode)

			if tc.wantIPS {
				assert.Empty(t, warnings)

				return
			}

			require.Len(t, warnings, 1)
			assert.Equal(t, idsIPSWarning, warnings[0].Field)
		})
	}
}

// TestConverter_IDS_UnrecognizedMode warns on a <mode> outside the options of
// model 1.1.2 and reports it as IDS, as OPNsense runs it (GOTCHAS 5.2), even with
// a leftover <ips>1</ips> beside it. A config without a version is read from
// <mode>, so it warns as well. The value is wrong whether or not the engine runs,
// so unlike the warnings on what the engine does with traffic, this one stays with
// the engine off.
func TestConverter_IDS_UnrecognizedMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		mode    string
		off     bool
	}{
		{"1.1.2", "afpacket", false},
		{"1.1.2", "NETMAP", false},
		{"", "afpacket", false},
		{"1.1.2", "afpacket", true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s %s off=%t", tc.version, tc.mode, tc.off), func(t *testing.T) {
			t.Parallel()

			device, warnings := parseIDsFixture(t, idsFixture{
				version: tc.version,
				general: "<mode>" + tc.mode + "</mode><ips>1</ips>",
				off:     tc.off,
			})
			assert.Equal(t, !tc.off, device.IDS.Enabled)
			require.Len(t, warnings, 1)
			assert.Equal(t, idsModeWarning, warnings[0].Field)
			assert.Equal(t, tc.mode, warnings[0].Value)
			assert.Equal(t, common.SeverityMedium, warnings[0].Severity)
			assert.NotEmpty(t, warnings[0].Message)
			assert.False(t, device.IDS.IPSMode)
		})
	}
}
