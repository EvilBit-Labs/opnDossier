package diff

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// settingsCompare runs the comparison that owns a settings struct on a device
// pair that differs only in that struct.
func settingsCompare(old, newCfg *common.CommonDevice) []Change {
	a := NewAnalyzer()
	changes := a.CompareSystem(&old.System, &newCfg.System)
	changes = append(changes, compareServiceSettings(old, newCfg)...)

	return append(changes, a.CompareDNS(old.DNS, newCfg.DNS)...)
}

// TestCompareSettings_EveryFieldIsReported sets each field of the settings
// structs in turn and requires a diff entry, so a field added to one of these
// models later cannot be missed silently. dns.servers is the one field left
// out: System.DNSServers carries the same list and CompareSystem reports it.
func TestCompareSettings_EveryFieldIsReported(t *testing.T) {
	t.Parallel()

	targets := map[string]func(*common.CommonDevice) any{
		"snmp":          func(d *common.CommonDevice) any { return &d.SNMP },
		"syslog":        func(d *common.CommonDevice) any { return &d.Syslog },
		"dns.unbound":   func(d *common.CommonDevice) any { return &d.DNS.Unbound },
		"dns.dnsMasq":   func(d *common.CommonDevice) any { return &d.DNS.DNSMasq },
		"system.webGui": func(d *common.CommonDevice) any { return &d.System.WebGUI },
		"dns":           func(d *common.CommonDevice) any { return &d.DNS },
	}

	for prefix, target := range targets {
		fields := reflect.TypeOf(target(&common.CommonDevice{})).Elem()

		for i := range fields.NumField() {
			name := prefix + "." + fields.Field(i).Name

			// A nested struct has a target of its own, and dns.servers is
			// reported by CompareSystem.
			if fields.Field(i).Type.Kind() == reflect.Struct ||
				settingRatings[prefix+"."+settingName(fields.Field(i))].reportedBy != "" {
				continue
			}

			var old, changed common.CommonDevice
			require.Truef(t, varyField(reflect.ValueOf(target(&changed)).Elem().Field(i)), "%s: no probe", name)

			assert.NotEmptyf(t, settingsCompare(&old, &changed),
				"%s is not compared, so a change to it produces no diff entry", name)
			assert.Emptyf(t, settingsCompare(&changed, &changed), "%s: equal values reported", name)
		}
	}
}

func TestCompareSettings_Ratings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		old, new   func(*common.CommonDevice)
		path       string
		changeType ChangeType
		impact     SecurityImpact
		oldValue   string
		newValue   string
	}{
		{
			name: "snmp agent enabled", new: func(d *common.CommonDevice) { d.SNMP.Enabled = true },
			path: "snmp.enabled", changeType: ChangeModified, impact: SecurityImpactMedium,
			oldValue: "false", newValue: "true",
		},
		{
			name: "snmp community is never shown",
			old:  func(d *common.CommonDevice) { d.SNMP.ROCommunity = "public" },
			new:  func(d *common.CommonDevice) { d.SNMP.ROCommunity = "s3cret" },
			path: "snmp.roCommunity", changeType: ChangeModified, impact: SecurityImpactMedium,
			oldValue: "[set]", newValue: "[set]",
		},
		{
			name: "snmpv3 user added",
			new: func(d *common.CommonDevice) {
				d.SNMP.Users = []common.SNMPUser{{Username: "ops", ReadWrite: true}}
			},
			path: "snmp.users", changeType: ChangeAdded, impact: SecurityImpactMedium,
			newValue: `[{"username":"ops","readWrite":true}]`,
		},
		{
			name: "remote log server removed",
			old:  func(d *common.CommonDevice) { d.Syslog.RemoteServer = "10.0.0.5" },
			path: "syslog.remoteServer", changeType: ChangeRemoved, impact: SecurityImpactMedium,
			oldValue: "10.0.0.5",
		},
		{
			name: "firewall log forwarding turned off",
			old:  func(d *common.CommonDevice) { d.Syslog.FilterLogging = true },
			path: "syslog.filterLogging", changeType: ChangeModified, impact: SecurityImpactMedium,
			oldValue: "true", newValue: "false",
		},
		{
			name: "unbound dnssec turned off",
			old:  func(d *common.CommonDevice) { d.DNS.Unbound.DNSSEC = true },
			path: "dns.unbound.dnssec", changeType: ChangeModified, impact: SecurityImpactMedium,
			oldValue: "true", newValue: "false",
		},
		{
			name: "unbound dnssec turned on",
			new:  func(d *common.CommonDevice) { d.DNS.Unbound.DNSSEC = true },
			path: "dns.unbound.dnssec", changeType: ChangeModified, impact: SecurityImpactLow,
			oldValue: "false", newValue: "true",
		},
		{
			name: "dnsmasq port changed",
			old:  func(d *common.CommonDevice) { d.DNS.DNSMasq.Port = "53" },
			new:  func(d *common.CommonDevice) { d.DNS.DNSMasq.Port = "0" },
			path: "dns.dnsMasq.port", changeType: ChangeModified, impact: SecurityImpactLow,
			oldValue: "53", newValue: "0",
		},
		{
			name: "web gui certificate swapped",
			old:  func(d *common.CommonDevice) { d.System.WebGUI.SSLCertRef = "aaa" },
			new:  func(d *common.CommonDevice) { d.System.WebGUI.SSLCertRef = "bbb" },
			path: "system.webGui.sslCertRef", changeType: ChangeModified, impact: SecurityImpactMedium,
			oldValue: "aaa", newValue: "bbb",
		},
		{
			name: "an unrated field is still reported",
			new:  func(d *common.CommonDevice) { d.SNMP.SysContact = "noc" },
			path: "snmp.sysContact", changeType: ChangeAdded, newValue: "noc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var old, changed common.CommonDevice
			if tt.old != nil {
				tt.old(&old)
			}
			if tt.new != nil {
				tt.new(&changed)
			}

			changes := settingsCompare(&old, &changed)
			require.Len(t, changes, 1)

			got := changes[0]
			assert.Equal(t, tt.path, got.Path)
			assert.Equal(t, tt.changeType, got.Type)
			assert.Equal(t, string(tt.impact), got.SecurityImpact)
			assert.Equal(t, tt.oldValue, got.OldValue)
			assert.Equal(t, tt.newValue, got.NewValue)
			assert.Equal(t, strings.HasPrefix(tt.path, "dns."), got.Section == SectionDNS)
		})
	}
}

// TestCompareSettings_NilAndEmptyListAreEqual pins that a list one parse left
// nil and another left empty is not a change.
func TestCompareSettings_NilAndEmptyListAreEqual(t *testing.T) {
	t.Parallel()

	var old, changed common.CommonDevice
	changed.SNMP.ListenAddresses = []string{}
	changed.DNS.DNSMasq.Hosts = []common.DNSMasqHost{}

	assert.Empty(t, settingsCompare(&old, &changed))
}

// TestSettingRatings_EveryKeyNamesAField fails on a rating whose path no
// settings field has, such as one left behind by a renamed JSON tag. Such a
// rating never applies, and a reportedBy entry stops suppressing its field.
func TestSettingRatings_EveryKeyNamesAField(t *testing.T) {
	t.Parallel()

	paths := map[string]bool{}

	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		paths[path] = true
		if typ.Kind() != reflect.Struct {
			return
		}
		for field := range typ.Fields() {
			walk(path+"."+settingName(field), field.Type)
		}
	}
	walk("snmp", reflect.TypeFor[common.SNMPConfig]())
	walk("syslog", reflect.TypeFor[common.SyslogConfig]())
	walk("dns", reflect.TypeFor[common.DNSConfig]())
	walk("system.webGui", reflect.TypeFor[common.WebGUI]())

	for path := range settingRatings {
		assert.Truef(t, paths[path], "settingRatings has %q, which no settings field has", path)
	}
}

// TestCompareDNS_PrivateAddressElementGone pins that losing the rebind ranges
// is rated only while the element is still in the config: with it gone the
// audit reads rebind protection as unknown, not as off.
func TestCompareDNS_PrivateAddressElementGone(t *testing.T) {
	t.Parallel()

	old := common.DNSConfig{Unbound: common.UnboundConfig{
		PrivateAddress: []string{"10.0.0.0/8"}, PrivateAddressConfigured: true,
	}}
	emptied := common.DNSConfig{Unbound: common.UnboundConfig{PrivateAddressConfigured: true}}

	impact := func(newCfg common.DNSConfig) string {
		for _, change := range NewAnalyzer().CompareDNS(old, newCfg) {
			if change.Path == "dns.unbound.privateAddress" {
				return change.SecurityImpact
			}
		}

		return "no entry"
	}

	assert.Equal(t, string(SecurityImpactMedium), impact(emptied))
	assert.Empty(t, impact(common.DNSConfig{}))
}

// secretName matches a field name that suggests a credential.
var secretName = regexp.MustCompile(`(?i)pass|secret|token|community|psk|key`)

// TestSettingRatings_SecretFieldsAreRedacted fails when a settings model gains
// a field whose name suggests a credential and that the diff would print. A
// field of the struct itself needs redact in settingRatings. A field inside a
// list element cannot be redacted by path, so it fails until settingText
// learns to leave it out.
func TestSettingRatings_SecretFieldsAreRedacted(t *testing.T) {
	t.Parallel()

	var walk func(path string, typ reflect.Type, inList bool)
	walk = func(path string, typ reflect.Type, inList bool) {
		if typ.Kind() == reflect.Slice {
			typ, inList = typ.Elem(), true
		}
		if typ.Kind() != reflect.Struct {
			return
		}

		for field := range typ.Fields() {
			fieldPath := path + "." + settingName(field)

			if secretName.MatchString(field.Name) {
				assert.Falsef(
					t,
					inList,
					"%s looks like a credential inside a list, which the diff prints whole",
					fieldPath,
				)
				assert.Truef(
					t,
					settingRatings[fieldPath].redact,
					"%s looks like a credential; set redact in settingRatings or rename the pattern's exception",
					fieldPath,
				)
			}

			walk(fieldPath, field.Type, inList)
		}
	}
	walk("snmp", reflect.TypeFor[common.SNMPConfig](), false)
	walk("syslog", reflect.TypeFor[common.SyslogConfig](), false)
	walk("dns", reflect.TypeFor[common.DNSConfig](), false)
	walk("system.webGui", reflect.TypeFor[common.WebGUI](), false)
}

// TestCompareSettings_FieldKindsTheModelsDoNotUseYet pins that a field of a
// kind no settings model has today is compared rather than panicking, and that
// a field without a JSON name is reported under its Go name.
func TestCompareSettings_FieldKindsTheModelsDoNotUseYet(t *testing.T) {
	t.Parallel()

	type future struct {
		Count   int `json:"count"`
		Pointer *string
		Hidden  string `json:"-"`
		private string
	}

	text := "x"
	changes := compareSettings(SectionSystem, "future",
		future{private: "a"}, future{Count: 2, Pointer: &text, Hidden: "h", private: "b"})

	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		paths = append(paths, change.Path)
		assert.Equal(t, ChangeAdded, change.Type, change.Path)
	}

	assert.Equal(t, []string{"future.count", "future.Pointer", "future.Hidden"}, paths)
}

func enginePaths(t *testing.T, old, changed *common.CommonDevice, opts Options) map[string]Section {
	t.Helper()

	result, err := NewEngine(old, changed, opts, nil).Compare(context.Background())
	require.NoError(t, err)

	paths := map[string]Section{}
	for _, change := range result.Changes {
		paths[change.Path] = change.Section
	}

	return paths
}

// TestEngine_Compare_SettingsReachTheirSections drives the settings comparers
// through the engine, which is where a section filter and --security apply.
func TestEngine_Compare_SettingsReachTheirSections(t *testing.T) {
	t.Parallel()

	// One rated system setting, one unrated system setting, one rated dns setting.
	old, changed := &common.CommonDevice{}, &common.CommonDevice{}
	old.DNS.Unbound.DNSSEC = true
	changed.SNMP.Enabled = true
	changed.SNMP.SysContact = "noc"

	assert.Equal(t, map[string]Section{
		"snmp.enabled":       SectionSystem,
		"snmp.sysContact":    SectionSystem,
		"dns.unbound.dnssec": SectionDNS,
	}, enginePaths(t, old, changed, Options{}))

	assert.Equal(t, map[string]Section{"dns.unbound.dnssec": SectionDNS},
		enginePaths(t, old, changed, Options{Sections: []string{"dns"}}))

	assert.Equal(t, map[string]Section{
		"snmp.enabled":       SectionSystem,
		"dns.unbound.dnssec": SectionDNS,
	}, enginePaths(t, old, changed, Options{SecurityOnly: true}), "an unrated entry is not security-relevant")
}

// TestEngine_Compare_Normalize_KeepsSettingsTheTextDoesNotShow pins that
// --normalize drops neither a community replaced by another, which displays as
// [set] on both sides, nor a list whose change is whitespace inside a member.
func TestEngine_Compare_Normalize_KeepsSettingsTheTextDoesNotShow(t *testing.T) {
	t.Parallel()

	old, changed := &common.CommonDevice{}, &common.CommonDevice{}
	old.SNMP.ROCommunity, changed.SNMP.ROCommunity = "public", "s3cret"
	old.Syslog.Destinations = []common.SyslogDestination{{Description: "a b"}}
	changed.Syslog.Destinations = []common.SyslogDestination{{Description: "a  b"}}

	assert.Equal(t, map[string]Section{
		"snmp.roCommunity":    SectionSystem,
		"syslog.destinations": SectionSystem,
	}, enginePaths(t, old, changed, Options{Normalize: true}))
}

// TestSettingRatings_MatchTheUserGuide keeps the ratings table in the diff
// guide in step with settingRatings, in both directions.
func TestSettingRatings_MatchTheUserGuide(t *testing.T) {
	t.Parallel()

	guide, err := os.ReadFile("../../docs/user-guide/commands/diff.md")
	require.NoError(t, err)

	cell := func(impact SecurityImpact) string {
		if impact == "" {
			return "-"
		}

		return strings.ToUpper(string(impact))
	}

	documented := map[string][2]string{}
	for line := range strings.SplitSeq(string(guide), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) == 5 && strings.HasPrefix(strings.TrimSpace(cells[1]), "`") {
			path := strings.Trim(strings.TrimSpace(cells[1]), "`")
			documented[path] = [2]string{strings.TrimSpace(cells[2]), strings.TrimSpace(cells[3])}
		}
	}

	rated := map[string][2]string{}
	for path, rating := range settingRatings {
		if rating.set != "" || rating.cleared != "" {
			rated[path] = [2]string{cell(rating.set), cell(rating.cleared)}
		}
	}

	assert.Equal(t, rated, documented)
}
