package diff

import (
	"reflect"
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
	}

	for prefix, target := range targets {
		fields := reflect.TypeOf(target(&common.CommonDevice{})).Elem()

		for i := range fields.NumField() {
			name := prefix + "." + fields.Field(i).Name

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
