package diff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// settingRating describes one settings path. set rates a change whose new
// value is true or non-empty, cleared one whose new value is false or empty.
// A path without a rating is still reported, unrated, so a field added to a
// model is never silent.
type settingRating struct {
	label   string
	set     SecurityImpact
	cleared SecurityImpact
	// redact shows only whether the value is set. The entry is still emitted
	// when one secret replaces another.
	redact bool
	// skip names the comparison that already reports the field.
	skip string
}

// settingRatings is keyed by the path the JSON export uses.
var settingRatings = map[string]settingRating{
	"snmp.enabled": {label: "SNMP agent", set: SecurityImpactMedium, cleared: SecurityImpactLow},
	"snmp.roCommunity": {
		label:   "SNMP community",
		set:     SecurityImpactMedium,
		cleared: SecurityImpactLow,
		redact:  true,
	},
	"snmp.listenAddresses": {label: "SNMP listen addresses", set: SecurityImpactMedium, cleared: SecurityImpactMedium},
	"snmp.users":           {label: "SNMPv3 users", set: SecurityImpactMedium, cleared: SecurityImpactLow},

	"syslog.enabled":       {label: "Remote logging", set: SecurityImpactLow, cleared: SecurityImpactMedium},
	"syslog.systemLogging": {label: "System log forwarding", set: SecurityImpactLow, cleared: SecurityImpactMedium},
	"syslog.authLogging": {
		label:   "Authentication log forwarding",
		set:     SecurityImpactLow,
		cleared: SecurityImpactMedium,
	},
	"syslog.filterLogging": {label: "Firewall log forwarding", set: SecurityImpactLow, cleared: SecurityImpactMedium},
	"syslog.dhcpLogging":   {label: "DHCP log forwarding", cleared: SecurityImpactLow},
	"syslog.vpnLogging":    {label: "VPN log forwarding", cleared: SecurityImpactLow},
	"syslog.portalAuthLogging": {
		label: "Captive portal log forwarding", cleared: SecurityImpactLow,
	},
	"syslog.dpingerLogging":   {label: "Gateway monitor log forwarding", cleared: SecurityImpactLow},
	"syslog.hostapdLogging":   {label: "Wireless log forwarding", cleared: SecurityImpactLow},
	"syslog.resolverLogging":  {label: "Resolver log forwarding", cleared: SecurityImpactLow},
	"syslog.pppLogging":       {label: "PPP log forwarding", cleared: SecurityImpactLow},
	"syslog.igmpProxyLogging": {label: "IGMP proxy log forwarding", cleared: SecurityImpactLow},
	"syslog.remoteServer":     {label: "Remote log server", set: SecurityImpactMedium, cleared: SecurityImpactMedium},
	"syslog.remoteServer2": {
		label:   "Second remote log server",
		set:     SecurityImpactMedium,
		cleared: SecurityImpactMedium,
	},
	"syslog.remoteServer3": {
		label:   "Third remote log server",
		set:     SecurityImpactMedium,
		cleared: SecurityImpactMedium,
	},
	"syslog.destinations": {
		label:   "Remote log destinations",
		set:     SecurityImpactMedium,
		cleared: SecurityImpactMedium,
	},
	"syslog.logFileSize": {label: "Log file size", set: SecurityImpactLow, cleared: SecurityImpactLow},
	"syslog.rotateCount": {label: "Log rotation count", set: SecurityImpactLow, cleared: SecurityImpactLow},

	"dns.servers":         {skip: "CompareSystem reports it as system.dnsServers"},
	"dns.unbound.enabled": {label: "Unbound resolver", set: SecurityImpactLow, cleared: SecurityImpactLow},
	"dns.unbound.dnssec": {
		label:   "Unbound DNSSEC validation",
		set:     SecurityImpactLow,
		cleared: SecurityImpactMedium,
	},
	"dns.unbound.dnssecStripped": {
		label:   "Unbound DNSSEC data hardening",
		set:     SecurityImpactLow,
		cleared: SecurityImpactMedium,
	},
	"dns.unbound.privateAddress": {
		label: "Unbound rebind protection ranges", set: SecurityImpactLow, cleared: SecurityImpactMedium,
	},
	// Absent leaves rebind protection unknown, so neither direction is rated.
	"dns.unbound.privateAddressConfigured": {label: "Unbound private-address element"},
	"dns.unbound.hideIdentity":             {label: "Unbound identity hiding", cleared: SecurityImpactLow},
	"dns.unbound.hideVersion":              {label: "Unbound version hiding", cleared: SecurityImpactLow},
	"dns.dnsMasq.enabled":                  {label: "dnsmasq", set: SecurityImpactLow, cleared: SecurityImpactLow},
	"dns.dnsMasq.dnssec": {
		label:   "dnsmasq DNSSEC validation",
		set:     SecurityImpactLow,
		cleared: SecurityImpactMedium,
	},
	"dns.dnsMasq.port": {
		label:   "dnsmasq DNS port",
		set:     SecurityImpactLow,
		cleared: SecurityImpactLow,
	},
	"dns.dnsMasq.hosts": {
		label:   "dnsmasq host overrides",
		set:     SecurityImpactLow,
		cleared: SecurityImpactLow,
	},
	"dns.dnsMasq.domainOverrides": {
		label:   "dnsmasq domain overrides",
		set:     SecurityImpactLow,
		cleared: SecurityImpactLow,
	},
	"dns.dnsMasq.forwarders": {
		label:   "dnsmasq forwarders",
		set:     SecurityImpactLow,
		cleared: SecurityImpactLow,
	},

	"system.webGui.protocol":         {skip: "CompareSystem reports it as system.webgui.protocol"},
	"system.webGui.noAntiLockout":    {skip: "compareImplicitFilterSettings reports it"},
	"system.webGui.noDnsRebindCheck": {skip: "CompareSystem reports it as system.webgui.nodnsrebindcheck"},
	"system.webGui.sslCertRef": {
		label: "Web GUI certificate", set: SecurityImpactMedium, cleared: SecurityImpactMedium,
	},
	"system.webGui.port":              {label: "Web GUI port", set: SecurityImpactLow, cleared: SecurityImpactLow},
	"system.webGui.loginAutocomplete": {label: "Web GUI login autocomplete", set: SecurityImpactLow},
}

// compareServiceSettings reports SNMP and syslog changes in the system section.
// It has no section-level added or removed entry: which setting changed is the
// finding, as with firewall rules and users.
func compareServiceSettings(old, newCfg *common.CommonDevice) []Change {
	return append(
		compareSettings(SectionSystem, "snmp", old.SNMP, newCfg.SNMP),
		compareSettings(SectionSystem, "syslog", old.Syslog, newCfg.Syslog)...)
}

// CompareDNS compares the Unbound and dnsmasq settings.
func (a *Analyzer) CompareDNS(old, newCfg common.DNSConfig) []Change {
	return compareSettings(SectionDNS, "dns", old, newCfg)
}

// compareSettings walks two values of one settings struct and reports every
// field that differs, one entry per field, under the field's JSON name.
func compareSettings(section Section, path string, old, newCfg any) []Change {
	return compareSettingValues(section, path, reflect.ValueOf(old), reflect.ValueOf(newCfg))
}

func compareSettingValues(section Section, path string, old, newCfg reflect.Value) []Change {
	rating := settingRatings[path]
	if rating.skip != "" {
		return nil
	}

	if old.Kind() == reflect.Struct {
		var changes []Change

		for i := range old.NumField() {
			name, _, _ := strings.Cut(old.Type().Field(i).Tag.Get("json"), ",")
			changes = append(changes,
				compareSettingValues(section, path+"."+name, old.Field(i), newCfg.Field(i))...)
		}

		return changes
	}

	// A nil list and an empty one are the same setting.
	if old.Kind() == reflect.Slice && old.Len() == 0 && newCfg.Len() == 0 {
		return nil
	}
	if reflect.DeepEqual(old.Interface(), newCfg.Interface()) {
		return nil
	}

	label := rating.label
	if label == "" {
		label = path
	}

	change := Change{
		Type:        ChangeModified,
		Section:     section,
		Path:        path,
		Description: label + " changed",
		OldValue:    settingText(old, rating.redact),
		NewValue:    settingText(newCfg, rating.redact),
		// A list is shown as text that whitespace normalization could flatten,
		// and a redacted value does not show what was compared.
		summarized: rating.redact || old.Kind() == reflect.Slice,
	}

	impact := rating.set
	switch {
	case old.Kind() == reflect.Bool:
		change.Description = label + " turned off"
		if newCfg.Bool() {
			change.Description = label + " turned on"
		} else {
			impact = rating.cleared
		}
	case newCfg.Len() == 0:
		change.Type, change.Description, impact = ChangeRemoved, label+" removed", rating.cleared
	case old.Len() == 0:
		change.Type, change.Description = ChangeAdded, label+" added"
	}
	change.SecurityImpact = string(impact)

	return []Change{change}
}

// settingText renders a string, bool or list field for display.
func settingText(v reflect.Value, redact bool) string {
	switch {
	case v.Kind() == reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case v.Len() == 0:
		return ""
	case redact:
		return "[set]"
	case v.Kind() == reflect.String:
		return v.String()
	}

	if list, ok := reflect.TypeAssert[[]string](v); ok {
		return strings.Join(list, ", ")
	}

	text, err := json.Marshal(v.Interface())
	if err != nil {
		return fmt.Sprint(v.Interface())
	}

	return string(text)
}
