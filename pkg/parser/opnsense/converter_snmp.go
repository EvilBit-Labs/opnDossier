package opnsense

import (
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// netsnmpGeneralVersions lists every version Netsnmp/General.xml has carried
// in the os-net-snmp plugin, from 1.0.0 (2018) to 1.0.7 as of 26.7.9; the
// plugin's history skips 1.0.2. The elements convertSNMP reads kept their
// names in each.
var netsnmpGeneralVersions = strings.Fields("1.0.0 1.0.1 1.0.3 1.0.4 1.0.5 1.0.6 1.0.7")

// netsnmpUserVersions lists every version Netsnmp/User.xml has carried; 1.0.1
// added <readwrite>.
var netsnmpUserVersions = strings.Fields("1.0.0 1.0.1")

const (
	// netsnmpOn is the value the plugin's templates and netsnmp_enabled()
	// compare <enabled> and <readwrite> with. They read the raw config, so an
	// absent element is off, and so is an empty one.
	netsnmpOn = "1"

	snmpLegacyPath  = "SNMP.Snmpd"
	snmpNetsnmpPath = "SNMP.Netsnmp"
)

// convertSNMP reports the SNMP agent the config starts, or an empty
// SNMPConfig when it starts none.
//
// OPNsense has had three agents. Core ran bsnmpd from the legacy top-level
// <snmpd> up to 16.7, and the os-snmp plugin did the same from 17.1 to 18.7,
// both only when <snmpd><enable> was set (isset()). The plugin was removed in
// 19.1, leaving os-net-snmp, which reads <OPNsense><netsnmp> and starts only
// when <general><enabled> is 1. The factory default shipped
// <snmpd><rocommunity>public</rocommunity></snmpd> without <enable> through
// 25.7, and no migration removes it, so most upgraded configs carry a legacy
// block that starts nothing.
//
// The config does not record the release, so a legacy block with <enable> is
// reported as running unless net-snmp is enabled: on 19.1 and later that
// over-reports an agent, which is the safe direction.
func (c *converter) convertSNMP(doc *schema.OpnSenseDocument) common.SNMPConfig {
	legacy := doc.Snmpd
	netsnmp := doc.OPNsense.Netsnmp
	if netsnmp != nil {
		c.checkNetsnmpVersions(netsnmp)
	}

	if netsnmp != nil && netsnmp.General.Enabled == netsnmpOn {
		if legacy.Enable != nil {
			c.addWarning(snmpLegacyPath+".Enable", *legacy.Enable,
				"legacy <snmpd> agent not reported: the os-net-snmp agent is enabled, "+
					"and OPNsense 19.1 and later run no agent from <snmpd>",
				common.SeverityLow)
		}

		return netsnmpConfig(netsnmp)
	}

	if legacy.Enable != nil {
		c.addWarning(snmpLegacyPath+".Enable", *legacy.Enable,
			"legacy <snmpd> agent reported as running: OPNsense up to 18.7 starts it, "+
				"OPNsense 19.1 and later do not",
			common.SeverityLow)

		return common.SNMPConfig{
			Enabled:     true,
			ROCommunity: legacy.ROCommunity,
			SysLocation: legacy.SysLocation,
			SysContact:  legacy.SysContact,
		}
	}

	// A legacy block without <enable> starts nothing on any release, so
	// leaving it out needs no warning: it is the factory default's leftover.
	return common.SNMPConfig{}
}

// netsnmpConfig maps an enabled os-net-snmp agent. A disabled user is left
// out, as the agent's templates skip it; passwords and keys are never read.
func netsnmpConfig(netsnmp *schema.Netsnmp) common.SNMPConfig {
	general := netsnmp.General
	cfg := common.SNMPConfig{
		Enabled:     true,
		ROCommunity: general.Community,
		SysLocation: general.SysLocation,
		SysContact:  general.SysContact,
	}

	for entry := range strings.SplitSeq(general.Listen, ",") {
		if address := strings.TrimSpace(entry); address != "" {
			cfg.ListenAddresses = append(cfg.ListenAddresses, address)
		}
	}

	for _, user := range netsnmp.User.Users {
		if user.Enabled != netsnmpOn {
			continue
		}

		cfg.Users = append(cfg.Users, common.SNMPUser{
			Username:  user.Username,
			ReadWrite: user.ReadWrite == netsnmpOn,
		})
	}

	return cfg
}

// checkNetsnmpVersions warns when either os-net-snmp model carries a version
// convertSNMP has not been checked against, since a renamed element would
// read as an agent that is off (GOTCHAS 18.1).
func (c *converter) checkNetsnmpVersions(netsnmp *schema.Netsnmp) {
	versions := []struct {
		path    string
		version string
		known   []string
	}{
		{snmpNetsnmpPath + ".General.Version", netsnmp.General.Version, netsnmpGeneralVersions},
		{snmpNetsnmpPath + ".User.Version", netsnmp.User.Version, netsnmpUserVersions},
	}

	for _, v := range versions {
		if v.version == "" || slices.Contains(v.known, v.version) {
			continue
		}

		c.addWarning(v.path, v.version,
			"unrecognized os-net-snmp model version; element mapping may be stale",
			common.SeverityMedium)
	}
}
