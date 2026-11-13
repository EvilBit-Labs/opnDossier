package opnsense

import (
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// netsnmpGeneralVersions lists every version Netsnmp/General.xml has carried
// in the os-net-snmp plugin, 1.0.0 (2018) to 1.0.7 (26.7); the plugin's
// history skips 1.0.2. The elements convertSNMP reads kept their names in each.
var netsnmpGeneralVersions = strings.Fields("1.0.0 1.0.1 1.0.3 1.0.4 1.0.5 1.0.6 1.0.7")

// netsnmpUserVersions lists every version Netsnmp/User.xml has carried; 1.0.1
// added <readwrite>.
var netsnmpUserVersions = strings.Fields("1.0.0 1.0.1")

// netsnmpOn is the value the plugin's templates and netsnmp_enabled() compare
// <enabled> and <readwrite> with. They read the raw config, so an absent
// element is off, and so is an empty one.
const netsnmpOn = "1"

const snmpNetsnmpPath = "SNMP.Netsnmp"

// convertSNMP reports the SNMP agent the config starts. From 19.1 the only
// agent OPNsense ships is the os-net-snmp plugin, which reads
// <OPNsense><netsnmp> and starts only when <general><enabled> is 1. Without
// one, the legacy top-level <snmpd> is mapped as before.
func (c *converter) convertSNMP(doc *schema.OpnSenseDocument) common.SNMPConfig {
	netsnmp := doc.OPNsense.Netsnmp
	if netsnmp != nil {
		c.checkNetsnmpVersions(netsnmp)

		if netsnmp.General.Enabled == netsnmpOn {
			return netsnmpConfig(netsnmp)
		}
	}

	return common.SNMPConfig{
		ROCommunity: doc.Snmpd.ROCommunity,
		SysLocation: doc.Snmpd.SysLocation,
		SysContact:  doc.Snmpd.SysContact,
	}
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
