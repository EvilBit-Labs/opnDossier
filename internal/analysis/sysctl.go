package analysis

import (
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// sysctlDefaultKeyword is the value both firewalls accept in place of a number
// to select a tunable's built-in default.
const sysctlDefaultKeyword = "default"

// sysctlNameSpace is what FreeBSD's sysctl trims from the end of a name: the
// characters isspace accepts in the C locale.
const sysctlNameSpace = " \t\n\v\f\r"

// sysctlDefault is what OPNsense applies to a tunable left at its default.
type sysctlDefault struct {
	// keyword is the value in effect for a row holding the literal "default",
	// in every release.
	keyword string
	// unset is the value in effect when the tunable's value is empty or the
	// config has no row for it. It is empty when that depends on the release.
	unset string
}

// opnsenseSysctlDefault returns OPNsense's default for one of the tunables a
// check reads, and false for any other tunable.
//
// In current releases OPNsense lists its defaults in system_sysctl_defaults()
// in src/etc/inc/system.inc, and system_sysctl_get() applies them; before
// 22.1.2, get_default_sysctl_value() supplies them. The keyword "default"
// selects that default, with the same values for these tunables at every
// major release from 16.1. 15.1 and 15.7 list no default for the two
// source-route tunables, so there the keyword leaves the kernel's 0. From
// 25.1.3 on, an empty value selects the default too, and from 25.1.4 on a
// tunable the config does not list gets it, because the getter seeds every
// default not marked optional (every default from 25.7) before reading the
// config. Before 25.1.3 an empty value is handed to sysctl, which rejects it,
// and before 25.1.4 the tunables in this table are not set when the config
// does not list them, so the FreeBSD kernel's own value applies.
//
// For the source-route and SYN-cookie tunables the two agree: OPNsense's
// default and the kernel's are 0, 0 and 1, so an empty or missing row reads
// the same in every release. For the blackhole tunables they do not: OPNsense's
// default is 2 for TCP and 1 for UDP, the kernel's is 0 for both, so an empty
// or missing blackhole row is left unknown rather than guessing the release.
func opnsenseSysctlDefault(name string) (sysctlDefault, bool) {
	switch name {
	case "net.inet.ip.sourceroute", "net.inet.ip.accept_sourceroute":
		return sysctlDefault{keyword: "0", unset: "0"}, true
	case "net.inet.tcp.syncookies":
		return sysctlDefault{keyword: "1", unset: "1"}, true
	case "net.inet.tcp.blackhole":
		return sysctlDefault{keyword: "2"}, true
	case "net.inet.udp.blackhole":
		return sysctlDefault{keyword: "1"}, true
	default:
		return sysctlDefault{}, false
	}
}

// EffectiveSysctl returns the value a tunable has on the firewall, and false
// when the config does not tell.
//
// The last row naming the tunable wins, as on both firewalls: each keys the
// tunables by name in config order, so a later row replaces an earlier one. A
// row holding anything but "" or "default" is that value on any device.
//
// An empty value, the keyword and a missing row are resolved for OPNsense only
// (opnsenseSysctlDefault). On any other device a row is read as written and a
// missing row is unknown. The pfSense converter does not read tunables at all
// (a declared gap), so a missing row there means unread, and pfSense itself
// resolves only the keyword, from a defaults list with no source-route entry.
//
// On OPNsense, a tunable that a padded row names (SysctlNamePadded) is unknown
// here. A caller falls back to the reading it had before tunables were
// resolved.
func EffectiveSysctl(device *common.CommonDevice, name string) (string, bool) {
	if device == nil || SysctlNamePadded(device, name) {
		return "", false
	}

	value, found := "", false
	for _, item := range device.Sysctl {
		if item.Tunable == name {
			value, found = item.Value, true
		}
	}

	if found && value != "" && value != sysctlDefaultKeyword {
		return value, true
	}

	if device.DeviceType != common.DeviceTypeOPNsense {
		return value, found
	}

	def, ok := opnsenseSysctlDefault(name)
	if !ok {
		return "", false
	}

	if value == sysctlDefaultKeyword {
		return def.keyword, true
	}

	return def.unset, def.unset != ""
}

// SysctlNamePadded reports whether an OPNsense config holds a padded row for a
// tunable: one naming it with trailing whitespace, one trailing dot, or a dot
// followed by whitespace. It is false on any other device, where rows are read
// as written.
//
// OPNsense keys such a row apart from the exact name, but FreeBSD's sysctl
// drops trailing whitespace from a name (sbin/sysctl/sysctl.c parse, from
// FreeBSD 10.3) and the kernel accepts one trailing dot (sys/kern/kern_sysctl.c
// name2oid), so OPNsense 16.7 to 20.1, which hand every name to sysctl, apply
// it too, before or after the exact name depending on where each first
// appears. From 20.7 OPNsense skips a name sysctl does not list. The value in
// effect then depends on the release and on the order of the rows, so the
// controls read such a tunable as they did before tunables were resolved.
// Leading whitespace is not dropped, so a row with it names no tunable.
func SysctlNamePadded(device *common.CommonDevice, name string) bool {
	if device == nil || device.DeviceType != common.DeviceTypeOPNsense {
		return false
	}

	for _, item := range device.Sysctl {
		if item.Tunable != name &&
			strings.TrimSuffix(strings.TrimRight(item.Tunable, sysctlNameSpace), ".") == name {
			return true
		}
	}

	return false
}
