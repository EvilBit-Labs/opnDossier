package opnsense

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// syslogModelVersions lists every <OPNsense><Syslog version="..."> this
// converter has been checked against, in order: 1.0.0 from 19.7 to 21.7 (21.7
// added the tls transports and the certificate without raising it), 1.0.1 from
// 22.1 to 24.1, 1.0.2 from 24.7 to 26.1, which added the retention fields to
// general, and 1.0.3 in 26.7. The destination elements keep their names
// across all of them.
var syslogModelVersions = strings.Fields("1.0.0 1.0.1 1.0.2 1.0.3")

// The retention eras, as indexes into syslogModelVersions.
const (
	syslogClogEra   = 0 // 1.0.0, 19.7 to 21.7: circular logs, and from 20.7 daily archives too
	syslogLegacyEra = 1 // 1.0.1, 22.1 to 24.1: daily archives, set under <syslog>
)

// syslogClogDefaultSize is the size in bytes OPNsense gave a circular log
// whose <logfilesize> was unset, up to 21.7 (system.inc).
const syslogClogDefaultSize = "511488"

// syslogArchiveDefault is the number of daily archives log_archive keeps when
// none is set, from 20.7 under <syslog> and from 24.7 as the model's default.
const syslogArchiveDefault = "31"

// bytesPerMB converts maxfilesize, which log_archive compares with the file
// size divided by 1024 twice.
const bytesPerMB = 1024 * 1024

// syslogTransports are the transports for which syslog-ng-destinations.conf
// writes a network target. Any other value yields an empty destination block,
// which forwards nothing.
var syslogTransports = strings.Fields("udp4 tcp4 udp6 tcp6 tls4 tls6")

// syslogEventLevels are the levels a destination's level filter must keep for
// the categories other than filter logging to count as forwarded. Leaving out
// debug alone loses none of their events; 20.1 wrote this list as the default.
var syslogEventLevels = strings.Fields("info notice warn err crit alert emerg")

// filterlog writes every entry as program filterlog, facility local0, level
// info (filterlog.c: openlog("filterlog", LOG_NDELAY, LOG_LOCAL0) and
// syslog(LOG_INFO, ...)).
const (
	filterlogProgram  = "filterlog"
	filterlogFacility = "local0"
	filterlogLevel    = "info"
)

// convertSyslog maps the remote logging and retention settings to
// common.SyslogConfig.
//
// From 20.1, OPNsense forwards only to <OPNsense><Syslog><destinations>; 19.7
// was the last release to read the remote keys under <syslog>, and nothing
// migrates or removes them, so an upgraded config can still carry them. They
// are read only when the config has no Syslog model. A config of any release
// can lack the model until something saves it (the 26.7.9 factory default
// does), so that reading tells nothing about the release, and only what
// <syslog> holds is reported. Ignoring the legacy keys beside the model errs
// towards no remote logging for a 19.7 config that used both, the safe
// direction for the checks that read it.
func (c *converter) convertSyslog(doc *schema.OpnSenseDocument) common.SyslogConfig {
	legacy := doc.Syslog
	model := doc.OPNsense.SyslogInternal

	cfg := common.SyslogConfig{Format: legacy.Format}

	if model == nil {
		applyLegacySyslogRemote(&cfg, &legacy)
		c.applySyslogRetention(&cfg, &legacy, nil)

		return cfg
	}

	if model.Version != "" && !slices.Contains(syslogModelVersions, model.Version) {
		c.addWarning(
			"Syslog.Version",
			model.Version,
			"unrecognized OPNsense Syslog model version; remote destinations may be read incompletely",
			common.SeverityMedium,
		)
	}

	c.warnOnIgnoredLegacySyslogRemote(&legacy)
	c.applySyslogDestinations(&cfg, model.Destinations.Destination)
	c.applySyslogRetention(&cfg, &legacy, model)

	return cfg
}

// applySyslogRetention sets the retention the release keeps local logs under.
// With the model, the release is known from its version, so the defaults it
// applies are reported too: a circular log of LogFileSize bytes up to 21.7,
// and RotateCount daily archives from 20.7, each rotated early at LogFileSize
// bytes where set. Without the model the release is not known, so only what
// <syslog> holds is reported. A key the release no longer reads is ignored
// with a warning, and nothing is reported while local logging is off, since
// then no local log is kept. A model with no version is read as the current
// one.
func (c *converter) applySyslogRetention(cfg *common.SyslogConfig, legacy *schema.Syslog, model *schema.SyslogModel) {
	if model == nil {
		if legacy.DisableLocalLogging == nil {
			cfg.LogFileSize = legacy.LogFilesize
			cfg.RotateCount = cmp.Or(legacy.PreserveLogs, legacy.RotateCount)
		}

		return
	}

	switch slices.Index(syslogModelVersions, model.Version) {
	case syslogClogEra:
		// 19.7 to 21.7 keep circular logs, and from 20.7 daily archives beside
		// them unless disable_clog is set. The archives cannot be told from
		// their absence on 19.7 and 20.1, so they count only when the config
		// names them or disable_clog, which 20.7 added, is set. <rotatecount>
		// is pfSense's key, read when the OPNsense one is absent.
		if legacy.DisableLocalLogging != nil {
			return
		}
		clogOff := templateFlagSet(legacy.DisableClog)
		if !clogOff {
			cfg.LogFileSize = cmp.Or(legacy.LogFilesize, syslogClogDefaultSize)
		}
		cfg.RotateCount = cmp.Or(legacy.PreserveLogs, legacy.RotateCount)
		if clogOff {
			cfg.RotateCount = cmp.Or(cfg.RotateCount, syslogArchiveDefault)
		}
	case syslogLegacyEra:
		c.warnOnStaleSyslogRetention("logfilesize", legacy.LogFilesize, "")
		if legacy.DisableLocalLogging != nil {
			return
		}
		cfg.RotateCount = cmp.Or(legacy.PreserveLogs, syslogArchiveDefault)
		cfg.LogFileSize = c.syslogMBToBytes(legacy.MaxFileSize)
	default:
		c.warnOnStaleSyslogRetention("logfilesize", legacy.LogFilesize, "")
		// Migration M1_0_2 copies these into the model and leaves them, so
		// they are worth a warning only once they disagree with it.
		c.warnOnStaleSyslogRetention("preservelogs", legacy.PreserveLogs, model.General.Maxpreserve)
		c.warnOnStaleSyslogRetention("maxfilesize", legacy.MaxFileSize, model.General.Maxfilesize)
		// syslog-ng-local.conf writes local logs only when loglocal is 1.
		if model.General.Loglocal != "1" {
			return
		}
		cfg.RotateCount = cmp.Or(model.General.Maxpreserve, syslogArchiveDefault)
		cfg.LogFileSize = c.syslogMBToBytes(model.General.Maxfilesize)
	}
}

// templateFlagSet reads a legacy flag the way the syslog templates do: their
// helpers.empty treats an absent or empty element as unset and any other
// text, 0 included, as set.
func templateFlagSet(value string) bool {
	return value != ""
}

// warnOnStaleSyslogRetention reports a legacy retention key the release does
// not read, unless it holds the value the release reads instead.
func (c *converter) warnOnStaleSyslogRetention(key, value, current string) {
	if value == "" || value == current {
		return
	}

	c.addWarning(
		"Syslog.Retention",
		key+"="+value,
		"legacy log retention setting ignored: this OPNsense release does not read <syslog><"+key+">",
		common.SeverityLow,
	)
}

// syslogMBToBytes converts a maxfilesize in MB to bytes, the unit LogFileSize
// holds for the circular logs.
func (c *converter) syslogMBToBytes(value string) string {
	if value == "" {
		return ""
	}

	mb, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		c.addWarning("Syslog.MaxFileSize", value, "log file size is not a whole number of MB", common.SeverityLow)

		return ""
	}

	return strconv.FormatUint(mb*bytesPerMB, 10)
}

// applyLegacySyslogRemote copies the remote keys of a config that predates the
// Syslog model.
func applyLegacySyslogRemote(cfg *common.SyslogConfig, sl *schema.Syslog) {
	cfg.Enabled = bool(sl.Enable)
	cfg.SystemLogging = bool(sl.System)
	cfg.AuthLogging = bool(sl.Auth)
	cfg.FilterLogging = bool(sl.Filter)
	cfg.DHCPLogging = bool(sl.Dhcp)
	cfg.VPNLogging = bool(sl.VPN)
	cfg.PortalAuthLogging = bool(sl.Portalauth)
	cfg.DPingerLogging = bool(sl.DPinger)
	cfg.HostapdLogging = bool(sl.Hostapd)
	cfg.ResolverLogging = bool(sl.Resolver)
	cfg.PPPLogging = bool(sl.PPP)
	cfg.IGMPProxyLogging = bool(sl.IgmpProxy)
	cfg.RemoteServer = sl.Remoteserver
	cfg.RemoteServer2 = sl.Remoteserver2
	cfg.RemoteServer3 = sl.Remoteserver3
	cfg.SourceIP = sl.Sourceip
	cfg.IPProtocol = sl.IPProtocol

	// logall sent every message to the servers, whatever the category flags.
	if templateFlagSet(sl.LogAll) {
		setAllSyslogCategories(cfg)
	}
}

// setAllSyslogCategories marks every logging category as forwarded.
func setAllSyslogCategories(cfg *common.SyslogConfig) {
	cfg.SystemLogging = true
	cfg.AuthLogging = true
	cfg.FilterLogging = true
	cfg.DHCPLogging = true
	cfg.VPNLogging = true
	cfg.PortalAuthLogging = true
	cfg.DPingerLogging = true
	cfg.HostapdLogging = true
	cfg.ResolverLogging = true
	cfg.PPPLogging = true
	cfg.IGMPProxyLogging = true
}

// warnOnIgnoredLegacySyslogRemote reports legacy remote keys left beside the
// Syslog model, so a server the config still names is not dropped silently.
func (c *converter) warnOnIgnoredLegacySyslogRemote(sl *schema.Syslog) {
	servers := slices.DeleteFunc(
		[]string{sl.Remoteserver, sl.Remoteserver2, sl.Remoteserver3},
		func(s string) bool { return s == "" },
	)
	// <enable> alone names no server, so 19.7 forwarded nowhere from it either.
	if len(servers) == 0 {
		return
	}

	c.addWarning(
		"Syslog.RemoteServer",
		strings.Join(servers, listSeparator),
		"legacy remote syslog settings ignored: OPNsense 20.1 and later forward only to the Syslog model's destinations",
		common.SeverityMedium,
	)
}

// applySyslogDestinations lists the model's destinations and summarizes the
// ones that forward into the flat fields the checks read.
func (c *converter) applySyslogDestinations(cfg *common.SyslogConfig, items []schema.SyslogDestination) {
	var servers []string

	for i := range items {
		item := &items[i]
		if item.IsPlaceholder() {
			continue
		}

		// The template forwards only when enabled is exactly 1; an absent
		// element reads as 0 there, unlike the model's default. It does not
		// test the hostname, but an empty one names no server to send to.
		enabled := item.Enabled == "1"
		cfg.Destinations = append(cfg.Destinations, common.SyslogDestination{
			Enabled:     enabled,
			Transport:   item.Transport,
			Hostname:    item.Hostname,
			Port:        item.Port,
			Programs:    splitNonEmpty(item.Program, listSeparator),
			Levels:      splitNonEmpty(item.Level, listSeparator),
			Facilities:  splitNonEmpty(item.Facility, listSeparator),
			Description: item.Description,
		})

		if !enabled || item.Hostname == "" {
			continue
		}

		if !slices.Contains(syslogTransports, item.Transport) {
			c.addWarning(
				"Syslog.Destinations.Transport",
				item.Transport,
				"syslog destination "+item.Hostname+" has a transport OPNsense writes no target for, so it forwards nothing",
				common.SeverityMedium,
			)

			continue
		}

		cfg.Enabled = true
		servers = append(servers, item.Hostname)
		applySyslogCoverage(cfg, item)
	}

	for i, field := range []*string{&cfg.RemoteServer, &cfg.RemoteServer2, &cfg.RemoteServer3} {
		if i < len(servers) {
			*field = servers[i]
		}
	}
}

// applySyslogCoverage sets the logging flags a forwarding destination
// covers. The template ANDs the program, level and facility filters. Filter
// logging is decided from the program, facility and level filterlog writes;
// the other categories come from many programs and levels, so only a filter
// that cannot drop their events counts, and anything else leaves the flag as
// it is.
func applySyslogCoverage(cfg *common.SyslogConfig, d *schema.SyslogDestination) {
	if admitsFilterlog(d) {
		cfg.FilterLogging = true
	}

	if d.Facility != "" {
		return
	}

	if d.Level != "" {
		levels := splitNonEmpty(d.Level, listSeparator)
		for _, level := range syslogEventLevels {
			if !slices.Contains(levels, level) {
				return
			}
		}
	}

	if d.Program == "" {
		setAllSyslogCategories(cfg)

		return
	}

	// The program names are those 19.7's legacy remote template filtered each
	// category on. System and authentication events come from many programs,
	// so no program list proves them.
	for _, program := range splitNonEmpty(d.Program, listSeparator) {
		switch program {
		case "dhcpd", "dhcrelay":
			cfg.DHCPLogging = true
		case "unbound", "dnsmasq":
			cfg.ResolverLogging = true
		case "captiveportal":
			cfg.PortalAuthLogging = true
		case "l2tps", "poes", "pptps", "charon", "openvpn":
			cfg.VPNLogging = true
		case "dpinger":
			cfg.DPingerLogging = true
		case "hostapd":
			cfg.HostapdLogging = true
		}
	}
}

// admitsFilterlog reports whether every filter of the destination lets
// filterlog's entries through. syslog-ng matches each program entry as an
// unanchored pattern, so an entry such as "filter" admits filterlog too; an
// entry that is not a valid pattern admits nothing. The model accepts only
// names from its application list, so that takes a hand edit.
func admitsFilterlog(d *schema.SyslogDestination) bool {
	if d.Level != "" && !slices.Contains(splitNonEmpty(d.Level, listSeparator), filterlogLevel) {
		return false
	}

	if d.Facility != "" && !slices.Contains(splitNonEmpty(d.Facility, listSeparator), filterlogFacility) {
		return false
	}

	if d.Program == "" {
		return true
	}

	return slices.ContainsFunc(splitNonEmpty(d.Program, listSeparator), func(entry string) bool {
		pattern, err := regexp.Compile(entry)

		return err == nil && pattern.MatchString(filterlogProgram)
	})
}
