package opnsense

import (
	"cmp"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// syslogModelVersions lists every <OPNsense><Syslog version="..."> this
// converter has been checked against: 1.0.0 (19.7 to 20.7), 1.0.1 (24.1),
// 1.0.2 (24.7 and 25.1, which added the retention fields to general) and 1.0.3
// (26.7). Each later version only adds elements.
var syslogModelVersions = strings.Fields("1.0.0 1.0.1 1.0.2 1.0.3")

// syslogLegacyRetentionVersions are the model versions whose general block does
// not hold retention yet, so the legacy <syslog> keys still set it.
var syslogLegacyRetentionVersions = strings.Fields("1.0.0 1.0.1")

// syslogTransports are the transports for which syslog-ng-destinations.conf
// writes a network target. Any other value yields an empty destination block,
// which forwards nothing.
var syslogTransports = strings.Fields("udp4 tcp4 udp6 tcp6 tls4 tls6")

// syslogEventLevels are the levels a destination's level filter must keep for
// its events to count as forwarded. Leaving out debug alone loses none of the
// events the logging checks ask about; 20.1 wrote this list as the default.
var syslogEventLevels = strings.Fields("info notice warn err crit alert emerg")

// convertSyslog maps the remote logging and retention settings to
// common.SyslogConfig.
//
// From 20.1, OPNsense forwards only to <OPNsense><Syslog><destinations>; 19.7
// was the last release to read the remote keys under <syslog>, and nothing
// migrates or removes them, so an upgraded config can still carry them. They
// are read only when the config has no Syslog model, which a config from 19.7
// on carries once the model has been migrated or saved. That reading errs
// towards no remote logging for a 19.7 config that used both, the safe
// direction for the checks that read it.
func (c *converter) convertSyslog(doc *schema.OpnSenseDocument) common.SyslogConfig {
	legacy := doc.Syslog
	model := &doc.OPNsense.SyslogInternal

	cfg := common.SyslogConfig{
		LogFileSize: legacy.LogFilesize,
		RotateCount: cmp.Or(legacy.RotateCount, legacy.PreserveLogs),
		Format:      legacy.Format,
	}

	if model.XMLName.Local == "" {
		applyLegacySyslogRemote(&cfg, &legacy)

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

	// From 24.7 (model 1.0.2) log_archive reads retention from the model alone,
	// and migration M1_0_2 leaves the legacy keys behind.
	if !slices.Contains(syslogLegacyRetentionVersions, model.Version) &&
		(model.Version != "" || model.General.Maxpreserve != "") {
		cfg.LogFileSize = ""
		cfg.RotateCount = model.General.Maxpreserve
	}

	return cfg
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
}

// warnOnIgnoredLegacySyslogRemote reports legacy remote keys left beside the
// Syslog model, so a server the config still names is not dropped silently.
func (c *converter) warnOnIgnoredLegacySyslogRemote(sl *schema.Syslog) {
	servers := slices.DeleteFunc(
		[]string{sl.Remoteserver, sl.Remoteserver2, sl.Remoteserver3},
		func(s string) bool { return s == "" },
	)
	if len(servers) == 0 && !bool(sl.Enable) {
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
		// element reads as 0 there, unlike the model's default.
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

// applySyslogCoverage sets the logging flags a forwarding destination provably
// covers. The template ANDs the program, level and facility filters, and
// syslog-ng matches program() as a pattern, so only a filter that cannot drop
// a category's events counts; anything else leaves the flag as it is.
func applySyslogCoverage(cfg *common.SyslogConfig, d *schema.SyslogDestination) {
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

		return
	}

	// The program names are those 19.7's legacy remote template filtered each
	// category on. System and authentication events come from many programs,
	// so no program list proves them.
	for _, program := range splitNonEmpty(d.Program, listSeparator) {
		switch program {
		case "filterlog":
			cfg.FilterLogging = true
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
