package opnsense

import (
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// convertMonit maps doc.OPNsense.Monit to *common.MonitConfig.
// Returns nil if the Monit subsystem is not configured.
func (c *converter) convertMonit(doc *schema.OpnSenseDocument) *common.MonitConfig {
	monit := doc.OPNsense.Monit
	if monit == nil {
		return nil
	}

	cfg := &common.MonitConfig{
		Enabled:      monit.General.Enabled == xmlBoolTrue,
		Interval:     monit.General.Interval,
		StartDelay:   monit.General.Startdelay,
		MailServer:   monit.General.Mailserver,
		MailPort:     monit.General.Port,
		SSLEnabled:   monit.General.Ssl == xmlBoolTrue,
		HTTPDEnabled: monit.General.HttpdEnabled == xmlBoolTrue,
		HTTPDPort:    monit.General.HttpdPort,
		MMonitURL:    monit.General.MmonitURL,
	}

	if monit.Alert.Enabled == xmlBoolTrue || monit.Alert.Recipient != "" {
		cfg.Alert = &common.MonitAlert{
			Enabled:     monit.Alert.Enabled == xmlBoolTrue,
			Recipient:   monit.Alert.Recipient,
			NotOn:       monit.Alert.Noton,
			Events:      monit.Alert.Events,
			Description: monit.Alert.Description,
		}
	}

	cfg.Services = c.convertMonitServices(monit.Service)
	cfg.Tests = c.convertMonitTests(monit.Test)

	return cfg
}

// convertMonitServices maps []schema.MonitService to []common.MonitServiceEntry.
func (c *converter) convertMonitServices(services []schema.MonitService) []common.MonitServiceEntry {
	if len(services) == 0 {
		return nil
	}

	result := make([]common.MonitServiceEntry, 0, len(services))
	for _, s := range services {
		result = append(result, common.MonitServiceEntry{
			UUID:        s.UUID,
			Enabled:     s.Enabled == xmlBoolTrue,
			Name:        s.Name,
			Type:        s.Type,
			Description: s.Description,
			PIDFile:     s.Pidfile,
			Match:       s.Match,
			Path:        s.Path,
			Address:     s.Address,
			Interface:   s.Interface,
			Start:       s.Start,
			Stop:        s.Stop,
			Tests:       s.Tests,
			Depends:     s.Depends,
		})
	}

	return result
}

// convertMonitTests maps []schema.MonitTest to []common.MonitTest.
func (c *converter) convertMonitTests(tests []schema.MonitTest) []common.MonitTest {
	if len(tests) == 0 {
		return nil
	}

	result := make([]common.MonitTest, 0, len(tests))
	for _, t := range tests {
		result = append(result, common.MonitTest{
			UUID:      t.UUID,
			Name:      t.Name,
			Type:      t.Type,
			Condition: t.Condition,
			Action:    t.Action,
			Path:      t.Path,
		})
	}

	return result
}

// convertNetflow maps doc.OPNsense.Netflow to *common.NetflowConfig.
// Returns nil if Netflow has no meaningful configuration.
func (c *converter) convertNetflow(doc *schema.OpnSenseDocument) *common.NetflowConfig {
	nf := doc.OPNsense.Netflow
	hasCapture := nf.Capture.Interfaces != "" || nf.Capture.Version != ""
	hasCollect := nf.Collect.Enable == xmlBoolTrue

	if !hasCapture && !hasCollect {
		return nil
	}

	return &common.NetflowConfig{
		CaptureInterfaces: nf.Capture.Interfaces,
		CaptureVersion:    nf.Capture.Version,
		EgressOnly:        nf.Capture.EgressOnly == xmlBoolTrue,
		CaptureTargets:    nf.Capture.Targets,
		CollectEnabled:    hasCollect,
		InactiveTimeout:   nf.InactiveTimeout,
		ActiveTimeout:     nf.ActiveTimeout,
	}
}

// convertTrafficShaper maps doc.OPNsense.TrafficShaper to *common.TrafficShaperConfig.
// Returns nil if no traffic shaping is configured.
func (c *converter) convertTrafficShaper(doc *schema.OpnSenseDocument) *common.TrafficShaperConfig {
	ts := doc.OPNsense.TrafficShaper
	if ts.Pipes == "" && ts.Queues == "" && ts.Rules == "" {
		return nil
	}

	return &common.TrafficShaperConfig{
		Pipes:  ts.Pipes,
		Queues: ts.Queues,
		Rules:  ts.Rules,
	}
}

// convertCaptivePortal maps doc.OPNsense.Captiveportal to *common.CaptivePortalConfig.
// Returns nil if no captive portal zones are configured.
func (c *converter) convertCaptivePortal(doc *schema.OpnSenseDocument) *common.CaptivePortalConfig {
	cp := doc.OPNsense.Captiveportal
	if cp.Zones == "" && cp.Templates == "" {
		return nil
	}

	return &common.CaptivePortalConfig{
		Zones:     cp.Zones,
		Templates: cp.Templates,
	}
}

// convertCron maps doc.OPNsense.Cron to *common.CronConfig.
// Returns nil if no cron jobs are configured.
func (c *converter) convertCron(doc *schema.OpnSenseDocument) *common.CronConfig {
	if doc.OPNsense.Cron.Jobs == "" {
		return nil
	}

	return &common.CronConfig{
		Jobs: doc.OPNsense.Cron.Jobs,
	}
}

// convertTrust maps doc.OPNsense.Trust to *common.TrustConfig.
// Returns nil if TLS trust settings are all at defaults.
func (c *converter) convertTrust(doc *schema.OpnSenseDocument) *common.TrustConfig {
	t := doc.OPNsense.Trust.General
	hasCrypto := t.CipherString != "" || t.Ciphersuites != "" || t.MinProtocol != ""
	hasFlags := t.StoreIntermediateCerts == xmlBoolTrue || t.InstallCrls == xmlBoolTrue || t.FetchCrls == xmlBoolTrue

	if !hasCrypto && !hasFlags {
		return nil
	}

	return &common.TrustConfig{
		StoreIntermediateCerts:  t.StoreIntermediateCerts == xmlBoolTrue,
		InstallCRLs:             t.InstallCrls == xmlBoolTrue,
		FetchCRLs:               t.FetchCrls == xmlBoolTrue,
		EnableLegacySect:        t.EnableLegacySect == xmlBoolTrue,
		EnableConfigConstraints: t.EnableConfigConstraints == xmlBoolTrue,
		CipherString:            t.CipherString,
		Ciphersuites:            t.Ciphersuites,
		Groups:                  t.Groups,
		MinProtocol:             t.MinProtocol,
		MinProtocolDTLS:         t.MinProtocolDTLS,
	}
}

// convertKeaDHCP maps doc.OPNsense.Kea to *common.KeaDHCPConfig.
// Returns nil if the Kea DHCP server is not configured.
func (c *converter) convertKeaDHCP(doc *schema.OpnSenseDocument) *common.KeaDHCPConfig {
	kea := doc.OPNsense.Kea
	if kea.Dhcp4.General.Enabled != xmlBoolTrue && kea.Dhcp4.General.Interfaces == "" {
		return nil
	}

	return &common.KeaDHCPConfig{
		Enabled:       kea.Dhcp4.General.Enabled == xmlBoolTrue,
		Interfaces:    kea.Dhcp4.General.Interfaces,
		FirewallRules: kea.Dhcp4.General.FirewallRules == xmlBoolTrue,
		ValidLifetime: kea.Dhcp4.General.ValidLifetime,
		HA: common.KeaDHCPHA{
			Enabled:           kea.Dhcp4.HighAvailability.Enabled == xmlBoolTrue,
			ThisServerName:    kea.Dhcp4.HighAvailability.ThisServerName,
			MaxUnackedClients: kea.Dhcp4.HighAvailability.MaxUnackedClients,
		},
	}
}

// convertKeaDHCPScopes converts Kea DHCP4 subnets into unified DHCPScope entries.
// Reservations reference their parent subnet by UUID; we group them by subnet UUID
// and attach as static leases. Option data (gateway, DNS, NTP) is extracted from
// each subnet's inline option_data element.
//
//nolint:dupl // ISC and Kea converters have similar structure but distinct data sources
func (c *converter) convertKeaDHCPScopes(doc *schema.OpnSenseDocument) []common.DHCPScope {
	kea := doc.OPNsense.Kea.Dhcp4
	if kea.General.Enabled != xmlBoolTrue || len(kea.Subnets) == 0 {
		return nil
	}

	// Group reservations by parent subnet UUID.
	resBySubnet := make(map[string][]schema.KeaReservation, len(kea.Reservations))
	for _, r := range kea.Reservations {
		resBySubnet[r.Subnet] = append(resBySubnet[r.Subnet], r)
	}

	scopes := make([]common.DHCPScope, 0, len(kea.Subnets))
	for _, sub := range kea.Subnets {
		scope := common.DHCPScope{
			Source:      "kea",
			Enabled:     true, // Kea subnets are active when the server is enabled
			Description: sub.Description,
		}

		// Extract gateway, DNS, NTP from option_data.
		// Fields can be comma-separated lists; use the first value.
		if sub.OptionData.Routers != "" {
			scope.Gateway = firstCSV(sub.OptionData.Routers)
		}
		if sub.OptionData.DomainNameServers != "" {
			scope.DNSServer = firstCSV(sub.OptionData.DomainNameServers)
		}
		if sub.OptionData.NTPServers != "" {
			scope.NTPServer = firstCSV(sub.OptionData.NTPServers)
		}

		// Parse pool ranges from the pools field.
		// KeaPoolsField stores newline-separated range strings or CIDR subnets;
		// use the first entry as the primary range.
		if sub.Pools != "" {
			pools := splitKeaPools(sub.Pools)
			if len(pools) > 0 {
				scope.Range = parseKeaRange(pools[0])
			}
		}

		// Attach reservations that reference this subnet.
		for _, res := range resBySubnet[sub.UUID] {
			scope.StaticLeases = append(scope.StaticLeases, common.DHCPStaticLease{
				IPAddress:   res.IPAddress,
				MAC:         res.HWAddress,
				Hostname:    res.Hostname,
				Description: res.Description,
			})
		}

		scopes = append(scopes, scope)
	}

	return scopes
}

// splitKeaPools splits the newline-separated pool ranges from KeaPoolsField.
// Each entry is either "start-end" or "cidr/prefix". Empty entries are filtered.
func splitKeaPools(pools string) []string {
	var result []string
	for _, line := range strings.Split(pools, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// parseKeaRange converts a Kea pool range string ("start-end") to DHCPRange.
// CIDR entries (e.g., "10.0.0.0/24") are stored as-is in From with empty To.
func parseKeaRange(rangeStr string) common.DHCPRange {
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		return common.DHCPRange{From: rangeStr}
	}
	return common.DHCPRange{From: strings.TrimSpace(parts[0]), To: strings.TrimSpace(parts[1])}
}

// firstCSV returns the first value from a comma-separated string.
func firstCSV(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		return s[:i]
	}
	return s
}
