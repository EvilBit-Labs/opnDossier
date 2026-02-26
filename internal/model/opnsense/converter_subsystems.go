package opnsense

import (
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// convertMonit maps doc.OPNsense.Monit to *common.MonitConfig.
// Returns nil if the Monit subsystem is not configured.
func (c *Converter) convertMonit(doc *schema.OpnSenseDocument) *common.MonitConfig {
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
func (c *Converter) convertMonitServices(services []schema.MonitService) []common.MonitServiceEntry {
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
func (c *Converter) convertMonitTests(tests []schema.MonitTest) []common.MonitTest {
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
func (c *Converter) convertNetflow(doc *schema.OpnSenseDocument) *common.NetflowConfig {
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
func (c *Converter) convertTrafficShaper(doc *schema.OpnSenseDocument) *common.TrafficShaperConfig {
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
func (c *Converter) convertCaptivePortal(doc *schema.OpnSenseDocument) *common.CaptivePortalConfig {
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
func (c *Converter) convertCron(doc *schema.OpnSenseDocument) *common.CronConfig {
	if doc.OPNsense.Cron.Jobs == "" {
		return nil
	}

	return &common.CronConfig{
		Jobs: doc.OPNsense.Cron.Jobs,
	}
}

// convertTrust maps doc.OPNsense.Trust to *common.TrustConfig.
// Returns nil if TLS trust settings are all at defaults.
func (c *Converter) convertTrust(doc *schema.OpnSenseDocument) *common.TrustConfig {
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
func (c *Converter) convertKeaDHCP(doc *schema.OpnSenseDocument) *common.KeaDHCPConfig {
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
		Subnets:      kea.Dhcp4.Subnets,
		Reservations: kea.Dhcp4.Reservations,
	}
}
