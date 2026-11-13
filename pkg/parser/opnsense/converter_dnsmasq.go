package opnsense

import (
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// knownDnsmasqVersions lists the Dnsmasq model versions whose element names
// the schema was checked against. The model arrived in 25.1.2 at 1.0.0, and
// the releases since wrote 1.0.5 (25.1.6), 1.0.6 (25.1.8), 1.0.7 (25.1.10 to
// 25.7), 1.0.8 (25.7.11 to 26.1) and 1.0.9 (26.7). Each of those versions
// only added fields, and the model has a single migration, M1_0_0, which
// renames nothing. A version not listed here may have moved an element the
// converter reads (GOTCHAS 3.7, 18.1).
var knownDnsmasqVersions = map[string]struct{}{
	dnsmasqFirstModelVersion: {},
	"1.0.5":                  {},
	"1.0.6":                  {},
	"1.0.7":                  {},
	"1.0.8":                  {},
	"1.0.9":                  {},
}

const (
	// dnsmasqFirstModelVersion is the version the Dnsmasq model shipped at.
	dnsmasqFirstModelVersion = "1.0.0"
)

// convertDNSMasq maps <dnsmasq> to common.DNSMasqConfig.
func (c *converter) convertDNSMasq(doc *schema.OpnSenseDocument) common.DNSMasqConfig {
	dm := doc.DNSMasquerade

	if dm.Version != "" {
		if _, ok := knownDnsmasqVersions[dm.Version]; !ok {
			c.addWarning(
				"DNS.DNSMasq.Version",
				dm.Version,
				"unrecognized OPNsense Dnsmasq MVC model version; element mapping may be stale",
				common.SeverityMedium,
			)
		}
	}

	return common.DNSMasqConfig{
		Enabled:         bool(dm.Enable),
		Hosts:           convertDnsmasqHosts(dm.Hosts),
		DomainOverrides: convertDnsmasqDomainOverrides(dm.DomainOverrides),
		Forwarders:      c.convertForwarders(dm.Forwarders),
	}
}

// convertDnsmasqHosts maps the <hosts> entries to DNS host overrides.
func convertDnsmasqHosts(hosts []schema.DNSMasqHost) []common.DNSMasqHost {
	if len(hosts) == 0 {
		return nil
	}

	result := make([]common.DNSMasqHost, 0, len(hosts))
	for _, h := range hosts {
		result = append(result, common.DNSMasqHost{
			Host:        h.Host,
			Domain:      h.Domain,
			IP:          h.IP,
			Description: h.Descr,
			Aliases:     []string(h.Aliases),
		})
	}

	return result
}

// convertDnsmasqDomainOverrides maps the <domainoverrides> entries.
func convertDnsmasqDomainOverrides(overrides []schema.DomainOverride) []common.DomainOverride {
	if len(overrides) == 0 {
		return nil
	}

	result := make([]common.DomainOverride, 0, len(overrides))
	for _, o := range overrides {
		result = append(result, common.DomainOverride{
			Domain:      o.Domain,
			IP:          o.IP,
			Description: o.Descr,
			Port:        o.Port,
			SourceIP:    o.SrcIP,
		})
	}

	return result
}
