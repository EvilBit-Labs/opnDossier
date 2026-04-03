package builder

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// writeSecuritySection writes the security configuration section to the markdown instance.
func (b *MarkdownBuilder) writeSecuritySection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Security Configuration").
		H3("NAT Configuration")

	natSummary := data.NATSummary()
	if natSummary.Mode != "" || data.NAT.OutboundMode != "" {
		md.H4("NAT Summary")
		mode := natSummary.Mode
		if mode == "" {
			mode = data.NAT.OutboundMode
		}
		md.PlainTextf("%s: %s", markdown.Bold("NAT Mode"), mode).LF().
			PlainTextf("%s: %s", markdown.Bold("NAT Reflection"), formatters.FormatBool(natSummary.ReflectionDisabled)).
			LF().
			PlainTextf(
				"%s: %s",
				markdown.Bold("Port Forward State Sharing"),
				formatters.FormatBool(natSummary.PfShareForward),
			).LF().
			PlainTextf("%s: %d", markdown.Bold("Outbound Rules"), len(natSummary.OutboundRules)).LF().
			PlainTextf("%s: %d", markdown.Bold("Inbound Rules"), len(natSummary.InboundRules))

		if natSummary.ReflectionDisabled {
			md.Note(
				"NAT reflection is properly disabled, preventing potential security issues where internal clients can access internal services via external IP addresses.",
			)
		} else {
			md.Warning(
				"NAT reflection is enabled, which may allow internal clients to access internal services via external IP addresses. Consider disabling if not needed.",
			)
		}
	}

	b.WriteOutboundNATTable(md.H4("Outbound NAT (Source Translation)"), natSummary.OutboundRules)
	b.WriteInboundNATTable(md.H4("Inbound NAT (Port Forwarding)"), natSummary.InboundRules)

	if len(natSummary.InboundRules) > 0 {
		md.Warning(
			"Inbound NAT rules (port forwarding) increase the attack surface by exposing internal services to external networks. Ensure these rules are necessary and properly secured.",
		)
	}

	if len(data.FirewallRules) > 0 {
		b.WriteFirewallRulesTable(md.H3("Firewall Rules"), data.FirewallRules)
	}

	// IDS/Suricata Configuration
	b.writeIDSSection(md, data)
}

// BuildSecuritySection builds the security configuration section.
func (b *MarkdownBuilder) BuildSecuritySection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeSecuritySection(md, data)
	return md.String()
}

// writeIDSSection writes the IDS/Suricata configuration section to the markdown instance.
func (b *MarkdownBuilder) writeIDSSection(md *markdown.Markdown, data *common.CommonDevice) {
	ids := data.IDS
	if ids == nil || !ids.Enabled {
		return
	}

	md.H3("Intrusion Detection System (IDS/Suricata)")

	// Detection mode
	detectionMode := "IDS"
	if ids.IPSMode {
		detectionMode = "IPS"
	}

	// Configuration summary table
	configRows := [][]string{
		{"**Status**", "Enabled"},
		{"**Mode**", detectionMode},
	}

	if ids.Detect.Profile != "" {
		configRows = append(configRows, []string{"**Detection Profile**", ids.Detect.Profile})
	}

	if ids.MPMAlgo != "" {
		configRows = append(configRows, []string{"**Pattern Matching Algorithm**", ids.MPMAlgo})
	}

	configRows = append(
		configRows,
		[]string{"**Promiscuous Mode**", formatters.FormatBoolStatus(ids.Promiscuous)},
	)

	if ids.DefaultPacketSize != "" {
		configRows = append(configRows, []string{"**Default Packet Size**", ids.DefaultPacketSize})
	}

	md.H4("Configuration Summary").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows:   configRows,
		})

	// Monitored interfaces
	if len(ids.Interfaces) > 0 {
		md.H4("Monitored Interfaces")
		interfaceItems := make([]string, 0, len(ids.Interfaces))
		for _, iface := range ids.Interfaces {
			interfaceItems = append(interfaceItems, fmt.Sprintf("`%s`", iface))
		}
		md.BulletList(interfaceItems...)
	}

	// Home networks
	if len(ids.HomeNetworks) > 0 {
		md.H4("Home Networks")
		netItems := make([]string, 0, len(ids.HomeNetworks))
		for _, net := range ids.HomeNetworks {
			netItems = append(netItems, fmt.Sprintf("`%s`", net))
		}
		md.BulletList(netItems...)
	}

	// Logging configuration
	logRows := [][]string{
		{"**Syslog**", formatters.FormatBoolStatus(ids.SyslogEnabled)},
		{"**EVE Syslog**", formatters.FormatBoolStatus(ids.SyslogEveEnabled)},
	}

	if ids.LogPayload != "" {
		logRows = append(logRows, []string{"**Payload Logging**", ids.LogPayload})
	}

	if ids.Verbosity != "" {
		logRows = append(logRows, []string{"**Verbosity**", ids.Verbosity})
	}

	if ids.AlertLogrotate != "" {
		logRows = append(logRows, []string{"**Log Rotation**", ids.AlertLogrotate})
	}

	if ids.AlertSaveLogs != "" {
		logRows = append(logRows, []string{"**Log Retention**", ids.AlertSaveLogs})
	}

	md.H4("Logging Configuration").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows:   logRows,
		})

	// Security notes
	if !ids.IPSMode {
		md.Tip(
			"Consider enabling IPS mode for active threat prevention. IDS mode only detects threats without blocking them.",
		)
	} else {
		md.Note(
			"IPS mode is active. Suricata will actively block detected threats based on configured rules.",
		)
	}

	if ids.SyslogEveEnabled {
		md.Note(
			"EVE JSON logging is enabled via syslog, which supports SIEM integration for centralized threat monitoring.",
		)
	}
}

// BuildIDSSection builds the IDS/Suricata configuration section.
func (b *MarkdownBuilder) BuildIDSSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeIDSSection(md, data)
	return md.String()
}

// WriteFirewallRulesTable writes a firewall rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteFirewallRulesTable(
	md *markdown.Markdown,
	rules []common.FirewallRule,
) *markdown.Markdown {
	return md.Table(*BuildFirewallRulesTableSet(rules))
}

// BuildFirewallRulesTableSet builds the table data for firewall rules.
func BuildFirewallRulesTableSet(rules []common.FirewallRule) *markdown.TableSet {
	headers := []string{
		"#",
		"Interface",
		"Action",
		"IP Ver",
		"Proto",
		"Source",
		"Destination",
		"Target",
		"Source Port",
		"Dest Port",
		"Enabled",
		"Description",
	}

	rows := make([][]string, 0, len(rules))
	for i, rule := range rules {
		source := rule.Source.Address
		if source == "" {
			source = destinationAny
		}

		dest := rule.Destination.Address
		if dest == "" {
			dest = destinationAny
		}

		interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			interfaceLinks,
			string(rule.Type),
			string(rule.IPProtocol),
			rule.Protocol,
			source,
			dest,
			rule.Target,
			formatters.EscapeTableContent(rule.Source.Port),
			formatters.EscapeTableContent(rule.Destination.Port),
			formatters.FormatBoolInverted(rule.Disabled),
			formatters.EscapeTableContent(rule.Description),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}
