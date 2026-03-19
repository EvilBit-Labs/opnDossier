package builder

import (
	"bytes"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// writeServicesSection writes the service configuration section to the markdown instance.
func (b *MarkdownBuilder) writeServicesSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H2("Service Configuration").
		H3("DHCP Server")

	// DHCP Summary Table
	b.WriteDHCPSummaryTable(md, data.DHCP)

	// Per-scope detailed sections (only for scopes with additional config)
	for _, dhcp := range data.DHCP {
		hasStaticLeases := len(dhcp.StaticLeases) > 0
		hasNumberOptions := len(dhcp.NumberOptions) > 0
		hasAdvanced := HasAdvancedDHCPConfig(dhcp)
		hasIPv6 := HasDHCPv6Config(dhcp)

		if !hasStaticLeases && !hasNumberOptions && !hasAdvanced && !hasIPv6 {
			continue
		}

		// Capitalize interface name for header (defensive check for empty string)
		headerName := dhcp.Interface
		if dhcp.Interface != "" {
			headerName = strings.ToUpper(dhcp.Interface[:1]) + strings.ToLower(dhcp.Interface[1:])
		}
		md.H4(headerName + " DHCP Details")

		// Static leases table
		if hasStaticLeases {
			md.PlainTextf("%s:", markdown.Bold("Static Leases")).LF()
			b.WriteDHCPStaticLeasesTable(md, dhcp.StaticLeases)
		}

		// Number options table
		if hasNumberOptions {
			md.PlainTextf("%s:", markdown.Bold("DHCP Number Options")).LF()
			numOptRows := make([][]string, 0, len(dhcp.NumberOptions))
			for _, opt := range dhcp.NumberOptions {
				numOptRows = append(numOptRows, []string{
					formatters.EscapeTableContent(opt.Number),
					formatters.EscapeTableContent(opt.Type),
					formatters.EscapeTableContent(opt.Value),
				})
			}
			md.Table(markdown.TableSet{
				Header: []string{"Option Number", "Type", "Value"},
				Rows:   numOptRows,
			})
		}

		// Advanced options section
		if hasAdvanced {
			md.PlainTextf("%s:", markdown.Bold("Advanced DHCP Options")).LF()
			advItems := buildAdvancedDHCPItems(dhcp)
			md.BulletList(advItems...)
		}

		// DHCPv6 options section
		if hasIPv6 {
			md.PlainTextf("%s:", markdown.Bold("DHCPv6 Options")).LF()
			v6Items := buildDHCPv6Items(dhcp)
			md.BulletList(v6Items...)
		}
	}

	md.H3("DNS Resolver (Unbound)")
	if data.DNS.Unbound.Enabled {
		md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBool(data.DNS.Unbound.Enabled)).LF()
	}

	md.H3("SNMP")
	if data.SNMP.SysLocation != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Location"), data.SNMP.SysLocation).LF()
	}
	if data.SNMP.SysContact != "" {
		md.PlainTextf("%s: %s", markdown.Bold("System Contact"), data.SNMP.SysContact).LF()
	}
	if data.SNMP.ROCommunity != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Read-Only Community"), data.SNMP.ROCommunity).LF()
	}

	md.H3("NTP")
	if data.NTP.PreferredServer != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Preferred Server"), data.NTP.PreferredServer).LF()
	}

	if len(data.LoadBalancer.MonitorTypes) > 0 {
		rows := make([][]string, 0, len(data.LoadBalancer.MonitorTypes))
		for _, monitor := range data.LoadBalancer.MonitorTypes {
			rows = append(rows, []string{monitor.Name, monitor.Type, monitor.Description})
		}
		md.H3("Load Balancer Monitors").
			Table(markdown.TableSet{
				Header: []string{"Name", "Type", "Description"},
				Rows:   rows,
			})
	}
}

// BuildServicesSection builds the service configuration section.
func (b *MarkdownBuilder) BuildServicesSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeServicesSection(md, data)
	return md.String()
}

// WriteDHCPSummaryTable writes a DHCP scope summary table and returns md for chaining.
func (b *MarkdownBuilder) WriteDHCPSummaryTable(md *markdown.Markdown, scopes []common.DHCPScope) *markdown.Markdown {
	return md.Table(*BuildDHCPSummaryTableSet(scopes))
}

// BuildDHCPSummaryTableSet builds the table data for DHCP scope summary.
func BuildDHCPSummaryTableSet(scopes []common.DHCPScope) *markdown.TableSet {
	headers := []string{
		"Interface",
		"Enabled",
		"Gateway",
		"Range Start",
		"Range End",
		"DNS",
		"WINS",
		"NTP",
	}

	rows := make([][]string, 0, len(scopes))

	if len(scopes) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-",
			"No DHCP scopes configured",
		})
	} else {
		for _, scope := range scopes {
			rows = append(rows, []string{
				formatters.EscapeTableContent(scope.Interface),
				formatters.FormatBool(scope.Enabled),
				formatters.EscapeTableContent(scope.Gateway),
				formatters.EscapeTableContent(scope.Range.From),
				formatters.EscapeTableContent(scope.Range.To),
				formatters.EscapeTableContent(scope.DNSServer),
				formatters.EscapeTableContent(scope.WINSServer),
				formatters.EscapeTableContent(scope.NTPServer),
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteDHCPStaticLeasesTable writes a static DHCP leases table and returns md for chaining.
func (b *MarkdownBuilder) WriteDHCPStaticLeasesTable(
	md *markdown.Markdown,
	leases []common.DHCPStaticLease,
) *markdown.Markdown {
	return md.Table(*BuildDHCPStaticLeasesTableSet(leases))
}

// BuildDHCPStaticLeasesTableSet builds the table data for static DHCP leases.
func BuildDHCPStaticLeasesTableSet(leases []common.DHCPStaticLease) *markdown.TableSet {
	headers := []string{
		"Hostname",
		"MAC",
		"IP",
		"CID",
		"Filename",
		"Rootpath",
		"Default Lease",
		"Max Lease",
		"Description",
	}

	rows := make([][]string, 0, len(leases))

	if len(leases) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-", "-",
			"No static leases configured",
		})
	} else {
		for _, lease := range leases {
			rows = append(rows, []string{
				formatters.EscapeTableContent(lease.Hostname),
				formatters.EscapeTableContent(lease.MAC),
				formatters.EscapeTableContent(lease.IPAddress),
				formatters.EscapeTableContent(lease.CID),
				formatters.EscapeTableContent(lease.Filename),
				formatters.EscapeTableContent(lease.Rootpath),
				FormatLeaseTime(lease.DefaultLeaseTime),
				FormatLeaseTime(lease.MaxLeaseTime),
				formatters.EscapeTableContent(lease.Description),
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}
