package processor

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nao1215/markdown"
)

// ToMarkdown returns the report formatted as Markdown using the markdown library.
func (r *Report) ToMarkdown() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)

	r.addHeader(md)
	r.addConfigInfo(md)

	if r.Statistics != nil {
		r.addStatistics(md)
	}

	r.addFindingsUnsafe(md)

	if err := md.Build(); err != nil {
		return "# OPNsense Configuration Analysis Report\n\nError generating report.\n"
	}

	return buf.String()
}

// Helper functions for Markdown generation

// addHeader writes the top-level report title and generation timestamp to the markdown document.
// Caller must hold mu.
func (r *Report) addHeader(md *markdown.Markdown) {
	md.H1("OPNsense Configuration Analysis Report").
		PlainTextf("Generated: %s", r.GeneratedAt.Format(time.RFC3339)).
		LF()
}

// addConfigInfo writes the configuration metadata section (hostname, domain, version, theme) to the markdown document.
// Caller must hold mu.
func (r *Report) addConfigInfo(md *markdown.Markdown) {
	md.H2("Configuration Information")
	configItems := []string{
		fmt.Sprintf("%s: %s", markdown.Bold("Hostname"), r.ConfigInfo.Hostname),
		fmt.Sprintf("%s: %s", markdown.Bold("Domain"), r.ConfigInfo.Domain),
	}
	if r.ConfigInfo.Version != "" {
		configItems = append(configItems, fmt.Sprintf("%s: %s", markdown.Bold("Version"), r.ConfigInfo.Version))
	}
	if r.ConfigInfo.Theme != "" {
		configItems = append(configItems, fmt.Sprintf("%s: %s", markdown.Bold("Theme"), r.ConfigInfo.Theme))
	}
	md.BulletList(configItems...)
	md.LF()
}

// addStatistics writes the configuration statistics overview and summary sections to the markdown document.
// Caller must hold mu.
func (r *Report) addStatistics(md *markdown.Markdown) {
	overviewItems := []string{
		fmt.Sprintf("%s: %d", markdown.Bold("Total Interfaces"), r.Statistics.TotalInterfaces),
		fmt.Sprintf("%s: %d", markdown.Bold("Firewall Rules"), r.Statistics.TotalFirewallRules),
		fmt.Sprintf("%s: %d", markdown.Bold("NAT Entries"), r.Statistics.NATEntries),
		fmt.Sprintf("%s: %d", markdown.Bold("DHCP Scopes"), r.Statistics.DHCPScopes),
		fmt.Sprintf("%s: %d", markdown.Bold("Users"), r.Statistics.TotalUsers),
		fmt.Sprintf("%s: %d", markdown.Bold("Groups"), r.Statistics.TotalGroups),
		fmt.Sprintf("%s: %d", markdown.Bold("Services"), r.Statistics.TotalServices),
		fmt.Sprintf("%s: %d", markdown.Bold("Sysctl Settings"), r.Statistics.SysctlSettings),
	}

	summaryItems := []string{
		fmt.Sprintf("%s: %d", markdown.Bold("Total Configuration Items"), r.Statistics.Summary.TotalConfigItems),
		fmt.Sprintf("%s: %d/100", markdown.Bold("Security Score"), r.Statistics.Summary.SecurityScore),
		fmt.Sprintf("%s: %d/100", markdown.Bold("Configuration Complexity"), r.Statistics.Summary.ConfigComplexity),
		fmt.Sprintf("%s: %t", markdown.Bold("Has Security Features"), r.Statistics.Summary.HasSecurityFeatures),
	}

	md.
		H2("Configuration Statistics").
		H3("Overview").
		BulletList(overviewItems...).
		LF().
		H3("Summary Metrics").
		BulletList(summaryItems...).
		LF()

	addInterfaceDetails(md, "Interface Details", r.Statistics.InterfaceDetails)
	addStatisticsList(md, "Firewall Rules by Interface", r.Statistics.RulesByInterface, " rules")
	addStatisticsList(md, "Firewall Rules by Type", r.Statistics.RulesByType, " rules")
	addDHCPScopeDetails(md, "DHCP Scope Details", r.Statistics.DHCPScopeDetails)
	addStatisticsList(md, "Users by Scope", r.Statistics.UsersByScope, " users")
	addStatisticsList(md, "Groups by Scope", r.Statistics.GroupsByScope, " groups")

	if len(r.Statistics.EnabledServices) > 0 {
		md.H3("Enabled Services").
			BulletList(r.Statistics.EnabledServices...).
			LF()
	}

	if len(r.Statistics.ServiceDetails) > 0 {
		md.H3("Service Details")
		for _, service := range r.Statistics.ServiceDetails {
			serviceItems := []string{
				fmt.Sprintf("%s: %t", markdown.Bold("Enabled"), service.Enabled),
			}
			// Sort detail keys for deterministic output
			detailKeys := slices.Sorted(maps.Keys(service.Details))
			for _, k := range detailKeys {
				serviceItems = append(serviceItems, fmt.Sprintf("%s: %s", markdown.Bold(k), service.Details[k]))
			}

			md.
				H4(service.Name).
				BulletList(serviceItems...).
				LF()
		}
	}

	if len(r.Statistics.SecurityFeatures) > 0 {
		md.
			H3("Security Features").
			BulletList(r.Statistics.SecurityFeatures...).
			LF()
	}

	if r.Statistics.NATMode != "" {
		natItems := []string{
			fmt.Sprintf("%s: %s", markdown.Bold("NAT Mode"), r.Statistics.NATMode),
			fmt.Sprintf("%s: %d", markdown.Bold("NAT Entries"), r.Statistics.NATEntries),
		}
		md.
			H3("NAT Configuration").
			BulletList(natItems...).
			LF()
	}

	if r.Statistics.LoadBalancerMonitors > 0 {
		lbItems := []string{
			fmt.Sprintf("%s: %d", markdown.Bold("Monitors"), r.Statistics.LoadBalancerMonitors),
		}
		md.
			H3("Load Balancer").
			BulletList(lbItems...).
			LF()
	}

	if r.Statistics.IDSEnabled {
		idsItems := []string{
			markdown.Bold("Status") + ": Enabled",
			fmt.Sprintf("%s: %s", markdown.Bold("Mode"), r.Statistics.IDSMode),
		}
		if len(r.Statistics.IDSMonitoredInterfaces) > 0 {
			idsItems = append(idsItems, fmt.Sprintf("%s: %s",
				markdown.Bold("Monitored Interfaces"),
				strings.Join(r.Statistics.IDSMonitoredInterfaces, ", ")))
		}
		if r.Statistics.IDSDetectionProfile != "" {
			idsItems = append(idsItems, fmt.Sprintf("%s: %s",
				markdown.Bold("Detection Profile"), r.Statistics.IDSDetectionProfile))
		}
		idsItems = append(idsItems, fmt.Sprintf("%s: %t",
			markdown.Bold("Logging Enabled"), r.Statistics.IDSLoggingEnabled))

		md.
			H3("IDS/IPS Configuration").
			BulletList(idsItems...).
			LF()
	}
}

// addFindingsUnsafe adds findings to markdown. Caller must hold mu.
func (r *Report) addFindingsUnsafe(md *markdown.Markdown) {
	md.H2("Analysis Findings")
	if r.totalFindingsUnsafe() == 0 {
		md.
			PlainText("No findings to report.").
			LF()
		return
	}

	md.
		PlainText(fmt.Sprintf("Total findings: %d", r.totalFindingsUnsafe())).
		LF()

	r.addFindingsSection(md, "Critical", r.Findings.Critical)
	r.addFindingsSection(md, "High", r.Findings.High)
	r.addFindingsSection(md, "Medium", r.Findings.Medium)
	r.addFindingsSection(md, "Low", r.Findings.Low)
	r.addFindingsSection(md, "Informational", r.Findings.Info)
}

// addStatisticsList renders a sorted bullet list of named integer statistics under the given title,
// appending suffix to each value.
func addStatisticsList(md *markdown.Markdown, title string, stats map[string]int, suffix string) {
	if len(stats) == 0 {
		return
	}
	// Sort keys for deterministic output
	keys := slices.Sorted(maps.Keys(stats))
	items := make([]string, 0, len(keys))
	for _, k := range keys {
		items = append(items, fmt.Sprintf("%s: %d%s", markdown.Bold(k), stats[k], suffix))
	}
	md.
		H3(title).
		BulletList(items...).
		LF()
}

// addInterfaceDetails renders a table of interface statistics (type, enabled state, addressing, blocking) under the given title.
func addInterfaceDetails(md *markdown.Markdown, title string, details []InterfaceStatistics) {
	if len(details) == 0 {
		return
	}
	table := markdown.TableSet{
		Header: []string{"Interface", "Type", "Enabled", "IPv4", "IPv6", "DHCP", "Block Private", "Block Bogons"},
		Rows:   [][]string{},
	}
	for _, detail := range details {
		table.Rows = append(table.Rows, []string{
			detail.Name,
			detail.Type,
			strconv.FormatBool(detail.Enabled),
			strconv.FormatBool(detail.HasIPv4),
			strconv.FormatBool(detail.HasIPv6),
			strconv.FormatBool(detail.HasDHCP),
			strconv.FormatBool(detail.BlockPriv),
			strconv.FormatBool(detail.BlockBogons),
		})
	}

	md.
		H3(title).
		Table(table).
		LF()
}

// addDHCPScopeDetails renders a table of DHCP scope statistics (interface, enabled state, address range) under the given title.
func addDHCPScopeDetails(md *markdown.Markdown, title string, details []DHCPScopeStatistics) {
	if len(details) == 0 {
		return
	}
	table := markdown.TableSet{
		Header: []string{"Interface", "Enabled", "Range Start", "Range End"},
		Rows:   [][]string{},
	}
	for _, detail := range details {
		table.Rows = append(table.Rows, []string{
			detail.Interface,
			strconv.FormatBool(detail.Enabled),
			detail.From,
			detail.To,
		})
	}
	md.
		H3(title).
		Table(table).
		LF()
}

// Summary returns a brief summary of the report.
func (r *Report) Summary() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)

	// Title with hostname
	hostname := r.ConfigInfo.Hostname
	if r.ConfigInfo.Domain != "" {
		hostname += "." + r.ConfigInfo.Domain
	}
	md.
		PlainText("OPNsense Configuration Report for " + hostname).
		LF()

	// Configuration statistics
	if r.Statistics != nil {
		md.
			PlainTextf("Configuration contains %d interfaces, %d firewall rules, %d users, and %d groups.",
				r.Statistics.TotalInterfaces,
				r.Statistics.TotalFirewallRules,
				r.Statistics.TotalUsers,
				r.Statistics.TotalGroups).
			LF()
	}

	// Findings summary
	totalFindings := r.totalFindingsUnsafe()
	if totalFindings == 0 {
		md.PlainText("No issues found in the configuration.")
	} else {
		parts := []string{}
		if len(r.Findings.Critical) > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", len(r.Findings.Critical)))
		}
		if len(r.Findings.High) > 0 {
			parts = append(parts, fmt.Sprintf("%d high", len(r.Findings.High)))
		}
		if len(r.Findings.Medium) > 0 {
			parts = append(parts, fmt.Sprintf("%d medium", len(r.Findings.Medium)))
		}
		if len(r.Findings.Low) > 0 {
			parts = append(parts, fmt.Sprintf("%d low", len(r.Findings.Low)))
		}
		if len(r.Findings.Info) > 0 {
			parts = append(parts, fmt.Sprintf("%d info", len(r.Findings.Info)))
		}

		md.PlainTextf("Analysis found %d findings: %s.", totalFindings, strings.Join(parts, ", "))
	}

	if err := md.Build(); err != nil {
		return fmt.Sprintf("Error generating summary: %v", err)
	}

	return buf.String()
}

// addFindingsSection adds a findings section using the markdown library.
// Caller must hold mu.
func (r *Report) addFindingsSection(md *markdown.Markdown, title string, findings []Finding) {
	if len(findings) == 0 {
		return
	}

	md.H3(fmt.Sprintf("%s (%d)", title, len(findings)))

	for i, finding := range findings {
		md.H4(fmt.Sprintf("%d. %s", i+1, finding.Title))

		findingItems := []string{
			fmt.Sprintf("%s: %s", markdown.Bold("Type"), finding.Type),
		}

		if finding.Component != "" {
			findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Component"), finding.Component))
		}

		findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Description"), finding.Description))

		if finding.Recommendation != "" {
			findingItems = append(
				findingItems,
				fmt.Sprintf("%s: %s", markdown.Bold("Recommendation"), finding.Recommendation),
			)
		}

		if finding.Reference != "" {
			findingItems = append(findingItems, fmt.Sprintf("%s: %s", markdown.Bold("Reference"), finding.Reference))
		}

		md.
			BulletList(findingItems...).
			HorizontalRule().
			LF()
	}
}
