package builder

import (
	"bytes"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// writeSystemSection writes the system configuration section to the markdown instance.
func (b *MarkdownBuilder) writeSystemSection(md *markdown.Markdown, data *common.CommonDevice) {
	sys := data.System
	md.H2("System Configuration")

	writeSystemBasics(md, sys)
	writeSystemWebGUI(md, sys)
	writeSystemSettings(md, sys)
	writeSystemHardwareOffloading(md, sys)
	writeSystemPowerManagement(md, sys)
	writeSystemFeatures(md, sys)
	writeSystemMisc(md, sys)

	if len(data.Users) > 0 {
		b.WriteUserTable(md.H3("System Users"), data.Users)
	}
	if len(data.Groups) > 0 {
		b.WriteGroupTable(md.H3("System Groups"), data.Groups)
	}
}

func writeSystemBasics(md *markdown.Markdown, sys common.System) {
	md.H3("Basic Information").
		PlainTextf("%s: %s", markdown.Bold("Hostname"), sys.Hostname).LF().
		PlainTextf("%s: %s", markdown.Bold("Domain"), sys.Domain).LF()

	if sys.Optimization != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Optimization"), sys.Optimization).LF()
	}
	if sys.Timezone != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Timezone"), sys.Timezone).LF()
	}
	if sys.Language != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Language"), sys.Language).LF()
	}
}

func writeSystemWebGUI(md *markdown.Markdown, sys common.System) {
	if sys.WebGUI.Protocol == "" {
		return
	}
	md.H3("Web GUI Configuration").
		PlainTextf("%s: %s", markdown.Bold("Protocol"), sys.WebGUI.Protocol).LF()
}

func writeSystemSettings(md *markdown.Markdown, sys common.System) {
	md.H3("System Settings").
		PlainTextf("%s: %s", markdown.Bold("DNS Allow Override"), formatters.FormatBool(sys.DNSAllowOverride)).LF().
		PlainTextf("%s: %d", markdown.Bold("Next UID"), sys.NextUID).LF().
		PlainTextf("%s: %d", markdown.Bold("Next GID"), sys.NextGID).LF()

	if len(sys.TimeServers) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("Time Servers"), strings.Join(sys.TimeServers, ", ")).LF()
	}
	if len(sys.DNSServers) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("DNS Server"), strings.Join(sys.DNSServers, ", ")).LF()
	}
}

func writeSystemHardwareOffloading(md *markdown.Markdown, sys common.System) {
	md.H3("Hardware Offloading").
		PlainTextf("%s: %s", markdown.Bold("Disable NAT Reflection"), formatters.FormatBool(sys.DisableNATReflection)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("Use Virtual Terminal"), formatters.FormatBool(sys.UseVirtualTerminal)).LF().
		PlainTextf("%s: %s", markdown.Bold("Disable Console Menu"), formatters.FormatBool(sys.DisableConsoleMenu)).LF().
		PlainTextf("%s: %s", markdown.Bold("Disable VLAN HW Filter"), formatters.FormatBool(sys.DisableVLANHWFilter)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("Disable Checksum Offloading"), formatters.FormatBool(sys.DisableChecksumOffloading)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("Disable Segmentation Offloading"), formatters.FormatBool(sys.DisableSegmentationOffloading)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("Disable Large Receive Offloading"), formatters.FormatBool(sys.DisableLargeReceiveOffloading)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("IPv6 Allow"), formatters.FormatBool(sys.IPv6Allow)).LF()
}

func writeSystemPowerManagement(md *markdown.Markdown, sys common.System) {
	md.H3("Power Management").
		PlainTextf("%s: %s", markdown.Bold("Powerd AC Mode"), formatters.GetPowerModeDescriptionCompact(sys.PowerdACMode)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("Powerd Battery Mode"), formatters.GetPowerModeDescriptionCompact(sys.PowerdBatteryMode)).
		LF().
		PlainTextf("%s: %s", markdown.Bold("Powerd Normal Mode"), formatters.GetPowerModeDescriptionCompact(sys.PowerdNormalMode)).
		LF()
}

func writeSystemFeatures(md *markdown.Markdown, sys common.System) {
	md.H3("System Features").
		PlainTextf("%s: %s", markdown.Bold("PF Share Forward"), formatters.FormatBool(sys.PfShareForward)).LF().
		PlainTextf("%s: %s", markdown.Bold("LB Use Sticky"), formatters.FormatBool(sys.LbUseSticky)).LF().
		PlainTextf("%s: %s", markdown.Bold("RRD Backup"), formatters.FormatBool(sys.RrdBackup)).LF().
		PlainTextf("%s: %s", markdown.Bold("Netflow Backup"), formatters.FormatBool(sys.NetflowBackup))
}

func writeSystemMisc(md *markdown.Markdown, sys common.System) {
	if sys.Bogons.Interval != "" {
		md.H3("Bogons Configuration").
			PlainTextf("%s: %s", markdown.Bold("Interval"), sys.Bogons.Interval).LF()
	}
	if sys.SSH.Group != "" {
		md.H3("SSH Configuration").
			PlainTextf("%s: %s", markdown.Bold("Group"), sys.SSH.Group).LF()
	}
	if sys.Firmware.Version != "" {
		md.H3("Firmware Information").
			PlainTextf("%s: %s", markdown.Bold("Version"), sys.Firmware.Version).LF()
	}
}

// BuildSystemSection builds the system configuration section.
func (b *MarkdownBuilder) BuildSystemSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeSystemSection(md, data)
	return md.String()
}

// WriteUserTable writes a users table and returns md for chaining.
func (b *MarkdownBuilder) WriteUserTable(md *markdown.Markdown, users []common.User) *markdown.Markdown {
	return md.Table(*BuildUserTableSet(users))
}

// BuildUserTableSet builds the table data for system users.
func BuildUserTableSet(users []common.User) *markdown.TableSet {
	headers := []string{"Name", "Description", "Group", "Scope"}

	rows := make([][]string, 0, len(users))
	for _, user := range users {
		rows = append(rows, []string{
			formatters.EscapeTableContent(user.Name),
			formatters.EscapeTableContent(user.Description),
			formatters.EscapeTableContent(user.GroupName),
			formatters.EscapeTableContent(user.Scope),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteGroupTable writes a groups table and returns md for chaining.
func (b *MarkdownBuilder) WriteGroupTable(md *markdown.Markdown, groups []common.Group) *markdown.Markdown {
	return md.Table(*BuildGroupTableSet(groups))
}

// BuildGroupTableSet builds the table data for system groups.
func BuildGroupTableSet(groups []common.Group) *markdown.TableSet {
	headers := []string{"Name", "Description", "Scope"}

	rows := make([][]string, 0, len(groups))
	for _, group := range groups {
		rows = append(rows, []string{
			formatters.EscapeTableContent(group.Name),
			formatters.EscapeTableContent(group.Description),
			formatters.EscapeTableContent(group.Scope),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteSysctlTable writes a sysctl tunables table and returns md for chaining.
func (b *MarkdownBuilder) WriteSysctlTable(md *markdown.Markdown, sysctl []common.SysctlItem) *markdown.Markdown {
	return md.Table(*BuildSysctlTableSet(sysctl))
}

// BuildSysctlTableSet builds the table data for system tunables.
func BuildSysctlTableSet(sysctl []common.SysctlItem) *markdown.TableSet {
	headers := []string{"Tunable", "Value", "Description"}

	rows := make([][]string, 0, len(sysctl))
	for _, item := range sysctl {
		rows = append(rows, []string{
			formatters.EscapeTableContent(item.Tunable),
			formatters.EscapeTableContent(item.Value),
			formatters.EscapeTableContent(item.Description),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}
