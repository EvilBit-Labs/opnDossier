package builder

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// writeNetworkSection writes the network configuration section to the markdown instance.
func (b *MarkdownBuilder) writeNetworkSection(md *markdown.Markdown, data *common.CommonDevice) {
	b.WriteInterfaceTable(
		md.H2("Network Configuration").H3("Interfaces"),
		data.Interfaces,
	)

	for _, iface := range data.Interfaces {
		name := iface.Name
		if name == "" {
			name = "unnamed"
		}
		sectionName := strings.ToUpper(name[:1]) + strings.ToLower(name[1:]) + " Interface"
		md.H3(sectionName)
		buildInterfaceDetails(md, iface)
	}
}

// BuildNetworkSection builds the network configuration section.
func (b *MarkdownBuilder) BuildNetworkSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeNetworkSection(md, data)
	return md.String()
}

// WriteInterfaceTable writes an interfaces table and returns md for chaining.
func (b *MarkdownBuilder) WriteInterfaceTable(md *markdown.Markdown, interfaces []common.Interface) *markdown.Markdown {
	return md.Table(*BuildInterfaceTableSet(interfaces))
}

// BuildInterfaceTableSet builds the table data for network interfaces.
func BuildInterfaceTableSet(interfaces []common.Interface) *markdown.TableSet {
	headers := []string{"Name", "Description", "IP Address", "CIDR", "Enabled"}

	rows := make([][]string, 0, len(interfaces))
	for _, iface := range interfaces {
		description := iface.Description
		if description == "" {
			description = iface.PhysicalIf
		}

		cidr := ""
		if iface.Subnet != "" {
			cidr = "/" + iface.Subnet
		}

		rows = append(rows, []string{
			fmt.Sprintf("`%s`", iface.Name),
			fmt.Sprintf("`%s`", formatters.EscapeTableContent(description)),
			fmt.Sprintf("`%s`", iface.IPAddress),
			cidr,
			formatters.FormatBool(iface.Enabled),
		})
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// buildInterfaceDetails renders the property details for a single network interface into the markdown builder.
func buildInterfaceDetails(md *markdown.Markdown, iface common.Interface) {
	// Build a list of interface properties that are set
	if iface.PhysicalIf != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Physical Interface"), iface.PhysicalIf).LF()
	}
	md.PlainTextf("%s: %s", markdown.Bold("Enabled"), formatters.FormatBool(iface.Enabled)).LF()
	if iface.IPAddress != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Address"), iface.IPAddress).LF()
	}
	if iface.Subnet != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv4 Subnet"), iface.Subnet).LF()
	}
	if iface.IPv6Address != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Address"), iface.IPv6Address).LF()
	}
	if iface.SubnetV6 != "" {
		md.PlainTextf("%s: %s", markdown.Bold("IPv6 Subnet"), iface.SubnetV6).LF()
	}
	if iface.Gateway != "" {
		md.PlainTextf("%s: %s", markdown.Bold("Gateway"), iface.Gateway).LF()
	}
	if iface.MTU != "" {
		md.PlainTextf("%s: %s", markdown.Bold("MTU"), iface.MTU).LF()
	}
	md.PlainTextf("%s: %s", markdown.Bold("Block Private Networks"), formatters.FormatBool(iface.BlockPrivate)).LF()
	md.PlainTextf("%s: %s", markdown.Bold("Block Bogon Networks"), formatters.FormatBool(iface.BlockBogons))
}

// WriteVLANTable writes a VLAN configurations table and returns md for chaining.
func (b *MarkdownBuilder) WriteVLANTable(md *markdown.Markdown, vlans []common.VLAN) *markdown.Markdown {
	return md.Table(*BuildVLANTableSet(vlans))
}

// BuildVLANTableSet builds the table data for VLAN configurations.
func BuildVLANTableSet(vlans []common.VLAN) *markdown.TableSet {
	headers := []string{
		"VLAN Interface",
		"Physical Interface",
		"VLAN Tag",
		"Description",
		"Created",
		"Updated",
	}

	rows := make([][]string, 0, len(vlans))

	if len(vlans) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "No VLANs configured", "-", "-",
		})
	} else {
		for _, vlan := range vlans {
			rows = append(rows, []string{
				formatters.EscapeTableContent(vlan.VLANIf),
				formatters.EscapeTableContent(vlan.PhysicalIf),
				vlan.Tag,
				formatters.EscapeTableContent(vlan.Description),
				vlan.Created,
				vlan.Updated,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteStaticRoutesTable writes a static routes table and returns md for chaining.
func (b *MarkdownBuilder) WriteStaticRoutesTable(
	md *markdown.Markdown,
	routes []common.StaticRoute,
) *markdown.Markdown {
	return md.Table(*BuildStaticRoutesTableSet(routes))
}

// BuildStaticRoutesTableSet builds the table data for static routes.
func BuildStaticRoutesTableSet(routes []common.StaticRoute) *markdown.TableSet {
	headers := []string{
		"Destination Network",
		"Gateway",
		"Description",
		"Status",
		"Created",
		"Updated",
	}

	rows := make([][]string, 0, len(routes))

	if len(routes) == 0 {
		rows = append(rows, []string{
			"-", "-", "No static routes configured", "-", "-", "-",
		})
	} else {
		for _, route := range routes {
			status := "**Enabled**"
			if route.Disabled {
				status = "Disabled"
			}

			rows = append(rows, []string{
				formatters.EscapeTableContent(route.Network),
				formatters.EscapeTableContent(route.Gateway),
				formatters.EscapeTableContent(route.Description),
				status,
				route.Created,
				route.Updated,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}
