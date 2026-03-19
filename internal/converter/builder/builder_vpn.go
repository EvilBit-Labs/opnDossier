package builder

import (
	"bytes"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// writeIPsecSection writes the IPsec VPN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeIPsecSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H3("IPsec VPN Configuration")

	ipsec := data.VPN.IPsec
	if !ipsec.Enabled {
		md.PlainText(markdown.Italic("No IPsec configuration present"))
		return
	}

	md.H4("General Configuration").
		Table(markdown.TableSet{
			Header: []string{"Setting", "Value"},
			Rows: [][]string{
				{"**Enabled**", formatters.FormatBool(ipsec.Enabled)},
			},
		})

	md.Note("Phase 1/Phase 2 tunnel configurations require additional parser implementation")
}

// BuildIPsecSection builds the IPsec VPN configuration section.
func (b *MarkdownBuilder) BuildIPsecSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeIPsecSection(md, data)
	return md.String()
}

// writeOpenVPNSection writes the OpenVPN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeOpenVPNSection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H3("OpenVPN Configuration")

	openvpn := data.VPN.OpenVPN

	// OpenVPN Servers
	if len(openvpn.Servers) == 0 {
		md.H4("OpenVPN Servers").
			PlainText(markdown.Italic("No OpenVPN servers configured"))
	} else {
		serverRows := make([][]string, 0, len(openvpn.Servers))
		for _, server := range openvpn.Servers {
			serverRows = append(serverRows, []string{
				formatters.EscapeTableContent(server.Description),
				server.Mode,
				server.Protocol,
				server.Interface,
				server.LocalPort,
				formatters.EscapeTableContent(server.TunnelNetwork),
				formatters.EscapeTableContent(server.RemoteNetwork),
				formatters.EscapeTableContent(server.CertRef),
			})
		}
		md.H4("OpenVPN Servers").
			Table(markdown.TableSet{
				Header: []string{
					"Description",
					"Mode",
					"Protocol",
					"Interface",
					"Port",
					"Tunnel Network",
					"Remote Network",
					"Certificate",
				},
				Rows: serverRows,
			})
	}

	// OpenVPN Clients
	if len(openvpn.Clients) == 0 {
		md.H4("OpenVPN Clients").
			PlainText(markdown.Italic("No OpenVPN clients configured"))
	} else {
		clientRows := make([][]string, 0, len(openvpn.Clients))
		for _, client := range openvpn.Clients {
			clientRows = append(clientRows, []string{
				formatters.EscapeTableContent(client.Description),
				formatters.EscapeTableContent(client.ServerAddr),
				client.ServerPort,
				client.Mode,
				client.Protocol,
				formatters.EscapeTableContent(client.CertRef),
			})
		}
		md.H4("OpenVPN Clients").
			Table(markdown.TableSet{
				Header: []string{
					"Description",
					"Server Address",
					"Port",
					"Mode",
					"Protocol",
					"Certificate",
				},
				Rows: clientRows,
			})
	}
}

// BuildOpenVPNSection builds the OpenVPN configuration section with servers, clients, and CSC.
func (b *MarkdownBuilder) BuildOpenVPNSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeOpenVPNSection(md, data)
	return md.String()
}

// writeVLANSection writes the VLAN configuration section to the markdown instance.
func (b *MarkdownBuilder) writeVLANSection(md *markdown.Markdown, data *common.CommonDevice) {
	b.WriteVLANTable(md.H3("VLAN Configuration"), data.VLANs)
}

// buildVLANSection builds the VLAN configuration section wrapper.
func (b *MarkdownBuilder) buildVLANSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeVLANSection(md, data)
	return md.String()
}

// writeStaticRoutesSection writes the static routes section to the markdown instance.
func (b *MarkdownBuilder) writeStaticRoutesSection(md *markdown.Markdown, data *common.CommonDevice) {
	b.WriteStaticRoutesTable(md.H3("Static Routes"), data.Routing.StaticRoutes)
}

// buildStaticRoutesSection builds the static routes section wrapper.
func (b *MarkdownBuilder) buildStaticRoutesSection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeStaticRoutesSection(md, data)
	return md.String()
}

// writeHASection writes the High Availability and CARP configuration section to the markdown instance.
func (b *MarkdownBuilder) writeHASection(md *markdown.Markdown, data *common.CommonDevice) {
	md.H3("High Availability & CARP")

	// Virtual IP Addresses
	if len(data.VirtualIPs) == 0 {
		md.H4("Virtual IP Addresses (CARP)").
			PlainText(markdown.Italic("No virtual IPs configured"))
	} else {
		vipRows := make([][]string, 0, len(data.VirtualIPs))
		for _, vip := range data.VirtualIPs {
			vipRows = append(vipRows, []string{
				formatters.EscapeTableContent(vip.Subnet),
				vip.Mode,
			})
		}
		md.H4("Virtual IP Addresses (CARP)").
			Table(markdown.TableSet{
				Header: []string{"VIP Address", "Type"},
				Rows:   vipRows,
			})
	}

	// HA Synchronization Settings
	hasync := data.HighAvailability

	if hasync.PfsyncInterface == "" && hasync.SynchronizeToIP == "" {
		md.H4("HA Synchronization Settings").
			PlainText(markdown.Italic("No HA synchronization configured"))
	} else {
		md.H4("HA Synchronization Settings").
			Table(markdown.TableSet{
				Header: []string{"Setting", "Value"},
				Rows: [][]string{
					{"**pfSync Interface**", formatters.EscapeTableContent(hasync.PfsyncInterface)},
					{"**pfSync Peer IP**", formatters.EscapeTableContent(hasync.PfsyncPeerIP)},
					{"**Configuration Sync IP**", formatters.EscapeTableContent(hasync.SynchronizeToIP)},
					{"**Sync Username**", formatters.EscapeTableContent(hasync.Username)},
					{"**Disable Preempt**", formatters.FormatBool(hasync.DisablePreempt)},
					{"**pfSync Version**", hasync.PfsyncVersion},
				},
			})
	}
}

// BuildHASection builds the High Availability and CARP configuration section.
func (b *MarkdownBuilder) BuildHASection(data *common.CommonDevice) string {
	var buf bytes.Buffer
	md := markdown.NewMarkdown(&buf)
	b.writeHASection(md, data)
	return md.String()
}
