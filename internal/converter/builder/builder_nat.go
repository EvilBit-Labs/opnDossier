package builder

import (
	"fmt"
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// WriteOutboundNATTable writes an outbound NAT rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteOutboundNATTable(md *markdown.Markdown, rules []common.NATRule) *markdown.Markdown {
	return md.Table(*BuildOutboundNATTableSet(rules))
}

// BuildOutboundNATTableSet builds the table data for outbound NAT rules.
func BuildOutboundNATTableSet(rules []common.NATRule) *markdown.TableSet {
	headers := []string{
		"#",
		"Direction",
		"Interface",
		"Source",
		"Destination",
		"Target",
		"Protocol",
		"Description",
		"Status",
	}

	rows := make([][]string, 0, len(rules))

	if len(rules) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-",
			"No outbound NAT rules configured",
			"-",
		})
	} else {
		for i, rule := range rules {
			source := rule.Source.Address
			if source == "" {
				source = destinationAny
			}

			dest := rule.Destination.Address
			if dest == "" {
				dest = destinationAny
			}

			protocol := rule.Protocol
			if protocol == "" {
				protocol = destinationAny
			}

			target := rule.Target
			if target != "" {
				target = fmt.Sprintf("`%s`", target)
			}

			status := "**Active**"
			if rule.Disabled {
				status = "**Disabled**"
			}

			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

			rows = append(rows, []string{
				strconv.Itoa(i + 1),
				"⬆️ Outbound",
				interfaceLinks,
				source,
				dest,
				target,
				protocol,
				formatters.EscapeTableContent(rule.Description),
				status,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}

// WriteInboundNATTable writes an inbound NAT rules table and returns md for chaining.
func (b *MarkdownBuilder) WriteInboundNATTable(
	md *markdown.Markdown,
	rules []common.InboundNATRule,
) *markdown.Markdown {
	return md.Table(*BuildInboundNATTableSet(rules))
}

// BuildInboundNATTableSet builds the table data for inbound NAT rules.
func BuildInboundNATTableSet(rules []common.InboundNATRule) *markdown.TableSet {
	headers := []string{
		"#",
		"Direction",
		"Interface",
		"External Port",
		"Target IP",
		"Target Port",
		"Protocol",
		"Description",
		"Priority",
		"Status",
	}

	rows := make([][]string, 0, len(rules))

	if len(rules) == 0 {
		rows = append(rows, []string{
			"-", "-", "-", "-", "-", "-", "-",
			"No inbound NAT rules configured",
			"-", "-",
		})
	} else {
		for i, rule := range rules {
			protocol := rule.Protocol
			if protocol == "" {
				protocol = destinationAny
			}

			targetIP := rule.InternalIP
			if targetIP != "" {
				targetIP = fmt.Sprintf("`%s`", targetIP)
			}

			status := "**Active**"
			if rule.Disabled {
				status = "**Disabled**"
			}

			interfaceLinks := formatters.FormatInterfacesAsLinks(rule.Interfaces)

			rows = append(rows, []string{
				strconv.Itoa(i + 1),
				"⬇️ Inbound",
				interfaceLinks,
				rule.ExternalPort,
				targetIP,
				rule.InternalPort,
				protocol,
				formatters.EscapeTableContent(rule.Description),
				strconv.Itoa(rule.Priority),
				status,
			})
		}
	}

	return &markdown.TableSet{
		Header: headers,
		Rows:   rows,
	}
}
