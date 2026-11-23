package builder

import (
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// writeSNMPAgentDetails writes the agent state, its listen addresses and its
// SNMPv3 users. A v3-only agent has no community, so without these lines the
// SNMP section would read as empty while an agent runs.
func writeSNMPAgentDetails(md *markdown.Markdown, snmp common.SNMPConfig) {
	if snmp.Enabled {
		md.PlainTextf("%s: %s", markdown.Bold(labelEnabled), formatters.FormatBool(snmp.Enabled)).LF()
	}

	if len(snmp.ListenAddresses) > 0 {
		md.PlainTextf("%s: %s", markdown.Bold("Listen Addresses"),
			formatters.EscapeMarkdownValue(strings.Join(snmp.ListenAddresses, ", "))).LF()
	}

	if len(snmp.Users) == 0 {
		return
	}

	users := make([]string, 0, len(snmp.Users))
	for _, user := range snmp.Users {
		access := "read-only"
		if user.ReadWrite {
			access = "read-write"
		}

		users = append(users, formatters.EscapeMarkdownValue(user.Username)+" ("+access+")")
	}

	md.PlainTextf("%s:", markdown.Bold("SNMPv3 Users")).LF()
	md.BulletList(users...)
}
