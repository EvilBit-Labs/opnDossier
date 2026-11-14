package builder

import (
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/nao1215/markdown"
)

// TestWriteServicesSection_DnsmasqRangeV6 shows the DHCPv6 range of a
// dnsmasq scope, which the summary table has no column for.
func TestWriteServicesSection_DnsmasqRangeV6(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	md := markdown.NewMarkdown(&buf)
	NewMarkdownBuilder().writeServicesSection(md, &common.CommonDevice{
		DHCP: []common.DHCPScope{{
			Interface: "lan",
			Source:    common.DHCPSourceDnsmasq,
			Enabled:   true,
			Range:     common.DHCPRange{From: "192.168.1.100", To: "192.168.1.199"},
			RangeV6:   &common.DHCPRange{From: "::1000", To: "::2000"},
		}},
	})

	output := md.String()
	if !strings.Contains(output, "#### Lan DHCP Details") {
		t.Errorf("expected a details section for the scope, got:\n%s", output)
	}
	if !strings.Contains(output, "**DHCPv6 Range**: ::1000 - ::2000") {
		t.Errorf("expected the DHCPv6 range, got:\n%s", output)
	}
}
