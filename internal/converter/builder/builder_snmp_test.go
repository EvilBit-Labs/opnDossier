package builder

import (
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestBuildServicesSection_SNMPAgentDetails checks that an agent with no
// community still shows in the SNMP section, through its state, listen
// addresses and SNMPv3 users.
func TestBuildServicesSection_SNMPAgentDetails(t *testing.T) {
	t.Parallel()

	out := NewMarkdownBuilder().BuildServicesSection(&common.CommonDevice{
		SNMP: common.SNMPConfig{
			Enabled:         true,
			ListenAddresses: []string{"192.0.2.1", "2001:db8::1"},
			Users: []common.SNMPUser{
				{Username: "poller"},
				{Username: "config_push", ReadWrite: true},
			},
		},
	})

	for _, want := range []string{
		"**Enabled**: " + formatters.FormatBool(true),
		"**Listen Addresses**: 192.0.2.1, 2001:db8::1",
		"**SNMPv3 Users**:",
		"- poller (read-only)",
		`- config\_push (read-write)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("services section missing %q:\n%s", want, out)
		}
	}

	empty := NewMarkdownBuilder().BuildServicesSection(&common.CommonDevice{})
	if strings.Contains(empty, "SNMPv3 Users") || strings.Contains(empty, "Listen Addresses") {
		t.Errorf("services section without an agent shows agent details:\n%s", empty)
	}
}
