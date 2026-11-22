package firewall_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFirewallPlugin_InterfaceInventory_SkipsPseudoInterfaces pins that the
// interface inventory counts the interfaces SANS-FW-003 counts. lo0 and the
// group entries OPNsense writes into <interfaces> are not network interfaces.
func TestFirewallPlugin_InterfaceInventory_SkipsPseudoInterfaces(t *testing.T) {
	t.Parallel()

	lo0 := common.Interface{Name: "lo0", Enabled: true, Type: "none", Virtual: true}
	group := common.Interface{Name: "mgmt", Enabled: true, Type: "group", Virtual: true}

	t.Run("counts only the network", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{Interfaces: []common.Interface{lo0, group, {Name: "wan", Enabled: true}}}

		findings, _, err := firewall.NewPlugin().RunChecks(device)
		require.NoError(t, err)

		f := inventoryFindingByRef(findings, controlInterfaceInventory)
		require.NotNil(t, f)
		assert.Contains(t, f.Description, "1 enabled network interface(s)")
	})

	t.Run("no finding with pseudo-interfaces only", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{Interfaces: []common.Interface{lo0, group}}

		findings, _, err := firewall.NewPlugin().RunChecks(device)
		require.NoError(t, err)
		assert.Nil(t, inventoryFindingByRef(findings, controlInterfaceInventory))
	})
}
