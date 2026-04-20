package firewall_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	controlDHCPInventory      = "FIREWALL-062"
	controlInterfaceInventory = "FIREWALL-063"
)

// inventoryFindingByRef returns the first finding with the given Reference, or nil.
func inventoryFindingByRef(findings []compliance.Finding, ref string) *compliance.Finding {
	for i := range findings {
		if findings[i].Reference == ref {
			return &findings[i]
		}
	}

	return nil
}

func TestFirewallPlugin_InventoryChecks_DHCP(t *testing.T) {
	t.Parallel()

	fp := firewall.NewPlugin()

	t.Run("emits finding when ISC DHCP scopes present", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan", Source: common.DHCPSourceISC},
				{Interface: "guest", Source: common.DHCPSourceISC},
			},
		}

		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		f := inventoryFindingByRef(findings, controlDHCPInventory)
		require.NotNil(t, f, "expected FIREWALL-062 inventory finding")
		assert.Equal(t, "inventory", f.Type)
		assert.Equal(t, "info", f.Severity)
		assert.Contains(t, f.Description, "2 ISC DHCP scope(s)")
		assert.Contains(t, f.Description, "lan")
		assert.Contains(t, f.Description, "guest")
	})

	t.Run("emits finding when only Kea DHCP scopes present", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Source: common.DHCPSourceKea, Description: "LAN subnet"},
			},
		}

		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		f := inventoryFindingByRef(findings, controlDHCPInventory)
		require.NotNil(t, f, "expected FIREWALL-062 inventory finding for Kea scopes")
		assert.Equal(t, "inventory", f.Type)
		assert.Contains(t, f.Description, "1 Kea subnet(s)")
		assert.Contains(t, f.Description, "LAN subnet")
	})

	t.Run("emits finding with both ISC and Kea scopes", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan", Source: common.DHCPSourceISC},
				{Source: common.DHCPSourceKea, Description: "Server VLAN"},
			},
		}

		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		f := inventoryFindingByRef(findings, controlDHCPInventory)
		require.NotNil(t, f)
		assert.Contains(t, f.Description, "1 ISC DHCP scope(s)")
		assert.Contains(t, f.Description, "1 Kea subnet(s)")
	})

	t.Run("ISC scope without Source treated as ISC", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan"}, // Source empty → treated as ISC
			},
		}

		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		f := inventoryFindingByRef(findings, controlDHCPInventory)
		require.NotNil(t, f)
		assert.Contains(t, f.Description, "1 ISC DHCP scope(s)")
	})

	t.Run("no finding when DHCP scopes empty", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{}
		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		assert.Nil(t, inventoryFindingByRef(findings, controlDHCPInventory),
			"unexpected DHCP inventory finding when no DHCP scopes")
	})

	t.Run("no finding on nil device", func(t *testing.T) {
		t.Parallel()

		findings, _, err := fp.RunChecks(nil)
		require.NoError(t, err)
		assert.Nil(t, inventoryFindingByRef(findings, controlDHCPInventory),
			"unexpected DHCP inventory finding on nil device")
	})
}

func TestFirewallPlugin_InventoryChecks_Interfaces(t *testing.T) {
	t.Parallel()

	fp := firewall.NewPlugin()

	t.Run("emits finding when enabled interfaces exist", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			Interfaces: []common.Interface{
				{Name: "wan", Enabled: true},
				{Name: "lan", Enabled: true},
				{Name: "opt1", Enabled: false},
			},
		}

		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		f := inventoryFindingByRef(findings, controlInterfaceInventory)
		require.NotNil(t, f, "expected FIREWALL-063 inventory finding")
		assert.Equal(t, "inventory", f.Type)
		assert.Equal(t, "info", f.Severity)
		assert.Contains(t, f.Description, "2 enabled interface(s)")
	})

	t.Run("no finding when all interfaces disabled", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			Interfaces: []common.Interface{
				{Name: "opt1", Enabled: false},
			},
		}

		findings, _, err := fp.RunChecks(device)
		require.NoError(t, err)
		assert.Nil(t, inventoryFindingByRef(findings, controlInterfaceInventory),
			"unexpected interface inventory finding when no enabled interfaces")
	})
}

func TestFirewallPlugin_InventoryFindings_DoNotAppearInEvaluated(t *testing.T) {
	t.Parallel()

	fp := firewall.NewPlugin()
	device := &common.CommonDevice{
		DHCP: []common.DHCPScope{{Interface: "lan"}},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
		},
	}

	_, evaluated, err := fp.RunChecks(device)
	require.NoError(t, err)

	for _, id := range []string{controlDHCPInventory, controlInterfaceInventory} {
		assert.NotContains(t, evaluated, id,
			"inventory control %s must not appear in evaluated slice", id)
	}
}

func TestFirewallPlugin_InventoryFindings_HaveCorrectType(t *testing.T) {
	t.Parallel()

	fp := firewall.NewPlugin()
	device := &common.CommonDevice{
		DHCP: []common.DHCPScope{{Interface: "lan"}},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
		},
	}

	findings, _, err := fp.RunChecks(device)
	require.NoError(t, err)

	var inventoryCount int

	for _, f := range findings {
		if f.Type == "inventory" {
			inventoryCount++
			require.Contains(t, []string{controlDHCPInventory, controlInterfaceInventory}, f.Reference,
				"inventory finding should reference an inventory control")
		}
	}

	assert.Equal(t, 2, inventoryCount, "expected exactly 2 inventory findings")
}
