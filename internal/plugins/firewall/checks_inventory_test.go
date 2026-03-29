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

	t.Run("emits finding when DHCP scopes present", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{
			DHCP: []common.DHCPScope{
				{Interface: "lan"},
				{Interface: "guest"},
			},
		}

		findings := fp.RunChecks(device)
		f := inventoryFindingByRef(findings, controlDHCPInventory)
		require.NotNil(t, f, "expected FIREWALL-062 inventory finding")
		assert.Equal(t, "inventory", f.Type)
		assert.Equal(t, "info", f.Severity)
		assert.Contains(t, f.Description, "2 DHCP scope(s)")
		assert.Contains(t, f.Description, "lan")
		assert.Contains(t, f.Description, "guest")
	})

	t.Run("no finding when DHCP scopes empty", func(t *testing.T) {
		t.Parallel()

		device := &common.CommonDevice{}
		findings := fp.RunChecks(device)
		assert.Nil(t, inventoryFindingByRef(findings, controlDHCPInventory),
			"unexpected DHCP inventory finding when no DHCP scopes")
	})

	t.Run("no finding on nil device", func(t *testing.T) {
		t.Parallel()

		findings := fp.RunChecks(nil)
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

		findings := fp.RunChecks(device)
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

		findings := fp.RunChecks(device)
		assert.Nil(t, inventoryFindingByRef(findings, controlInterfaceInventory),
			"unexpected interface inventory finding when no enabled interfaces")
	})
}

func TestFirewallPlugin_InventoryFindings_DoNotAppearInEvaluatedControlIDs(t *testing.T) {
	t.Parallel()

	fp := firewall.NewPlugin()
	device := &common.CommonDevice{
		DHCP: []common.DHCPScope{{Interface: "lan"}},
		Interfaces: []common.Interface{
			{Name: "wan", Enabled: true},
		},
	}

	evaluated := fp.EvaluatedControlIDs(device)

	for _, id := range []string{controlDHCPInventory, controlInterfaceInventory} {
		assert.NotContains(t, evaluated, id,
			"inventory control %s must not appear in EvaluatedControlIDs", id)
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

	findings := fp.RunChecks(device)

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
