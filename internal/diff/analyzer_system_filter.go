package diff

import (
	"strconv"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// compareImplicitFilterSettings reports changes to the two settings that change
// what pf enforces without any rule in the config changing. Turning packet
// filtering off drops every rule, block option and NAT at once, so it rates
// high; turning it back on loads the whole ruleset again and rates medium.
// Clearing noantilockout puts a pass rule to the web GUI and SSH back ahead of
// every user rule and rates medium; setting it removes that rule and rates low.
func compareImplicitFilterSettings(old, newCfg *common.System) []Change {
	var changes []Change

	if old.PacketFilterDisabled != newCfg.PacketFilterDisabled {
		description, impact := "Packet filtering enabled", SecurityImpactMedium
		if newCfg.PacketFilterDisabled {
			description, impact = "Packet filtering disabled", SecurityImpactHigh
		}

		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionSystem,
			Path:           "system.disablefilter",
			Description:    description,
			OldValue:       strconv.FormatBool(old.PacketFilterDisabled),
			NewValue:       strconv.FormatBool(newCfg.PacketFilterDisabled),
			SecurityImpact: string(impact),
		})
	}

	if old.WebGUI.NoAntiLockout != newCfg.WebGUI.NoAntiLockout {
		description, impact := "Anti-lockout rule enabled", SecurityImpactMedium
		if newCfg.WebGUI.NoAntiLockout {
			description, impact = "Anti-lockout rule disabled", SecurityImpactLow
		}

		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionSystem,
			Path:           "system.webgui.noantilockout",
			Description:    description,
			OldValue:       strconv.FormatBool(old.WebGUI.NoAntiLockout),
			NewValue:       strconv.FormatBool(newCfg.WebGUI.NoAntiLockout),
			SecurityImpact: string(impact),
		})
	}

	return changes
}
