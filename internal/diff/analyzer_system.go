package diff

import (
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareSystem compares system configuration between two configs.
func (a *Analyzer) CompareSystem(old, newCfg *common.System) []Change {
	var changes []Change

	// Handle nil pointers gracefully
	if old == nil && newCfg == nil {
		return changes
	}
	if old == nil {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionSystem,
			Path:        "system",
			Description: "System configuration section added",
		}}
	}
	if newCfg == nil {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionSystem,
			Path:        "system",
			Description: "System configuration section removed",
		}}
	}

	// Compare key system fields
	if old.Hostname != newCfg.Hostname {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionSystem,
			Path:        "system.hostname",
			Description: "Hostname changed",
			OldValue:    old.Hostname,
			NewValue:    newCfg.Hostname,
		})
	}

	if old.Domain != newCfg.Domain {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionSystem,
			Path:        "system.domain",
			Description: "Domain changed",
			OldValue:    old.Domain,
			NewValue:    newCfg.Domain,
		})
	}

	if old.Timezone != newCfg.Timezone {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionSystem,
			Path:        "system.timezone",
			Description: "Timezone changed",
			OldValue:    old.Timezone,
			NewValue:    newCfg.Timezone,
		})
	}

	oldDNS := strings.Join(old.DNSServers, ",")
	newDNS := strings.Join(newCfg.DNSServers, ",")
	if oldDNS != newDNS {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionSystem,
			Path:        "system.dnsservers",
			Description: "DNS server changed",
			OldValue:    oldDNS,
			NewValue:    newDNS,
		})
	}

	if old.WebGUI.Protocol != newCfg.WebGUI.Protocol {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionSystem,
			Path:           "system.webgui.protocol",
			Description:    "WebGUI protocol changed",
			OldValue:       old.WebGUI.Protocol,
			NewValue:       newCfg.WebGUI.Protocol,
			SecurityImpact: "medium",
		})
	}

	return changes
}
