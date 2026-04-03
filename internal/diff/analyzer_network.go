package diff

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareInterfaces compares interface configuration between two configs.
func (a *Analyzer) CompareInterfaces(old, newCfg []common.Interface) []Change {
	if len(old) == 0 && len(newCfg) == 0 {
		return nil
	}
	if len(old) == 0 {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionInterfaces,
			Path:        "interfaces",
			Description: "Interfaces configuration section added",
		}}
	}
	if len(newCfg) == 0 {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionInterfaces,
			Path:        "interfaces",
			Description: "Interfaces configuration section removed",
		}}
	}

	var changes []Change

	// Build name maps for O(1) lookup
	oldByName := make(map[string]common.Interface, len(old))
	for _, iface := range old {
		oldByName[iface.Name] = iface
	}
	newByName := make(map[string]common.Interface, len(newCfg))
	for _, iface := range newCfg {
		newByName[iface.Name] = iface
	}

	// Collect and sort names for deterministic output
	oldNames := slices.Sorted(maps.Keys(oldByName))
	newNames := slices.Sorted(maps.Keys(newByName))

	// Find removed interfaces
	for _, name := range oldNames {
		if _, exists := newByName[name]; exists {
			continue
		}
		iface := oldByName[name]
		changes = append(changes, Change{
			Type:        ChangeRemoved,
			Section:     SectionInterfaces,
			Path:        "interfaces." + name,
			Description: fmt.Sprintf("Removed interface: %s (%s)", name, iface.Description),
			OldValue:    formatInterface(iface),
		})
	}

	// Find added interfaces
	for _, name := range newNames {
		if _, exists := oldByName[name]; exists {
			continue
		}
		iface := newByName[name]
		changes = append(changes, Change{
			Type:        ChangeAdded,
			Section:     SectionInterfaces,
			Path:        "interfaces." + name,
			Description: fmt.Sprintf("Added interface: %s (%s)", name, iface.Description),
			NewValue:    formatInterface(iface),
		})
	}

	// Find modified interfaces
	for _, name := range oldNames {
		newIface, exists := newByName[name]
		if !exists {
			continue
		}
		ifaceChanges := a.compareInterface(name, oldByName[name], newIface)
		changes = append(changes, ifaceChanges...)
	}

	return changes
}

// compareInterface compares a single interface.
func (a *Analyzer) compareInterface(name string, old, newCfg common.Interface) []Change {
	var changes []Change

	if old.IPAddress != newCfg.IPAddress {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.ipAddress", name),
			Description: "IP address changed for " + name,
			OldValue:    old.IPAddress,
			NewValue:    newCfg.IPAddress,
		})
	}

	if old.Subnet != newCfg.Subnet {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.subnet", name),
			Description: "Subnet changed for " + name,
			OldValue:    old.Subnet,
			NewValue:    newCfg.Subnet,
		})
	}

	if old.Enabled != newCfg.Enabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.enabled", name),
			Description: "Enable state changed for " + name,
			OldValue:    strconv.FormatBool(old.Enabled),
			NewValue:    strconv.FormatBool(newCfg.Enabled),
		})
	}

	if old.Description != newCfg.Description {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.description", name),
			Description: "Description changed for " + name,
			OldValue:    old.Description,
			NewValue:    newCfg.Description,
		})
	}

	return changes
}

// CompareVLANs compares VLAN configuration between two configs.
func (a *Analyzer) CompareVLANs(old, newCfg []common.VLAN) []Change {
	if len(old) == 0 && len(newCfg) == 0 {
		return nil
	}
	if len(old) == 0 {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionVLANs,
			Path:        "vlans",
			Description: "VLANs configuration section added",
		}}
	}
	if len(newCfg) == 0 {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionVLANs,
			Path:        "vlans",
			Description: "VLANs configuration section removed",
		}}
	}

	var changes []Change

	// Build maps by VLANIf (unique identifier)
	oldByVlanif := make(map[string]common.VLAN, len(old))
	newByVlanif := make(map[string]common.VLAN, len(newCfg))

	for _, v := range old {
		if v.VLANIf != "" {
			oldByVlanif[v.VLANIf] = v
		}
	}
	for _, v := range newCfg {
		if v.VLANIf != "" {
			newByVlanif[v.VLANIf] = v
		}
	}

	// Sort keys for deterministic output
	oldVlanifs := slices.Sorted(maps.Keys(oldByVlanif))
	newVlanifs := slices.Sorted(maps.Keys(newByVlanif))

	// Find removed VLANs
	for _, vlanif := range oldVlanifs {
		if _, exists := newByVlanif[vlanif]; !exists {
			oldVlan := oldByVlanif[vlanif]
			changes = append(changes, Change{
				Type:        ChangeRemoved,
				Section:     SectionVLANs,
				Path:        fmt.Sprintf("vlans.vlan[%s]", vlanif),
				Description: fmt.Sprintf("Removed VLAN: %s (tag %s)", vlanif, oldVlan.Tag),
				OldValue: fmt.Sprintf(
					"tag=%s, if=%s, descr=%s",
					oldVlan.Tag,
					oldVlan.PhysicalIf,
					oldVlan.Description,
				),
			})
		}
	}

	// Find added VLANs
	for _, vlanif := range newVlanifs {
		if _, exists := oldByVlanif[vlanif]; !exists {
			newVlan := newByVlanif[vlanif]
			changes = append(changes, Change{
				Type:        ChangeAdded,
				Section:     SectionVLANs,
				Path:        fmt.Sprintf("vlans.vlan[%s]", vlanif),
				Description: fmt.Sprintf("Added VLAN: %s (tag %s)", vlanif, newVlan.Tag),
				NewValue: fmt.Sprintf(
					"tag=%s, if=%s, descr=%s",
					newVlan.Tag,
					newVlan.PhysicalIf,
					newVlan.Description,
				),
			})
		}
	}

	// Find modified VLANs
	for _, vlanif := range oldVlanifs {
		newVlan, exists := newByVlanif[vlanif]
		if !exists {
			continue
		}
		oldVlan := oldByVlanif[vlanif]
		if oldVlan.Tag != newVlan.Tag {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionVLANs,
				Path:        fmt.Sprintf("vlans.vlan[%s].tag", vlanif),
				Description: "VLAN tag changed for " + vlanif,
				OldValue:    oldVlan.Tag,
				NewValue:    newVlan.Tag,
			})
		}
	}

	return changes
}

// formatInterface returns a compact summary of an interface showing its physical
// device, IP address with subnet, and description.
func formatInterface(iface common.Interface) string {
	var parts []string
	if iface.PhysicalIf != "" {
		parts = append(parts, "if="+iface.PhysicalIf)
	}
	if iface.IPAddress != "" {
		ip := iface.IPAddress
		if iface.Subnet != "" {
			ip += "/" + iface.Subnet
		}
		parts = append(parts, "ip="+ip)
	}
	if iface.Description != "" {
		parts = append(parts, "descr="+iface.Description)
	}
	return strings.Join(parts, ", ")
}
