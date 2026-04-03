package diff

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareDHCP compares DHCP configuration between two configs.
// Focuses on persistent configuration (static reservations) not ephemeral state (leases).
func (a *Analyzer) CompareDHCP(old, newCfg []common.DHCPScope) []Change {
	if len(old) == 0 && len(newCfg) == 0 {
		return nil
	}
	if len(old) == 0 {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionDHCP,
			Path:        "dhcpd",
			Description: "DHCP configuration section added",
		}}
	}
	if len(newCfg) == 0 {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionDHCP,
			Path:        "dhcpd",
			Description: "DHCP configuration section removed",
		}}
	}

	var changes []Change

	// Build maps keyed by interface name
	oldByIface := make(map[string]common.DHCPScope, len(old))
	for _, scope := range old {
		oldByIface[scope.Interface] = scope
	}
	newByIface := make(map[string]common.DHCPScope, len(newCfg))
	for _, scope := range newCfg {
		newByIface[scope.Interface] = scope
	}

	// Collect and sort names for deterministic output
	oldNames := slices.Sorted(maps.Keys(oldByIface))
	newNames := slices.Sorted(maps.Keys(newByIface))

	// Find removed DHCP configs
	for _, name := range oldNames {
		if _, exists := newByIface[name]; !exists {
			changes = append(changes, Change{
				Type:        ChangeRemoved,
				Section:     SectionDHCP,
				Path:        "dhcpd." + name,
				Description: "Removed DHCP server for " + name,
			})
		}
	}

	// Find added DHCP configs
	for _, name := range newNames {
		if _, exists := oldByIface[name]; !exists {
			changes = append(changes, Change{
				Type:        ChangeAdded,
				Section:     SectionDHCP,
				Path:        "dhcpd." + name,
				Description: "Added DHCP server for " + name,
			})
		}
	}

	// Compare existing DHCP configs - focus on static reservations
	for _, name := range oldNames {
		if _, exists := newByIface[name]; !exists {
			continue
		}

		oldDHCP := oldByIface[name]
		newDHCP := newByIface[name]

		// Compare static reservations specifically
		staticChanges := a.compareStaticMappings(name, oldDHCP.StaticLeases, newDHCP.StaticLeases)
		changes = append(changes, staticChanges...)

		// Compare DHCP range changes
		if oldDHCP.Range.From != newDHCP.Range.From || oldDHCP.Range.To != newDHCP.Range.To {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.range", name),
				Description: "DHCP range changed for " + name,
				OldValue:    fmt.Sprintf("%s - %s", oldDHCP.Range.From, oldDHCP.Range.To),
				NewValue:    fmt.Sprintf("%s - %s", newDHCP.Range.From, newDHCP.Range.To),
			})
		}

		// Compare enable state
		if oldDHCP.Enabled != newDHCP.Enabled {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.enabled", name),
				Description: fmt.Sprintf("DHCP server %s state changed", name),
				OldValue:    strconv.FormatBool(oldDHCP.Enabled),
				NewValue:    strconv.FormatBool(newDHCP.Enabled),
			})
		}
	}

	return changes
}

// compareStaticMappings compares DHCP static reservations between two configs.
func (a *Analyzer) compareStaticMappings(ifaceName string, old, newCfg []common.DHCPStaticLease) []Change {
	var changes []Change

	// Build maps by MAC address (unique identifier for reservations)
	oldByMAC := make(map[string]common.DHCPStaticLease, len(old))
	newByMAC := make(map[string]common.DHCPStaticLease, len(newCfg))

	for _, lease := range old {
		oldByMAC[lease.MAC] = lease
	}
	for _, lease := range newCfg {
		newByMAC[lease.MAC] = lease
	}

	// Sort keys for deterministic output
	oldMACs := slices.Sorted(maps.Keys(oldByMAC))
	newMACs := slices.Sorted(maps.Keys(newByMAC))

	// Find removed static reservations
	for _, mac := range oldMACs {
		if _, exists := newByMAC[mac]; !exists {
			oldLease := oldByMAC[mac]
			changes = append(changes, Change{
				Type:    ChangeRemoved,
				Section: SectionDHCP,
				Path:    fmt.Sprintf("dhcpd.%s.staticmap[%s]", ifaceName, mac),
				Description: fmt.Sprintf(
					"Removed static reservation: %s (%s)",
					oldLease.IPAddress,
					staticLeaseLabel(oldLease),
				),
				OldValue: formatStaticLease(oldLease),
			})
		}
	}

	// Find added static reservations
	for _, mac := range newMACs {
		if _, exists := oldByMAC[mac]; !exists {
			newLease := newByMAC[mac]
			changes = append(changes, Change{
				Type:    ChangeAdded,
				Section: SectionDHCP,
				Path:    fmt.Sprintf("dhcpd.%s.staticmap[%s]", ifaceName, mac),
				Description: fmt.Sprintf(
					"Added static reservation: %s (%s)",
					newLease.IPAddress,
					staticLeaseLabel(newLease),
				),
				NewValue: formatStaticLease(newLease),
			})
		}
	}

	// Find modified static reservations
	for _, mac := range oldMACs {
		newLease, exists := newByMAC[mac]
		if !exists {
			continue
		}
		oldLease := oldByMAC[mac]
		if oldLease.IPAddress != newLease.IPAddress {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.staticmap[%s].ipaddr", ifaceName, mac),
				Description: "Static reservation IP changed for " + staticLeaseLabel(newLease),
				OldValue:    oldLease.IPAddress,
				NewValue:    newLease.IPAddress,
			})
		}
		if oldLease.Hostname != newLease.Hostname {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.staticmap[%s].hostname", ifaceName, mac),
				Description: "Static reservation hostname changed for " + mac,
				OldValue:    oldLease.Hostname,
				NewValue:    newLease.Hostname,
			})
		}
	}

	return changes
}

// staticLeaseLabel returns a human-readable label for a static lease.
func staticLeaseLabel(lease common.DHCPStaticLease) string {
	if lease.Hostname != "" {
		return lease.Hostname
	}
	if lease.Description != "" {
		return lease.Description
	}
	return lease.MAC
}

// formatStaticLease returns a formatted string for a static lease.
func formatStaticLease(lease common.DHCPStaticLease) string {
	parts := []string{"ip=" + lease.IPAddress, "mac=" + lease.MAC}
	if lease.Hostname != "" {
		parts = append(parts, "hostname="+lease.Hostname)
	}
	if lease.Description != "" {
		parts = append(parts, "descr="+lease.Description)
	}
	return strings.Join(parts, ", ")
}
