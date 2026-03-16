package diff

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// addressUnknown is the fallback label used when a rule source or destination address is empty.
const addressUnknown = "unknown"

// Analyzer performs structural comparison of configurations.
type Analyzer struct{}

// NewAnalyzer creates a new structural analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

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

// CompareFirewallRules compares firewall rules between two configs.
func (a *Analyzer) CompareFirewallRules(old, newCfg []common.FirewallRule) []Change {
	var changes []Change

	// Build maps by UUID for matching
	oldByUUID := make(map[string]common.FirewallRule, len(old))
	newByUUID := make(map[string]common.FirewallRule, len(newCfg))

	for _, rule := range old {
		if rule.UUID != "" {
			oldByUUID[rule.UUID] = rule
		}
	}
	for _, rule := range newCfg {
		if rule.UUID != "" {
			newByUUID[rule.UUID] = rule
		}
	}

	// Sort keys for deterministic output
	oldUUIDs := slices.Sorted(maps.Keys(oldByUUID))
	newUUIDs := slices.Sorted(maps.Keys(newByUUID))

	// Find removed rules
	for _, uuid := range oldUUIDs {
		if _, exists := newByUUID[uuid]; !exists {
			oldRule := oldByUUID[uuid]
			changes = append(changes, Change{
				Type:           ChangeRemoved,
				Section:        SectionFirewall,
				Path:           fmt.Sprintf("filter.rule[uuid=%s]", uuid),
				Description:    "Removed rule: " + ruleDescription(oldRule),
				OldValue:       formatRule(oldRule),
				SecurityImpact: "medium",
			})
		}
	}

	// Find added rules and modified rules
	for _, uuid := range newUUIDs {
		newRule := newByUUID[uuid]
		oldRule, exists := oldByUUID[uuid]
		if !exists {
			impact := ""
			if isPermissiveRule(newRule) {
				impact = "high"
			}
			changes = append(changes, Change{
				Type:           ChangeAdded,
				Section:        SectionFirewall,
				Path:           fmt.Sprintf("filter.rule[uuid=%s]", uuid),
				Description:    "Added rule: " + ruleDescription(newRule),
				NewValue:       formatRule(newRule),
				SecurityImpact: impact,
			})
		} else if !rulesEqual(oldRule, newRule) {
			// Flag cases where the modified rule becomes permissive while the old rule was not
			impact := ""
			if isPermissiveRule(newRule) && !isPermissiveRule(oldRule) {
				impact = "high"
			}
			changes = append(changes, Change{
				Type:           ChangeModified,
				Section:        SectionFirewall,
				Path:           fmt.Sprintf("filter.rule[uuid=%s]", uuid),
				Description:    "Modified rule: " + ruleDescription(newRule),
				OldValue:       formatRule(oldRule),
				NewValue:       formatRule(newRule),
				SecurityImpact: impact,
			})
		}
	}

	// Also compare by position for rules without UUIDs
	changes = append(changes, a.compareRulesByPosition(old, newCfg)...)

	return changes
}

// compareRulesByPosition compares rules that don't have UUIDs by position.
func (a *Analyzer) compareRulesByPosition(old, newCfg []common.FirewallRule) []Change {
	var changes []Change

	// Filter to rules without UUIDs
	var oldNoUUID, newNoUUID []common.FirewallRule
	for _, r := range old {
		if r.UUID == "" {
			oldNoUUID = append(oldNoUUID, r)
		}
	}
	for _, r := range newCfg {
		if r.UUID == "" {
			newNoUUID = append(newNoUUID, r)
		}
	}

	// Simple length comparison for rules without UUIDs
	if len(oldNoUUID) != len(newNoUUID) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionFirewall,
			Path:        "filter.rules",
			Description: fmt.Sprintf("Rule count changed (without UUID): %d → %d", len(oldNoUUID), len(newNoUUID)),
			OldValue:    fmt.Sprintf("%d rules", len(oldNoUUID)),
			NewValue:    fmt.Sprintf("%d rules", len(newNoUUID)),
		})
	}

	return changes
}

// CompareNAT compares NAT configuration between two configs.
func (a *Analyzer) CompareNAT(old, newCfg common.NATConfig) []Change {
	oldHas := old.HasData()
	newHas := newCfg.HasData()

	if !oldHas && !newHas {
		return nil
	}
	if !oldHas && newHas {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section added",
		}}
	}
	if oldHas && !newHas {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section removed",
		}}
	}

	var changes []Change

	// Compare outbound NAT mode
	if old.OutboundMode != newCfg.OutboundMode {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.outbound.mode",
			Description:    "Outbound NAT mode changed",
			OldValue:       old.OutboundMode,
			NewValue:       newCfg.OutboundMode,
			SecurityImpact: "medium",
		})
	}

	// Compare outbound rule counts
	if len(old.OutboundRules) != len(newCfg.OutboundRules) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.outbound.rules",
			Description: "Outbound NAT rule count changed",
			OldValue:    fmt.Sprintf("%d rules", len(old.OutboundRules)),
			NewValue:    fmt.Sprintf("%d rules", len(newCfg.OutboundRules)),
		})
	}

	// Compare inbound (port forward) rule counts
	if len(old.InboundRules) != len(newCfg.InboundRules) {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.inbound.rules",
			Description:    "Port forward rule count changed",
			OldValue:       fmt.Sprintf("%d rules", len(old.InboundRules)),
			NewValue:       fmt.Sprintf("%d rules", len(newCfg.InboundRules)),
			SecurityImpact: "medium",
		})
	}

	// Compare NAT boolean settings
	if old.ReflectionDisabled != newCfg.ReflectionDisabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.reflectionDisabled",
			Description: "NAT reflection setting changed",
			OldValue:    strconv.FormatBool(old.ReflectionDisabled),
			NewValue:    strconv.FormatBool(newCfg.ReflectionDisabled),
		})
	}
	if old.PfShareForward != newCfg.PfShareForward {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.pfShareForward",
			Description: "pf share-forward setting changed",
			OldValue:    strconv.FormatBool(old.PfShareForward),
			NewValue:    strconv.FormatBool(newCfg.PfShareForward),
		})
	}
	if old.BiNATEnabled != newCfg.BiNATEnabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.biNatEnabled",
			Description: "BiNAT setting changed",
			OldValue:    strconv.FormatBool(old.BiNATEnabled),
			NewValue:    strconv.FormatBool(newCfg.BiNATEnabled),
		})
	}

	return changes
}

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

// CompareUsers compares user configuration between two configs.
func (a *Analyzer) CompareUsers(old, newCfg []common.User) []Change {
	var changes []Change

	// Build maps by username
	oldByName := make(map[string]common.User, len(old))
	newByName := make(map[string]common.User, len(newCfg))

	for _, u := range old {
		oldByName[u.Name] = u
	}
	for _, u := range newCfg {
		newByName[u.Name] = u
	}

	// Sort keys for deterministic output
	oldUserNames := slices.Sorted(maps.Keys(oldByName))
	newUserNames := slices.Sorted(maps.Keys(newByName))

	// Find removed users
	for _, name := range oldUserNames {
		if _, exists := newByName[name]; !exists {
			oldUser := oldByName[name]
			changes = append(changes, Change{
				Type:           ChangeRemoved,
				Section:        SectionUsers,
				Path:           fmt.Sprintf("system.user[%s]", name),
				Description:    fmt.Sprintf("Removed user: %s (%s)", name, oldUser.Description),
				OldValue:       fmt.Sprintf("scope=%s, group=%s", oldUser.Scope, oldUser.GroupName),
				SecurityImpact: "medium",
			})
		}
	}

	// Find added users
	for _, name := range newUserNames {
		if _, exists := oldByName[name]; !exists {
			newUser := newByName[name]
			changes = append(changes, Change{
				Type:           ChangeAdded,
				Section:        SectionUsers,
				Path:           fmt.Sprintf("system.user[%s]", name),
				Description:    fmt.Sprintf("Added user: %s (%s)", name, newUser.Description),
				NewValue:       fmt.Sprintf("scope=%s, group=%s", newUser.Scope, newUser.GroupName),
				SecurityImpact: "medium",
			})
		}
	}

	// Find modified users
	for _, name := range oldUserNames {
		newUser, exists := newByName[name]
		if !exists {
			continue
		}
		oldUser := oldByName[name]
		if !usersEqual(oldUser, newUser) {
			changes = append(changes, Change{
				Type:           ChangeModified,
				Section:        SectionUsers,
				Path:           fmt.Sprintf("system.user[%s]", name),
				Description:    "Modified user: " + name,
				SecurityImpact: "low",
			})
		}
	}

	return changes
}

// CompareRoutes compares routing configuration between two configs.
func (a *Analyzer) CompareRoutes(old, newCfg common.Routing) []Change {
	oldHas := len(old.StaticRoutes) > 0 || len(old.Gateways) > 0 || len(old.GatewayGroups) > 0
	newHas := len(newCfg.StaticRoutes) > 0 || len(newCfg.Gateways) > 0 || len(newCfg.GatewayGroups) > 0

	if !oldHas && !newHas {
		return nil
	}
	if !oldHas && newHas {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionRouting,
			Path:        "routing",
			Description: "Routing configuration section added",
		}}
	}
	if oldHas && !newHas {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionRouting,
			Path:        "routing",
			Description: "Routing configuration section removed",
		}}
	}

	var changes []Change

	if len(old.StaticRoutes) != len(newCfg.StaticRoutes) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "staticroutes.route",
			Description: "Static route count changed",
			OldValue:    fmt.Sprintf("%d routes", len(old.StaticRoutes)),
			NewValue:    fmt.Sprintf("%d routes", len(newCfg.StaticRoutes)),
		})
	}

	if len(old.Gateways) != len(newCfg.Gateways) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "gateways.gateway_item",
			Description: "Gateway count changed",
			OldValue:    fmt.Sprintf("%d gateways", len(old.Gateways)),
			NewValue:    fmt.Sprintf("%d gateways", len(newCfg.Gateways)),
		})
	}

	if len(old.GatewayGroups) != len(newCfg.GatewayGroups) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "gateway_group",
			Description: "Gateway group count changed",
			OldValue:    fmt.Sprintf("%d groups", len(old.GatewayGroups)),
			NewValue:    fmt.Sprintf("%d groups", len(newCfg.GatewayGroups)),
		})
	}

	return changes
}

// ruleDescription returns the rule's description if set, or a synthesized
// summary of the form "type source -> destination" as a fallback.
func ruleDescription(rule common.FirewallRule) string {
	if rule.Description != "" {
		return rule.Description
	}

	src := rule.Source.Address
	if src == "" {
		src = addressUnknown
	}

	dst := rule.Destination.Address
	if dst == "" {
		dst = addressUnknown
	}

	return fmt.Sprintf("%s %s → %s", rule.Type, src, dst)
}

// formatRule returns a compact, human-readable representation of a firewall rule
// including its type, interfaces, protocol, source, destination, and disabled state.
func formatRule(rule common.FirewallRule) string {
	parts := []string{
		"type=" + rule.Type,
	}
	if len(rule.Interfaces) > 0 {
		parts = append(parts, "if="+strings.Join(rule.Interfaces, ","))
	}
	if rule.Protocol != "" {
		parts = append(parts, "proto="+rule.Protocol)
	}
	parts = append(parts,
		"src="+formatEndpoint(rule.Source),
		"dst="+formatEndpoint(rule.Destination))
	if rule.Disabled {
		parts = append(parts, "disabled")
	}
	return strings.Join(parts, ", ")
}

// formatEndpoint returns a string representation of a rule endpoint in the form
// [!]address[:port], using "unknown" when the address is empty.
func formatEndpoint(ep common.RuleEndpoint) string {
	var prefix string
	if ep.Negated {
		prefix = "!"
	}
	addr := ep.Address
	if addr == "" {
		addr = addressUnknown
	}
	result := prefix + addr
	if ep.Port != "" {
		result += ":" + ep.Port
	}
	return result
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

// rulesEqual reports whether two firewall rules are semantically equal by comparing
// their type, description, protocol, disabled state, source, destination, and interfaces.
func rulesEqual(a, b common.FirewallRule) bool {
	return a.Type == b.Type &&
		a.Description == b.Description &&
		a.Protocol == b.Protocol &&
		a.Disabled == b.Disabled &&
		a.Source == b.Source &&
		a.Destination == b.Destination &&
		slices.Equal(a.Interfaces, b.Interfaces)
}

// usersEqual reports whether two users are semantically equal by comparing
// their name, description, scope, group, and disabled state.
func usersEqual(a, b common.User) bool {
	return a.Name == b.Name &&
		a.Description == b.Description &&
		a.Scope == b.Scope &&
		a.GroupName == b.GroupName &&
		a.Disabled == b.Disabled
}

// isPermissiveRule reports whether a firewall rule is an unrestricted pass rule
// that allows all traffic from any source to any destination.
func isPermissiveRule(rule common.FirewallRule) bool {
	return rule.Type == "pass" &&
		rule.Source.Address == "any" &&
		rule.Destination.Address == "any"
}
