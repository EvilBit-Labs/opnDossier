package diff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

const addressUnknown = "unknown"

// Analyzer performs structural comparison of configurations.
type Analyzer struct{}

// NewAnalyzer creates a new structural analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// CompareSystem compares system configuration between two configs.
func (a *Analyzer) CompareSystem(old, newCfg *schema.System) []Change {
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

	if old.DNSServer != newCfg.DNSServer {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionSystem,
			Path:        "system.dnsserver",
			Description: "DNS server changed",
			OldValue:    old.DNSServer,
			NewValue:    newCfg.DNSServer,
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
func (a *Analyzer) CompareFirewallRules(old, newCfg []schema.Rule) []Change {
	var changes []Change

	// Build maps by UUID for matching
	oldByUUID := make(map[string]schema.Rule)
	newByUUID := make(map[string]schema.Rule)

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

	// Find removed rules
	for uuid, oldRule := range oldByUUID {
		if _, exists := newByUUID[uuid]; !exists {
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
	for uuid, newRule := range newByUUID {
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
func (a *Analyzer) compareRulesByPosition(old, newCfg []schema.Rule) []Change {
	var changes []Change

	// Filter to rules without UUIDs
	var oldNoUUID, newNoUUID []schema.Rule
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
func (a *Analyzer) CompareNAT(old, newCfg *schema.Nat) []Change {
	var changes []Change

	// Handle nil pointers gracefully
	if old == nil && newCfg == nil {
		return changes
	}
	if old == nil {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section added",
		}}
	}
	if newCfg == nil {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section removed",
		}}
	}

	// Compare outbound NAT mode
	if old.Outbound.Mode != newCfg.Outbound.Mode {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.outbound.mode",
			Description:    "Outbound NAT mode changed",
			OldValue:       old.Outbound.Mode,
			NewValue:       newCfg.Outbound.Mode,
			SecurityImpact: "medium",
		})
	}

	// Compare outbound rule counts
	if len(old.Outbound.Rule) != len(newCfg.Outbound.Rule) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.outbound.rules",
			Description: "Outbound NAT rule count changed",
			OldValue:    fmt.Sprintf("%d rules", len(old.Outbound.Rule)),
			NewValue:    fmt.Sprintf("%d rules", len(newCfg.Outbound.Rule)),
		})
	}

	// Compare inbound (port forward) rule counts
	if len(old.Inbound) != len(newCfg.Inbound) {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.inbound.rules",
			Description:    "Port forward rule count changed",
			OldValue:       fmt.Sprintf("%d rules", len(old.Inbound)),
			NewValue:       fmt.Sprintf("%d rules", len(newCfg.Inbound)),
			SecurityImpact: "medium",
		})
	}

	return changes
}

// CompareInterfaces compares interface configuration between two configs.
func (a *Analyzer) CompareInterfaces(old, newCfg *schema.Interfaces) []Change {
	var changes []Change

	// Handle nil pointers gracefully
	if old == nil && newCfg == nil {
		return changes
	}
	if old == nil {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionInterfaces,
			Path:        "interfaces",
			Description: "Interfaces configuration section added",
		}}
	}
	if newCfg == nil {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionInterfaces,
			Path:        "interfaces",
			Description: "Interfaces configuration section removed",
		}}
	}

	oldNames := old.Names()
	newNames := newCfg.Names()
	slices.Sort(oldNames)
	slices.Sort(newNames)

	// Build sets for O(1) lookups instead of O(n) slices.Contains
	newNameSet := make(map[string]struct{}, len(newNames))
	for _, name := range newNames {
		newNameSet[name] = struct{}{}
	}
	oldNameSet := make(map[string]struct{}, len(oldNames))
	for _, name := range oldNames {
		oldNameSet[name] = struct{}{}
	}

	// Find removed interfaces
	for _, name := range oldNames {
		if _, exists := newNameSet[name]; exists {
			continue
		}
		// Get should not fail here because name came from Names()
		iface, ok := old.Get(name)
		if !ok {
			// This indicates a bug in the Interfaces implementation - skip this interface
			continue
		}
		changes = append(changes, Change{
			Type:        ChangeRemoved,
			Section:     SectionInterfaces,
			Path:        "interfaces." + name,
			Description: fmt.Sprintf("Removed interface: %s (%s)", name, iface.Descr),
			OldValue:    formatInterface(iface),
		})
	}

	// Find added interfaces
	for _, name := range newNames {
		if _, exists := oldNameSet[name]; exists {
			continue
		}
		iface, ok := newCfg.Get(name)
		if !ok {
			continue
		}
		changes = append(changes, Change{
			Type:        ChangeAdded,
			Section:     SectionInterfaces,
			Path:        "interfaces." + name,
			Description: fmt.Sprintf("Added interface: %s (%s)", name, iface.Descr),
			NewValue:    formatInterface(iface),
		})
	}

	// Find modified interfaces
	for _, name := range oldNames {
		if _, exists := newNameSet[name]; !exists {
			continue
		}
		oldIface, ok1 := old.Get(name)
		newIface, ok2 := newCfg.Get(name)
		if !ok1 || !ok2 {
			continue
		}
		ifaceChanges := a.compareInterface(name, oldIface, newIface)
		changes = append(changes, ifaceChanges...)
	}

	return changes
}

// compareInterface compares a single interface.
func (a *Analyzer) compareInterface(name string, old, newCfg schema.Interface) []Change {
	var changes []Change

	if old.IPAddr != newCfg.IPAddr {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.ipaddr", name),
			Description: "IP address changed for " + name,
			OldValue:    old.IPAddr,
			NewValue:    newCfg.IPAddr,
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

	if old.Enable != newCfg.Enable {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.enable", name),
			Description: "Enable state changed for " + name,
			OldValue:    old.Enable,
			NewValue:    newCfg.Enable,
		})
	}

	if old.Descr != newCfg.Descr {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionInterfaces,
			Path:        fmt.Sprintf("interfaces.%s.descr", name),
			Description: "Description changed for " + name,
			OldValue:    old.Descr,
			NewValue:    newCfg.Descr,
		})
	}

	return changes
}

// CompareVLANs compares VLAN configuration between two configs.
func (a *Analyzer) CompareVLANs(old, newCfg *schema.VLANs) []Change {
	var changes []Change

	// Handle nil pointers gracefully
	if old == nil && newCfg == nil {
		return changes
	}
	if old == nil {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionVLANs,
			Path:        "vlans",
			Description: "VLANs configuration section added",
		}}
	}
	if newCfg == nil {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionVLANs,
			Path:        "vlans",
			Description: "VLANs configuration section removed",
		}}
	}

	// Build maps by vlanif (unique identifier)
	oldByVlanif := make(map[string]schema.VLAN)
	newByVlanif := make(map[string]schema.VLAN)

	for _, v := range old.VLAN {
		if v.Vlanif != "" {
			oldByVlanif[v.Vlanif] = v
		}
	}
	for _, v := range newCfg.VLAN {
		if v.Vlanif != "" {
			newByVlanif[v.Vlanif] = v
		}
	}

	// Find removed VLANs
	for vlanif, oldVlan := range oldByVlanif {
		if _, exists := newByVlanif[vlanif]; !exists {
			changes = append(changes, Change{
				Type:        ChangeRemoved,
				Section:     SectionVLANs,
				Path:        fmt.Sprintf("vlans.vlan[%s]", vlanif),
				Description: fmt.Sprintf("Removed VLAN: %s (tag %s)", vlanif, oldVlan.Tag),
				OldValue:    fmt.Sprintf("tag=%s, if=%s, descr=%s", oldVlan.Tag, oldVlan.If, oldVlan.Descr),
			})
		}
	}

	// Find added VLANs
	for vlanif, newVlan := range newByVlanif {
		if _, exists := oldByVlanif[vlanif]; !exists {
			changes = append(changes, Change{
				Type:        ChangeAdded,
				Section:     SectionVLANs,
				Path:        fmt.Sprintf("vlans.vlan[%s]", vlanif),
				Description: fmt.Sprintf("Added VLAN: %s (tag %s)", vlanif, newVlan.Tag),
				NewValue:    fmt.Sprintf("tag=%s, if=%s, descr=%s", newVlan.Tag, newVlan.If, newVlan.Descr),
			})
		}
	}

	// Find modified VLANs
	for vlanif, oldVlan := range oldByVlanif {
		if newVlan, exists := newByVlanif[vlanif]; exists {
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
	}

	return changes
}

// CompareDHCP compares DHCP configuration between two configs.
// Focuses on persistent configuration (static reservations) not ephemeral state (leases).
func (a *Analyzer) CompareDHCP(old, newCfg *schema.Dhcpd) []Change {
	var changes []Change

	// Handle nil pointers gracefully
	if old == nil && newCfg == nil {
		return changes
	}
	if old == nil {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionDHCP,
			Path:        "dhcpd",
			Description: "DHCP configuration section added",
		}}
	}
	if newCfg == nil {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionDHCP,
			Path:        "dhcpd",
			Description: "DHCP configuration section removed",
		}}
	}

	// Compare by interface names
	oldNames := make([]string, 0, len(old.Items))
	newNames := make([]string, 0, len(newCfg.Items))
	for name := range old.Items {
		oldNames = append(oldNames, name)
	}
	for name := range newCfg.Items {
		newNames = append(newNames, name)
	}
	slices.Sort(oldNames)
	slices.Sort(newNames)

	// Build sets for O(1) lookups instead of O(n) slices.Contains
	newNameSet := make(map[string]struct{}, len(newNames))
	for _, name := range newNames {
		newNameSet[name] = struct{}{}
	}
	oldNameSet := make(map[string]struct{}, len(oldNames))
	for _, name := range oldNames {
		oldNameSet[name] = struct{}{}
	}

	// Find removed DHCP configs
	for _, name := range oldNames {
		if _, exists := newNameSet[name]; !exists {
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
		if _, exists := oldNameSet[name]; !exists {
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
		if _, exists := newNameSet[name]; !exists {
			continue
		}

		oldDHCP := old.Items[name]
		newDHCP := newCfg.Items[name]

		// Compare static reservations specifically
		staticChanges := a.compareStaticMappings(name, oldDHCP.Staticmap, newDHCP.Staticmap)
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
		if oldDHCP.Enable != newDHCP.Enable {
			changes = append(changes, Change{
				Type:        ChangeModified,
				Section:     SectionDHCP,
				Path:        fmt.Sprintf("dhcpd.%s.enable", name),
				Description: fmt.Sprintf("DHCP server %s state changed", name),
				OldValue:    oldDHCP.Enable,
				NewValue:    newDHCP.Enable,
			})
		}
	}

	return changes
}

// compareStaticMappings compares DHCP static reservations between two configs.
func (a *Analyzer) compareStaticMappings(ifaceName string, old, newCfg []schema.DHCPStaticLease) []Change {
	var changes []Change

	// Build maps by MAC address (unique identifier for reservations)
	oldByMAC := make(map[string]schema.DHCPStaticLease)
	newByMAC := make(map[string]schema.DHCPStaticLease)

	for _, lease := range old {
		oldByMAC[lease.Mac] = lease
	}
	for _, lease := range newCfg {
		newByMAC[lease.Mac] = lease
	}

	// Find removed static reservations
	for mac, oldLease := range oldByMAC {
		if _, exists := newByMAC[mac]; !exists {
			changes = append(changes, Change{
				Type:    ChangeRemoved,
				Section: SectionDHCP,
				Path:    fmt.Sprintf("dhcpd.%s.staticmap[%s]", ifaceName, mac),
				Description: fmt.Sprintf(
					"Removed static reservation: %s (%s)",
					oldLease.IPAddr,
					staticLeaseLabel(oldLease),
				),
				OldValue: formatStaticLease(oldLease),
			})
		}
	}

	// Find added static reservations
	for mac, newLease := range newByMAC {
		if _, exists := oldByMAC[mac]; !exists {
			changes = append(changes, Change{
				Type:    ChangeAdded,
				Section: SectionDHCP,
				Path:    fmt.Sprintf("dhcpd.%s.staticmap[%s]", ifaceName, mac),
				Description: fmt.Sprintf(
					"Added static reservation: %s (%s)",
					newLease.IPAddr,
					staticLeaseLabel(newLease),
				),
				NewValue: formatStaticLease(newLease),
			})
		}
	}

	// Find modified static reservations
	for mac, oldLease := range oldByMAC {
		if newLease, exists := newByMAC[mac]; exists {
			if oldLease.IPAddr != newLease.IPAddr {
				changes = append(changes, Change{
					Type:        ChangeModified,
					Section:     SectionDHCP,
					Path:        fmt.Sprintf("dhcpd.%s.staticmap[%s].ipaddr", ifaceName, mac),
					Description: "Static reservation IP changed for " + staticLeaseLabel(newLease),
					OldValue:    oldLease.IPAddr,
					NewValue:    newLease.IPAddr,
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
	}

	return changes
}

// staticLeaseLabel returns a human-readable label for a static lease.
func staticLeaseLabel(lease schema.DHCPStaticLease) string {
	if lease.Hostname != "" {
		return lease.Hostname
	}
	if lease.Descr != "" {
		return lease.Descr
	}
	return lease.Mac
}

// formatStaticLease returns a formatted string for a static lease.
func formatStaticLease(lease schema.DHCPStaticLease) string {
	parts := []string{"ip=" + lease.IPAddr, "mac=" + lease.Mac}
	if lease.Hostname != "" {
		parts = append(parts, "hostname="+lease.Hostname)
	}
	if lease.Descr != "" {
		parts = append(parts, "descr="+lease.Descr)
	}
	return strings.Join(parts, ", ")
}

// CompareUsers compares user configuration between two configs.
func (a *Analyzer) CompareUsers(old, newCfg []schema.User) []Change {
	var changes []Change

	// Build maps by username
	oldByName := make(map[string]schema.User)
	newByName := make(map[string]schema.User)

	for _, u := range old {
		oldByName[u.Name] = u
	}
	for _, u := range newCfg {
		newByName[u.Name] = u
	}

	// Find removed users
	for name, oldUser := range oldByName {
		if _, exists := newByName[name]; !exists {
			changes = append(changes, Change{
				Type:           ChangeRemoved,
				Section:        SectionUsers,
				Path:           fmt.Sprintf("system.user[%s]", name),
				Description:    fmt.Sprintf("Removed user: %s (%s)", name, oldUser.Descr),
				OldValue:       fmt.Sprintf("scope=%s, group=%s", oldUser.Scope, oldUser.Groupname),
				SecurityImpact: "medium",
			})
		}
	}

	// Find added users
	for name, newUser := range newByName {
		if _, exists := oldByName[name]; !exists {
			changes = append(changes, Change{
				Type:           ChangeAdded,
				Section:        SectionUsers,
				Path:           fmt.Sprintf("system.user[%s]", name),
				Description:    fmt.Sprintf("Added user: %s (%s)", name, newUser.Descr),
				NewValue:       fmt.Sprintf("scope=%s, group=%s", newUser.Scope, newUser.Groupname),
				SecurityImpact: "medium",
			})
		}
	}

	// Find modified users
	for name, oldUser := range oldByName {
		if newUser, exists := newByName[name]; exists {
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
	}

	return changes
}

// CompareRoutes compares static route configuration between two configs.
func (a *Analyzer) CompareRoutes(old, newCfg *schema.StaticRoutes) []Change {
	var changes []Change

	// Handle nil pointers gracefully
	if old == nil && newCfg == nil {
		return changes
	}
	if old == nil {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionRouting,
			Path:        "staticroutes",
			Description: "Static routes configuration section added",
		}}
	}
	if newCfg == nil {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionRouting,
			Path:        "staticroutes",
			Description: "Static routes configuration section removed",
		}}
	}

	if len(old.Route) != len(newCfg.Route) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "staticroutes.route",
			Description: "Static route count changed",
			OldValue:    fmt.Sprintf("%d routes", len(old.Route)),
			NewValue:    fmt.Sprintf("%d routes", len(newCfg.Route)),
		})
	}

	return changes
}

// Helper functions

func ruleDescription(rule schema.Rule) string {
	if rule.Descr != "" {
		return rule.Descr
	}

	src := rule.Source.EffectiveAddress()
	if src == "" {
		src = addressUnknown
	}

	dst := rule.Destination.EffectiveAddress()
	if dst == "" {
		dst = addressUnknown
	}

	return fmt.Sprintf("%s %s → %s", rule.Type, src, dst)
}

func formatRule(rule schema.Rule) string {
	parts := []string{
		"type=" + rule.Type,
	}
	if len(rule.Interface) > 0 {
		parts = append(parts, "if="+rule.Interface.String())
	}
	if rule.Protocol != "" {
		parts = append(parts, "proto="+rule.Protocol)
	}
	parts = append(parts,
		"src="+formatSource(rule.Source),
		"dst="+formatDestination(rule.Destination))
	if rule.Disabled.Bool() {
		parts = append(parts, "disabled")
	}
	return strings.Join(parts, ", ")
}

func formatSource(src schema.Source) string {
	var prefix string
	if src.Not {
		prefix = "!"
	}
	addr := src.EffectiveAddress()
	if addr == "" {
		addr = addressUnknown
	}
	result := prefix + addr
	if src.Port != "" {
		result += ":" + src.Port
	}
	return result
}

func formatDestination(dst schema.Destination) string {
	var prefix string
	if dst.Not {
		prefix = "!"
	}
	addr := dst.EffectiveAddress()
	if addr == "" {
		addr = addressUnknown
	}
	result := prefix + addr
	if dst.Port != "" {
		result += ":" + dst.Port
	}
	return result
}

func formatInterface(iface schema.Interface) string {
	parts := []string{}
	if iface.If != "" {
		parts = append(parts, "if="+iface.If)
	}
	if iface.IPAddr != "" {
		ip := iface.IPAddr
		if iface.Subnet != "" {
			ip += "/" + iface.Subnet
		}
		parts = append(parts, "ip="+ip)
	}
	if iface.Descr != "" {
		parts = append(parts, "descr="+iface.Descr)
	}
	return strings.Join(parts, ", ")
}

func rulesEqual(a, b schema.Rule) bool {
	return a.Type == b.Type &&
		a.Descr == b.Descr &&
		a.Protocol == b.Protocol &&
		a.Disabled == b.Disabled &&
		a.Source.Equal(b.Source) &&
		a.Destination.Equal(b.Destination) &&
		slices.Equal([]string(a.Interface), []string(b.Interface))
}

func usersEqual(a, b schema.User) bool {
	return a.Name == b.Name &&
		a.Descr == b.Descr &&
		a.Scope == b.Scope &&
		a.Groupname == b.Groupname &&
		a.Disabled == b.Disabled
}

func isPermissiveRule(rule schema.Rule) bool {
	return rule.Type == "pass" &&
		rule.Source.EffectiveAddress() == "any" &&
		rule.Destination.EffectiveAddress() == "any"
}
