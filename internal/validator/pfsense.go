package validator

import (
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// ValidatePfSenseDocument validates an entire pfSense configuration document and
// returns all detected validation errors. It checks system settings, network
// interfaces, DHCP server, firewall rules, NAT rules, and users and groups.
func ValidatePfSenseDocument(doc *pfsense.Document) []ValidationError {
	if doc == nil {
		return []ValidationError{{
			Field:   "document",
			Message: "pfSense document is nil",
		}}
	}

	var errors []ValidationError

	errors = append(errors, validatePfSenseSystem(&doc.System)...)
	errors = append(errors, validatePfSenseInterfaces(&doc.Interfaces)...)
	errors = append(errors, validatePfSenseDhcpd(&doc.Dhcpd, &doc.Interfaces)...)
	errors = append(errors, validatePfSenseFilter(&doc.Filter, &doc.Interfaces)...)
	errors = append(errors, validatePfSenseNat(&doc.Nat)...)
	errors = append(errors, validatePfSenseUsersAndGroups(&doc.System)...)

	return errors
}

// collectPfSenseInterfaceNames returns every key from the pfSense interfaces map as a set.
func collectPfSenseInterfaceNames(ifaces *pfsense.Interfaces) map[string]struct{} {
	interfaceNames := make(map[string]struct{})

	if ifaces != nil && ifaces.Items != nil {
		for name := range ifaces.Items {
			interfaceNames[name] = struct{}{}
		}
	}

	return interfaceNames
}

// validatePfSenseInterfaces validates all configured pfSense network interfaces.
func validatePfSenseInterfaces(interfaces *pfsense.Interfaces) []ValidationError {
	var errors []ValidationError

	if interfaces == nil || interfaces.Items == nil {
		return errors
	}

	validInterfaceNames := collectPfSenseInterfaceNames(interfaces)

	for name, iface := range interfaces.Items {
		// Adapt to opnsense.Interface for shared field-level validation.
		opnIface := &opnsense.Interface{
			IPAddr:          iface.IPAddr,
			IPAddrv6:        iface.IPAddrv6,
			Subnet:          iface.Subnet,
			Subnetv6:        iface.Subnetv6,
			MTU:             iface.MTU,
			Track6Interface: iface.Track6Interface,
			Track6PrefixID:  iface.Track6PrefixID,
		}

		errors = append(errors, validateInterface(opnIface, name, validInterfaceNames)...)
	}

	return errors
}

// validatePfSenseDhcpd validates pfSense DHCP configuration, cross-referencing
// against the pfSense interfaces map.
func validatePfSenseDhcpd(dhcpd *pfsense.Dhcpd, interfaces *pfsense.Interfaces) []ValidationError {
	var errors []ValidationError

	if dhcpd == nil || dhcpd.Items == nil {
		return errors
	}

	ifaceSet := collectPfSenseInterfaceNames(interfaces)

	for name, cfg := range dhcpd.Items {
		// Adapt to opnsense.DhcpdInterface for shared field-level validation.
		opnCfg := opnsense.DhcpdInterface{
			Range:   cfg.Range,
			Gateway: cfg.Gateway,
		}

		errors = append(errors, validateDhcpdInterface(name, opnCfg, ifaceSet)...)
	}

	return errors
}

// validatePfSenseSystem checks the pfSense system-level configuration fields for
// required values and valid formats.
//
//nolint:dupl // structurally similar to validateSystem but operates on pfsense.System
func validatePfSenseSystem(sys *pfsense.System) []ValidationError {
	var errors []ValidationError

	if sys.Hostname == "" {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: "hostname is required",
		})
	} else if !isValidHostname(sys.Hostname) {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: fmt.Sprintf("hostname '%s' contains invalid characters", sys.Hostname),
		})
	}

	if sys.Domain == "" {
		errors = append(errors, ValidationError{
			Field:   "system.domain",
			Message: "domain is required",
		})
	}

	if sys.Timezone != "" && !isValidTimezone(sys.Timezone) {
		errors = append(errors, ValidationError{
			Field:   "system.timezone",
			Message: "invalid timezone format: " + sys.Timezone,
		})
	}

	if sys.Optimization != "" {
		if _, ok := constants.ValidOptimizationModes[sys.Optimization]; !ok {
			errors = append(errors, ValidationError{
				Field: "system.optimization",
				Message: fmt.Sprintf(
					"optimization '%s' must be one of: %v",
					sys.Optimization,
					slices.Sorted(maps.Keys(constants.ValidOptimizationModes)),
				),
			})
		}
	}

	validProtocols := []string{"http", "https"}
	if sys.WebGUI.Protocol != "" && !contains(validProtocols, sys.WebGUI.Protocol) {
		errors = append(errors, ValidationError{
			Field:   "system.webgui.protocol",
			Message: fmt.Sprintf("protocol '%s' must be one of: %v", sys.WebGUI.Protocol, validProtocols),
		})
	}

	validPowerdList := slices.Sorted(maps.Keys(constants.ValidPowerdModes))

	if sys.PowerdACMode != "" {
		if _, ok := constants.ValidPowerdModes[sys.PowerdACMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_ac_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", sys.PowerdACMode, validPowerdList),
			})
		}
	}

	if sys.PowerdBatteryMode != "" {
		if _, ok := constants.ValidPowerdModes[sys.PowerdBatteryMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_battery_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", sys.PowerdBatteryMode, validPowerdList),
			})
		}
	}

	if sys.PowerdNormalMode != "" {
		if _, ok := constants.ValidPowerdModes[sys.PowerdNormalMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_normal_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", sys.PowerdNormalMode, validPowerdList),
			})
		}
	}

	validBogonsIntervals := []string{"monthly", "weekly", "daily", "never"}
	if sys.Bogons.Interval != "" && !contains(validBogonsIntervals, sys.Bogons.Interval) {
		errors = append(errors, ValidationError{
			Field: "system.bogons.interval",
			Message: fmt.Sprintf(
				"bogons interval '%s' must be one of: %v",
				sys.Bogons.Interval,
				validBogonsIntervals,
			),
		})
	}

	return errors
}

// validatePfSenseFilter checks each pfSense firewall filter rule for valid types,
// protocols, interface references, and network specifications.
func validatePfSenseFilter(filter *pfsense.Filter, interfaces *pfsense.Interfaces) []ValidationError {
	var errors []ValidationError
	validInterfaceNames := collectPfSenseInterfaceNames(interfaces)
	for i, rule := range filter.Rule {
		errors = append(errors, validatePfSenseFilterRule(i, rule, validInterfaceNames)...)
	}
	return errors
}

// validatePfSenseFilterRule checks a single pfSense filter rule by delegating
// to concern-specific helpers. Splitting keeps validatePfSenseFilter well
// under gocognit's threshold.
func validatePfSenseFilterRule(
	i int,
	rule pfsense.FilterRule,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	var errors []ValidationError
	prefix := fmt.Sprintf("filter.rule[%d]", i)
	errors = append(errors, validatePfSenseRuleTypeAndProtocol(prefix, rule)...)
	errors = append(errors, validatePfSenseRuleInterface(prefix, rule, validInterfaceNames)...)
	errors = append(errors, validatePfSenseRuleEndpoints(prefix, rule, validInterfaceNames)...)
	errors = append(errors, validatePfSenseRuleAnyExclusivity(prefix, rule)...)
	errors = append(errors, validatePfSenseRuleDirection(prefix, rule)...)
	errors = append(errors, validatePfSenseRuleStateAndRate(prefix, rule)...)
	return errors
}

// validPfSenseRuleTypes / IPProtocols / Directions / StateTypes are hoisted to
// package scope so each helper does not reallocate them per rule.
var (
	validPfSenseRuleTypes      = []string{"pass", "block", "reject"}
	validPfSenseIPProtocols    = []string{"inet", "inet6", "inet46"}
	validPfSenseDirections     = []string{"in", "out", "any"}
	validPfSenseRuleStateTypes = []string{"keep state", "sloppy state", "synproxy state", "none"}
)

func validatePfSenseRuleTypeAndProtocol(prefix string, rule pfsense.FilterRule) []ValidationError {
	var errors []ValidationError
	if rule.Type != "" && !contains(validPfSenseRuleTypes, rule.Type) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".type",
			Message: fmt.Sprintf("rule type '%s' must be one of: %v", rule.Type, validPfSenseRuleTypes),
		})
	}
	if rule.IPProtocol != "" && !contains(validPfSenseIPProtocols, rule.IPProtocol) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".ipprotocol",
			Message: fmt.Sprintf("IP protocol '%s' must be one of: %v", rule.IPProtocol, validPfSenseIPProtocols),
		})
	}
	return errors
}

func validatePfSenseRuleInterface(
	prefix string,
	rule pfsense.FilterRule,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	if rule.Interface.IsEmpty() {
		return nil
	}
	var errors []ValidationError
	for _, iface := range rule.Interface {
		if _, exists := validInterfaceNames[iface]; exists {
			continue
		}
		errors = append(errors, ValidationError{
			Field: prefix + ".interface",
			Message: fmt.Sprintf(
				"interface '%s' must be one of the configured interfaces: %v",
				iface,
				sortedInterfaceNames(validInterfaceNames),
			),
		})
	}
	return errors
}

// validatePfSenseRuleEndpoints mirrors validateOPNRuleEndpoints in
// validate_security.go by design — the two devices share the same endpoint
// schema. The dupl linter flags this pair bidirectionally, so both sides
// carry the suppression per GOTCHAS §9.1.
//
//nolint:dupl // structurally identical to validateOPNRuleEndpoints by design
func validatePfSenseRuleEndpoints(
	prefix string,
	rule pfsense.FilterRule,
	validInterfaceNames map[string]struct{},
) []ValidationError {
	var errors []ValidationError
	errors = append(errors, validateNetworkField(
		rule.Source.Network, prefix+".source.network", "source", validInterfaceNames,
	)...)
	errors = append(errors, validateAddressField(
		rule.Source.Address, prefix+".source.address",
	)...)
	errors = append(errors, validateNetworkField(
		rule.Destination.Network, prefix+".destination.network", "destination", validInterfaceNames,
	)...)
	errors = append(errors, validateAddressField(
		rule.Destination.Address, prefix+".destination.address",
	)...)
	if rule.Source.Port != "" && !isValidPortOrRange(rule.Source.Port) {
		errors = append(errors, ValidationError{
			Field: prefix + ".source.port",
			Message: fmt.Sprintf(
				"source port '%s' is not a valid port (1-65535) or range (low-high)",
				rule.Source.Port,
			),
		})
	}
	if rule.Destination.Port != "" && !isValidPortOrRange(rule.Destination.Port) {
		errors = append(errors, ValidationError{
			Field: prefix + ".destination.port",
			Message: fmt.Sprintf(
				"destination port '%s' is not a valid port (1-65535) or range (low-high)",
				rule.Destination.Port,
			),
		})
	}
	return errors
}

// validatePfSenseRuleAnyExclusivity enforces that each endpoint specifies
// exactly one of {any, network, address} — pfSense treats combinations as
// ambiguous.
func validatePfSenseRuleAnyExclusivity(prefix string, rule pfsense.FilterRule) []ValidationError {
	var errors []ValidationError
	if countPfSenseEndpointFields(rule.Source.IsAny(), rule.Source.Network, rule.Source.Address) > 1 {
		errors = append(errors, ValidationError{
			Field:   prefix + ".source",
			Message: "source can only specify one of: any, network, or address",
		})
	}
	if countPfSenseEndpointFields(rule.Destination.IsAny(), rule.Destination.Network, rule.Destination.Address) > 1 {
		errors = append(errors, ValidationError{
			Field:   prefix + ".destination",
			Message: "destination can only specify one of: any, network, or address",
		})
	}
	return errors
}

func countPfSenseEndpointFields(isAny bool, network, address string) int {
	count := 0
	if isAny {
		count++
	}
	if network != "" {
		count++
	}
	if address != "" {
		count++
	}
	return count
}

func validatePfSenseRuleDirection(prefix string, rule pfsense.FilterRule) []ValidationError {
	var errors []ValidationError
	if rule.Floating == floatingYes && rule.Direction == "" {
		errors = append(errors, ValidationError{
			Field:   prefix + ".direction",
			Message: "direction is required for floating rules",
		})
	}
	if rule.Direction != "" && !contains(validPfSenseDirections, rule.Direction) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".direction",
			Message: fmt.Sprintf("direction '%s' must be one of: %v", rule.Direction, validPfSenseDirections),
		})
	}
	return errors
}

func validatePfSenseRuleStateAndRate(prefix string, rule pfsense.FilterRule) []ValidationError {
	var errors []ValidationError
	if rule.StateType != "" && !contains(validPfSenseRuleStateTypes, rule.StateType) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".statetype",
			Message: fmt.Sprintf("state type '%s' must be one of: %v", rule.StateType, validPfSenseRuleStateTypes),
		})
	}
	if rule.MaxSrcConnRate != "" && !isValidConnRateFormat(rule.MaxSrcConnRate) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".max-src-conn-rate",
			Message: "max-src-conn-rate must be in format 'connections/seconds' (e.g., '15/5')",
		})
	}
	return errors
}

// validatePfSenseNat checks pfSense NAT configuration including outbound mode
// and inbound rule fields.
func validatePfSenseNat(nat *pfsense.Nat) []ValidationError {
	var errors []ValidationError

	validModes := []string{"automatic", "hybrid", "advanced", "disabled"}
	if nat.Outbound.Mode != "" && !contains(validModes, nat.Outbound.Mode) {
		errors = append(errors, ValidationError{
			Field:   "nat.outbound.mode",
			Message: fmt.Sprintf("NAT outbound mode '%s' must be one of: %v", nat.Outbound.Mode, validModes),
		})
	}

	validReflectionModes := []string{"enable", "disable", "purenat"}
	for i, rule := range nat.Inbound {
		if rule.NATReflection != "" && !contains(validReflectionModes, rule.NATReflection) {
			errors = append(errors, ValidationError{
				Field: fmt.Sprintf("nat.inbound[%d].natreflection", i),
				Message: fmt.Sprintf(
					"NAT reflection mode '%s' must be one of: %v",
					rule.NATReflection,
					validReflectionModes,
				),
			})
		}
	}

	return errors
}

// validatePfSenseUsersAndGroups checks pfSense users and groups for required fields,
// uniqueness, valid IDs, valid scopes, and correct group references.
func validatePfSenseUsersAndGroups(sys *pfsense.System) []ValidationError {
	var errors []ValidationError

	groupNames := make(map[string]bool)
	groupGIDs := make(map[int]struct{})

	errors = append(errors, validatePfSenseGroups(sys.Group, groupNames, groupGIDs)...)
	errors = append(errors, validatePfSenseUsers(sys.User, groupNames)...)

	return errors
}

// validatePfSenseUsers validates pfSense users for required fields, uniqueness, and
// valid group membership.
func validatePfSenseUsers(users []pfsense.User, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError
	userNames := make(map[string]bool)
	userUIDs := make(map[int]struct{})

	for i, user := range users {
		errors = append(errors, validatePfSenseUserName(user, i, userNames)...)
		errors = append(errors, validatePfSenseUserUID(user, i, userUIDs)...)
		errors = append(errors, validatePfSenseUserGroupMembership(user, i, groupNames)...)
		errors = append(errors, validatePfSenseUserScope(user, i)...)
	}

	return errors
}

// validatePfSenseUserName validates pfSense user name requirements and uniqueness.
func validatePfSenseUserName(user pfsense.User, index int, userNames map[string]bool) []ValidationError {
	var errors []ValidationError

	switch {
	case user.Name == "":
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].name", index),
			Message: "user name is required",
		})
	case userNames[user.Name]:
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].name", index),
			Message: fmt.Sprintf("user name '%s' must be unique", user.Name),
		})
	default:
		userNames[user.Name] = true
	}

	return errors
}

// validatePfSenseUserUID validates pfSense user UID requirements and uniqueness.
func validatePfSenseUserUID(user pfsense.User, index int, userUIDs map[int]struct{}) []ValidationError {
	var errors []ValidationError

	if user.UID == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: "user UID is required",
		})
		return errors
	}

	uid, err := strconv.Atoi(user.UID)
	if err != nil || uid < 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("UID '%s' must be a non-negative integer", user.UID),
		})
		return errors
	}

	if _, exists := userUIDs[uid]; exists {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("user UID '%s' must be unique", user.UID),
		})
		return errors
	}

	userUIDs[uid] = struct{}{}
	return errors
}

// validatePfSenseUserGroupMembership validates pfSense user group membership.
func validatePfSenseUserGroupMembership(user pfsense.User, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	if user.Groupname != "" && !groupNames[user.Groupname] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].groupname", index),
			Message: fmt.Sprintf("referenced group '%s' does not exist", user.Groupname),
		})
	}

	return errors
}

// validatePfSenseGroups validates pfSense groups for required fields, uniqueness,
// and valid scopes. This is a pfSense-specific fork of validateGroups that works
// with pfsense.Group (which uses []string for Priv instead of string).
func validatePfSenseGroups(
	groups []pfsense.Group,
	groupNames map[string]bool,
	groupGIDs map[int]struct{},
) []ValidationError {
	var errors []ValidationError

	for i, group := range groups {
		switch {
		case group.Name == "":
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].name", i),
				Message: "group name is required",
			})
		case groupNames[group.Name]:
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].name", i),
				Message: fmt.Sprintf("group name '%s' must be unique", group.Name),
			})
		default:
			groupNames[group.Name] = true
		}

		if group.Gid == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].gid", i),
				Message: "group GID is required",
			})
		} else {
			gid, err := strconv.Atoi(group.Gid)
			if err != nil || gid < 0 {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("system.group[%d].gid", i),
					Message: fmt.Sprintf("GID '%s' must be a non-negative integer", group.Gid),
				})
			} else if _, exists := groupGIDs[gid]; exists {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("system.group[%d].gid", i),
					Message: fmt.Sprintf("group GID '%s' must be unique", group.Gid),
				})
			} else {
				groupGIDs[gid] = struct{}{}
			}
		}

		if group.Scope != "" {
			validScopes := []string{"system", "local"}
			if !contains(validScopes, group.Scope) {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("system.group[%d].scope", i),
					Message: fmt.Sprintf("group scope '%s' must be one of: %v", group.Scope, validScopes),
				})
			}
		}
	}

	return errors
}

// validatePfSenseUserScope validates pfSense user scope requirements.
func validatePfSenseUserScope(user pfsense.User, index int) []ValidationError {
	var errors []ValidationError

	if user.Scope == "" {
		return errors
	}

	validScopes := []string{"system", "local"}
	if !contains(validScopes, user.Scope) {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].scope", index),
			Message: fmt.Sprintf("user scope '%s' must be one of: %v", user.Scope, validScopes),
		})
	}

	return errors
}
