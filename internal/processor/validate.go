package processor

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
)

// Initial slice capacities for validation error collectors.
const (
	commonValidationErrorCapacity = 16
	systemValidationErrorCapacity = 8
)

// ValidationError represents a validation error with field and message information.
type ValidationError struct {
	Field   string
	Message string
}

// Error implements the error interface for ValidationError.
func (e ValidationError) Error() string {
	return e.Message
}

// ValidateCommonDevice performs best-effort semantic validation of a
// CommonDevice configuration. It checks the most critical domain invariants
// (hostname format, DHCP range ordering, firewall rule sanity, user/group
// uniqueness, sysctl name format) and returns all detected errors.
//
// NOTE: The `validate` command (internal/validator) remains the authoritative
// deep validator operating on the raw OPNsense schema. This function is a
// pipeline guard only — it catches obvious misconfigurations early without
// duplicating the full schema-level checks.
func ValidateCommonDevice(cfg *common.CommonDevice) []ValidationError {
	if cfg == nil {
		return []ValidationError{{
			Field:   "document",
			Message: "configuration is nil",
		}}
	}

	errors := make([]ValidationError, 0, commonValidationErrorCapacity)
	errors = append(errors, validateCommonSystem(&cfg.System)...)
	errors = append(errors, validateCommonInterfaces(cfg.Interfaces)...)
	errors = append(errors, validateCommonDHCP(cfg.DHCP, cfg.Interfaces)...)
	errors = append(errors, validateCommonFirewallRules(cfg.FirewallRules, cfg.Interfaces)...)
	errors = append(errors, validateCommonNAT(&cfg.NAT)...)
	errors = append(errors, validateCommonUsersAndGroups(cfg.Users, cfg.Groups)...)
	errors = append(errors, validateCommonSysctl(cfg.Sysctl)...)

	return errors
}

// validateCommonSystem checks system-level fields including hostname, domain,
// timezone, optimization mode, WebGUI protocol, powerd modes, and bogons interval.
func validateCommonSystem(s *common.System) []ValidationError {
	errors := make([]ValidationError, 0, systemValidationErrorCapacity)

	if strings.TrimSpace(s.Hostname) == "" {
		errors = append(errors, ValidationError{Field: "system.hostname", Message: "hostname is required"})
	} else if !isValidHostname(s.Hostname) {
		errors = append(errors, ValidationError{Field: "system.hostname", Message: "invalid hostname format"})
	}

	if strings.TrimSpace(s.Domain) == "" {
		errors = append(errors, ValidationError{Field: "system.domain", Message: "domain is required"})
	}

	if s.Timezone != "" && !isValidTimezone(s.Timezone) {
		errors = append(errors, ValidationError{Field: "system.timezone", Message: "invalid timezone format"})
	}

	if s.Optimization != "" {
		if _, ok := constants.ValidOptimizationModes[s.Optimization]; !ok {
			errors = append(
				errors,
				ValidationError{Field: "system.optimization", Message: "invalid optimization value"},
			)
		}
	}

	if s.WebGUI.Protocol != "" {
		validProtocols := map[string]struct{}{"http": {}, "https": {}}
		if _, ok := validProtocols[s.WebGUI.Protocol]; !ok {
			errors = append(
				errors,
				ValidationError{Field: "system.webGui.protocol", Message: "invalid web GUI protocol"},
			)
		}
	}

	if s.PowerdACMode != "" {
		if _, ok := constants.ValidPowerdModes[s.PowerdACMode]; !ok {
			errors = append(errors, ValidationError{Field: "system.powerdAcMode", Message: "invalid AC power mode"})
		}
	}

	if s.PowerdBatteryMode != "" {
		if _, ok := constants.ValidPowerdModes[s.PowerdBatteryMode]; !ok {
			errors = append(
				errors,
				ValidationError{Field: "system.powerdBatteryMode", Message: "invalid battery power mode"},
			)
		}
	}

	if s.PowerdNormalMode != "" {
		if _, ok := constants.ValidPowerdModes[s.PowerdNormalMode]; !ok {
			errors = append(
				errors,
				ValidationError{Field: "system.powerdNormalMode", Message: "invalid normal power mode"},
			)
		}
	}

	if s.Bogons.Interval != "" {
		validIntervals := map[string]struct{}{
			"daily":   {},
			"weekly":  {},
			"monthly": {},
			"never":   {},
		}
		if _, ok := validIntervals[s.Bogons.Interval]; !ok {
			errors = append(
				errors,
				ValidationError{Field: "system.bogons.interval", Message: "invalid bogons interval"},
			)
		}
	}

	return errors
}

// validateCommonInterfaces checks each interface for valid IP addresses, subnet
// prefix lengths, and MTU values.
func validateCommonInterfaces(ifaces []common.Interface) []ValidationError {
	errors := make([]ValidationError, 0, len(ifaces))

	for i, iface := range ifaces {
		prefix := fmt.Sprintf("interfaces[%d]", i)
		if iface.Name != "" {
			prefix = "interfaces." + iface.Name
		}

		if ip := strings.TrimSpace(iface.IPAddress); ip != "" && ip != "dhcp" && ip != "none" && !isValidIP(ip) {
			errors = append(errors, ValidationError{Field: prefix + ".ipAddress", Message: "invalid IPv4 address"})
		}

		if ip6 := strings.TrimSpace(
			iface.IPv6Address,
		); ip6 != "" && ip6 != "dhcp6" && ip6 != "slaac" && ip6 != "none" &&
			!isValidIPv6(ip6) {
			errors = append(errors, ValidationError{Field: prefix + ".ipv6Address", Message: "invalid IPv6 address"})
		}

		if iface.Subnet != "" {
			subnet, err := strconv.Atoi(iface.Subnet)
			if err != nil || subnet < 0 || subnet > constants.MaxIPv4Subnet {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".subnet", Message: "IPv4 subnet must be between 0 and 32"},
				)
			}
		}

		if iface.SubnetV6 != "" {
			subnetV6, err := strconv.Atoi(iface.SubnetV6)
			if err != nil || subnetV6 < 0 || subnetV6 > constants.MaxIPv6Subnet {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".subnetV6", Message: "IPv6 subnet must be between 0 and 128"},
				)
			}
		}

		if iface.MTU != "" {
			mtu, err := strconv.Atoi(iface.MTU)
			if err != nil || mtu < constants.MinMTU || mtu > constants.MaxMTU {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".mtu", Message: "MTU must be between 68 and 9000"},
				)
			}
		}
	}

	return errors
}

// validateCommonDHCP checks each DHCP scope for valid interface references and
// well-ordered IP address ranges.
func validateCommonDHCP(scopes []common.DHCPScope, ifaces []common.Interface) []ValidationError {
	errors := make([]ValidationError, 0, len(scopes))
	ifaceSet := make(map[string]struct{}, len(ifaces))

	for _, iface := range ifaces {
		if iface.Name != "" {
			ifaceSet[iface.Name] = struct{}{}
		}
	}

	for i, scope := range scopes {
		prefix := fmt.Sprintf("dhcp[%d]", i)

		if scope.Interface != "" {
			if _, ok := ifaceSet[scope.Interface]; !ok {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".interface", Message: "DHCP scope references unknown interface"},
				)
			}
		}

		fromValid := true
		toValid := true

		if scope.Range.From != "" && !isValidIP(scope.Range.From) {
			fromValid = false
			errors = append(
				errors,
				ValidationError{Field: prefix + ".range.from", Message: "invalid DHCP range start IP"},
			)
		}

		if scope.Range.To != "" && !isValidIP(scope.Range.To) {
			toValid = false
			errors = append(errors, ValidationError{Field: prefix + ".range.to", Message: "invalid DHCP range end IP"})
		}

		if fromValid && toValid && scope.Range.From != "" && scope.Range.To != "" {
			fromIP := net.ParseIP(scope.Range.From).To4()
			toIP := net.ParseIP(scope.Range.To).To4()
			if fromIP != nil && toIP != nil && bytes.Compare(fromIP, toIP) >= 0 {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".range", Message: "DHCP range start must be less than end"},
				)
			}
		}
	}

	return errors
}

// validateCommonFirewallRules checks each firewall rule for valid types, protocols,
// interface references, source/destination addresses, ports, direction, state type,
// and connection rate format.
func validateCommonFirewallRules(rules []common.FirewallRule, ifaces []common.Interface) []ValidationError {
	errors := make([]ValidationError, 0, len(rules))
	ifaceSet := make(map[string]struct{}, len(ifaces))

	for _, iface := range ifaces {
		if iface.Name != "" {
			ifaceSet[iface.Name] = struct{}{}
		}
	}

	for i, rule := range rules {
		prefix := fmt.Sprintf("firewallRules[%d]", i)

		if rule.Type != "" {
			validTypes := map[string]struct{}{"pass": {}, "block": {}, "reject": {}}
			if _, ok := validTypes[rule.Type]; !ok {
				errors = append(errors, ValidationError{Field: prefix + ".type", Message: "invalid firewall rule type"})
			}
		}

		if rule.IPProtocol != "" {
			validProtocols := map[string]struct{}{"inet": {}, "inet6": {}}
			if _, ok := validProtocols[rule.IPProtocol]; !ok {
				errors = append(errors, ValidationError{Field: prefix + ".ipProtocol", Message: "invalid IP protocol"})
			}
		}

		for idx, ifaceName := range rule.Interfaces {
			if ifaceName == "" {
				continue
			}

			if _, ok := ifaceSet[ifaceName]; !ok {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("%s.interfaces[%d]", prefix, idx),
					Message: "firewall rule references unknown interface",
				})
			}
		}

		if src := strings.TrimSpace(rule.Source.Address); src != "" && !strings.EqualFold(src, "any") {
			if looksLikeMalformedIP(src) && !isValidIP(src) && !isValidIPv6(src) && !isValidCIDR(src) {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".source.address", Message: "malformed source address"},
				)
			}
		}

		if dst := strings.TrimSpace(rule.Destination.Address); dst != "" && !strings.EqualFold(dst, "any") {
			if looksLikeMalformedIP(dst) && !isValidIP(dst) && !isValidIPv6(dst) && !isValidCIDR(dst) {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".destination.address", Message: "malformed destination address"},
				)
			}
		}

		if !isValidPortOrRange(rule.Source.Port) {
			errors = append(
				errors,
				ValidationError{Field: prefix + ".source.port", Message: "invalid source port or range"},
			)
		}

		if !isValidPortOrRange(rule.Destination.Port) {
			errors = append(
				errors,
				ValidationError{Field: prefix + ".destination.port", Message: "invalid destination port or range"},
			)
		}

		if rule.Direction != "" {
			validDirections := map[string]struct{}{"in": {}, "out": {}, "any": {}}
			if _, ok := validDirections[rule.Direction]; !ok {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".direction", Message: "invalid firewall direction"},
				)
			}
		}

		if rule.Floating && strings.TrimSpace(rule.Direction) == "" {
			errors = append(
				errors,
				ValidationError{Field: prefix + ".direction", Message: "floating rule requires direction"},
			)
		}

		if rule.StateType != "" {
			validStateTypes := map[string]struct{}{
				"keep state":     {},
				"sloppy state":   {},
				"synproxy state": {},
				"modulate state": {},
				"none":           {},
			}
			if _, ok := validStateTypes[rule.StateType]; !ok {
				errors = append(errors, ValidationError{Field: prefix + ".stateType", Message: "invalid state type"})
			}
		}

		if rule.MaxSrcConnRate != "" && !isValidConnRateFormat(rule.MaxSrcConnRate) {
			errors = append(
				errors,
				ValidationError{
					Field:   prefix + ".maxSrcConnRate",
					Message: "invalid max source connection rate format",
				},
			)
		}
	}

	return errors
}

// validateCommonNAT checks NAT configuration for valid outbound mode and
// reflection settings on inbound rules.
func validateCommonNAT(nat *common.NATConfig) []ValidationError {
	errors := make([]ValidationError, 0, len(nat.InboundRules)+1)

	if nat.OutboundMode != "" {
		validModes := map[string]struct{}{
			"automatic": {},
			"hybrid":    {},
			"advanced":  {},
			"disabled":  {},
		}
		if _, ok := validModes[nat.OutboundMode]; !ok {
			errors = append(errors, ValidationError{Field: "nat.outboundMode", Message: "invalid NAT outbound mode"})
		}
	}

	for i, rule := range nat.InboundRules {
		if rule.NATReflection == "" {
			continue
		}

		validReflection := map[string]struct{}{"enable": {}, "disable": {}, "purenat": {}}
		if _, ok := validReflection[rule.NATReflection]; !ok {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("nat.inboundRules[%d].natReflection", i),
				Message: "invalid NAT reflection mode",
			})
		}
	}

	return errors
}

// validateCommonUsersAndGroups checks user and group entries for required fields,
// uniqueness of names and IDs, valid scopes, and that users reference known groups.
func validateCommonUsersAndGroups(users []common.User, groups []common.Group) []ValidationError {
	errors := make([]ValidationError, 0, len(users)+len(groups))

	groupNames := make(map[string]bool, len(groups))
	groupIDs := make(map[string]bool, len(groups))

	for i, group := range groups {
		prefix := fmt.Sprintf("groups[%d]", i)

		if strings.TrimSpace(group.Name) == "" {
			errors = append(errors, ValidationError{Field: prefix + ".name", Message: "group name is required"})
		} else {
			if groupNames[group.Name] {
				errors = append(errors, ValidationError{Field: prefix + ".name", Message: "group name must be unique"})
			}
			groupNames[group.Name] = true
		}

		if strings.TrimSpace(group.GID) == "" {
			errors = append(errors, ValidationError{Field: prefix + ".gid", Message: "group GID is required"})
		} else {
			gid, err := strconv.Atoi(group.GID)
			if err != nil || gid <= 0 {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".gid", Message: "group GID must be a positive integer"},
				)
			} else {
				if groupIDs[group.GID] {
					errors = append(
						errors,
						ValidationError{Field: prefix + ".gid", Message: "group GID must be unique"},
					)
				}
				groupIDs[group.GID] = true
			}
		}

		if group.Scope != "" {
			validScope := map[string]struct{}{"system": {}, "local": {}}
			if _, ok := validScope[group.Scope]; !ok {
				errors = append(errors, ValidationError{Field: prefix + ".scope", Message: "invalid group scope"})
			}
		}
	}

	userNames := make(map[string]bool, len(users))
	userIDs := make(map[string]bool, len(users))

	for i, user := range users {
		prefix := fmt.Sprintf("users[%d]", i)

		if strings.TrimSpace(user.Name) == "" {
			errors = append(errors, ValidationError{Field: prefix + ".name", Message: "user name is required"})
		} else {
			if userNames[user.Name] {
				errors = append(errors, ValidationError{Field: prefix + ".name", Message: "user name must be unique"})
			}
			userNames[user.Name] = true
		}

		if strings.TrimSpace(user.UID) == "" {
			errors = append(errors, ValidationError{Field: prefix + ".uid", Message: "user UID is required"})
		} else {
			uid, err := strconv.Atoi(user.UID)
			if err != nil || uid <= 0 {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".uid", Message: "user UID must be a positive integer"},
				)
			} else {
				if userIDs[user.UID] {
					errors = append(errors, ValidationError{Field: prefix + ".uid", Message: "user UID must be unique"})
				}
				userIDs[user.UID] = true
			}
		}

		if user.GroupName != "" && !groupNames[user.GroupName] {
			errors = append(
				errors,
				ValidationError{Field: prefix + ".groupName", Message: "user references unknown group"},
			)
		}

		if user.Scope != "" {
			validScope := map[string]struct{}{"system": {}, "local": {}}
			if _, ok := validScope[user.Scope]; !ok {
				errors = append(errors, ValidationError{Field: prefix + ".scope", Message: "invalid user scope"})
			}
		}
	}

	return errors
}

// validateCommonSysctl checks sysctl tunables for required fields, uniqueness,
// and valid naming format (dotted identifier like "net.inet.tcp.msl").
func validateCommonSysctl(items []common.SysctlItem) []ValidationError {
	errors := make([]ValidationError, 0, len(items))
	seenTunables := make(map[string]bool, len(items))

	for i, item := range items {
		prefix := fmt.Sprintf("sysctl[%d]", i)

		if strings.TrimSpace(item.Tunable) == "" {
			errors = append(errors, ValidationError{Field: prefix + ".tunable", Message: "sysctl tunable is required"})
		} else {
			if seenTunables[item.Tunable] {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".tunable", Message: "sysctl tunable must be unique"},
				)
			}
			seenTunables[item.Tunable] = true

			if !isValidSysctlName(item.Tunable) {
				errors = append(
					errors,
					ValidationError{Field: prefix + ".tunable", Message: "invalid sysctl tunable format"},
				)
			}
		}

		if strings.TrimSpace(item.Value) == "" {
			errors = append(errors, ValidationError{Field: prefix + ".value", Message: "sysctl value is required"})
		}
	}

	return errors
}
