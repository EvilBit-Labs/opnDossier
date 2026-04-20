package processor

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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
		); ip6 != "" && ip6 != "dhcp6" && ip6 != "slaac" && ip6 != "track6" && ip6 != "none" &&
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

// validFirewallStateTypes enumerates the accepted values for FirewallRule.StateType.
var validFirewallStateTypes = map[string]struct{}{
	"keep state":     {},
	"sloppy state":   {},
	"synproxy state": {},
	"modulate state": {},
	"none":           {},
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
		errors = append(errors, validateFirewallRule(i, rule, ifaceSet)...)
	}
	return errors
}

// validateFirewallRule runs the per-rule checks. Splitting each concern into
// a named helper keeps validateCommonFirewallRules cognitively flat.
func validateFirewallRule(
	i int,
	rule common.FirewallRule,
	ifaceSet map[string]struct{},
) []ValidationError {
	prefix := fmt.Sprintf("firewallRules[%d]", i)
	var errors []ValidationError
	errors = append(errors, validateRuleTypeAndProtocol(prefix, rule)...)
	errors = append(errors, validateRuleInterfaces(prefix, rule, ifaceSet)...)
	errors = append(errors, validateRuleAddresses(prefix, rule)...)
	errors = append(errors, validateRulePorts(prefix, rule)...)
	errors = append(errors, validateRuleDirection(prefix, rule)...)
	errors = append(errors, validateRuleStateAndRate(prefix, rule)...)
	return errors
}

func validateRuleTypeAndProtocol(prefix string, rule common.FirewallRule) []ValidationError {
	var errors []ValidationError
	if rule.Type != "" &&
		rule.Type != common.RuleTypePass &&
		rule.Type != common.RuleTypeBlock &&
		rule.Type != common.RuleTypeReject {
		errors = append(errors, ValidationError{Field: prefix + ".type", Message: "invalid firewall rule type"})
	}
	if rule.IPProtocol != "" &&
		rule.IPProtocol != common.IPProtocolInet &&
		rule.IPProtocol != common.IPProtocolInet6 {
		errors = append(errors, ValidationError{Field: prefix + ".ipProtocol", Message: "invalid IP protocol"})
	}
	return errors
}

func validateRuleInterfaces(
	prefix string,
	rule common.FirewallRule,
	ifaceSet map[string]struct{},
) []ValidationError {
	var errors []ValidationError
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
	return errors
}

func validateRuleAddresses(prefix string, rule common.FirewallRule) []ValidationError {
	var errors []ValidationError
	if src := strings.TrimSpace(rule.Source.Address); src != "" && !strings.EqualFold(src, "any") {
		if looksLikeMalformedIP(src) && !isValidIP(src) && !isValidIPv6(src) && !isValidCIDR(src) {
			errors = append(errors, ValidationError{
				Field:   prefix + ".source.address",
				Message: "malformed source address",
			})
		}
	}
	if dst := strings.TrimSpace(rule.Destination.Address); dst != "" && !strings.EqualFold(dst, "any") {
		if looksLikeMalformedIP(dst) && !isValidIP(dst) && !isValidIPv6(dst) && !isValidCIDR(dst) {
			errors = append(errors, ValidationError{
				Field:   prefix + ".destination.address",
				Message: "malformed destination address",
			})
		}
	}
	return errors
}

func validateRulePorts(prefix string, rule common.FirewallRule) []ValidationError {
	var errors []ValidationError
	if !isValidPortOrRange(rule.Source.Port) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".source.port",
			Message: "invalid source port or range",
		})
	}
	if !isValidPortOrRange(rule.Destination.Port) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".destination.port",
			Message: "invalid destination port or range",
		})
	}
	return errors
}

func validateRuleDirection(prefix string, rule common.FirewallRule) []ValidationError {
	var errors []ValidationError
	if rule.Direction != "" &&
		rule.Direction != common.DirectionIn &&
		rule.Direction != common.DirectionOut &&
		rule.Direction != common.DirectionAny {
		errors = append(errors, ValidationError{
			Field:   prefix + ".direction",
			Message: "invalid firewall direction",
		})
	}
	if rule.Floating && strings.TrimSpace(string(rule.Direction)) == "" {
		errors = append(errors, ValidationError{
			Field:   prefix + ".direction",
			Message: "floating rule requires direction",
		})
	}
	return errors
}

func validateRuleStateAndRate(prefix string, rule common.FirewallRule) []ValidationError {
	var errors []ValidationError
	if rule.StateType != "" {
		if _, ok := validFirewallStateTypes[rule.StateType]; !ok {
			errors = append(errors, ValidationError{
				Field:   prefix + ".stateType",
				Message: "invalid state type",
			})
		}
	}
	if rule.MaxSrcConnRate != "" && !isValidConnRateFormat(rule.MaxSrcConnRate) {
		errors = append(errors, ValidationError{
			Field:   prefix + ".maxSrcConnRate",
			Message: "invalid max source connection rate format",
		})
	}
	return errors
}

// validateCommonNAT checks NAT configuration for valid outbound mode and
// reflection settings on inbound rules.
func validateCommonNAT(nat *common.NATConfig) []ValidationError {
	errors := make([]ValidationError, 0, len(nat.InboundRules)+1)

	if nat.OutboundMode != "" &&
		nat.OutboundMode != common.OutboundAutomatic &&
		nat.OutboundMode != common.OutboundHybrid &&
		nat.OutboundMode != common.OutboundAdvanced &&
		nat.OutboundMode != common.OutboundDisabled {
		errors = append(errors, ValidationError{Field: "nat.outboundMode", Message: "invalid NAT outbound mode"})
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

// validScopes enumerates the accepted values for user/group Scope. Shared by
// the per-entry validators below.
var validScopes = map[string]struct{}{"system": {}, "local": {}}

// validateCommonUsersAndGroups checks user and group entries for required fields,
// uniqueness of names and IDs, valid scopes, and that users reference known groups.
func validateCommonUsersAndGroups(users []common.User, groups []common.Group) []ValidationError {
	errors := make([]ValidationError, 0, len(users)+len(groups))

	groupNames := make(map[string]bool, len(groups))
	groupIDs := make(map[string]bool, len(groups))
	for i, group := range groups {
		errors = append(errors, validateGroupEntry(i, group, groupNames, groupIDs)...)
	}

	userNames := make(map[string]bool, len(users))
	userIDs := make(map[string]bool, len(users))
	for i, user := range users {
		errors = append(errors, validateUserEntry(i, user, userNames, userIDs, groupNames)...)
	}

	return errors
}

// validateGroupEntry validates one group and records its name/GID in the
// provided uniqueness maps. Splitting the per-entry validation out keeps
// validateCommonUsersAndGroups flat enough to pass gocognit.
func validateGroupEntry(
	i int,
	group common.Group,
	groupNames, groupIDs map[string]bool,
) []ValidationError {
	var errors []ValidationError
	prefix := fmt.Sprintf("groups[%d]", i)

	switch {
	case strings.TrimSpace(group.Name) == "":
		errors = append(errors, ValidationError{Field: prefix + ".name", Message: "group name is required"})
	case groupNames[group.Name]:
		errors = append(errors, ValidationError{Field: prefix + ".name", Message: "group name must be unique"})
		groupNames[group.Name] = true
	default:
		groupNames[group.Name] = true
	}

	errors = append(errors, validateIDField(prefix+".gid", "group GID", group.GID, groupIDs)...)

	if group.Scope != "" {
		if _, ok := validScopes[group.Scope]; !ok {
			errors = append(errors, ValidationError{Field: prefix + ".scope", Message: "invalid group scope"})
		}
	}

	return errors
}

// validateUserEntry validates one user and records its name/UID in the
// provided uniqueness maps. The group-name reference is checked against
// groupNames (which must already be populated by the group pass).
func validateUserEntry(
	i int,
	user common.User,
	userNames, userIDs, groupNames map[string]bool,
) []ValidationError {
	var errors []ValidationError
	prefix := fmt.Sprintf("users[%d]", i)

	switch {
	case strings.TrimSpace(user.Name) == "":
		errors = append(errors, ValidationError{Field: prefix + ".name", Message: "user name is required"})
	case userNames[user.Name]:
		errors = append(errors, ValidationError{Field: prefix + ".name", Message: "user name must be unique"})
		userNames[user.Name] = true
	default:
		userNames[user.Name] = true
	}

	errors = append(errors, validateIDField(prefix+".uid", "user UID", user.UID, userIDs)...)

	if user.GroupName != "" && !groupNames[user.GroupName] {
		errors = append(errors, ValidationError{
			Field:   prefix + ".groupName",
			Message: "user references unknown group",
		})
	}

	if user.Scope != "" {
		if _, ok := validScopes[user.Scope]; !ok {
			errors = append(errors, ValidationError{Field: prefix + ".scope", Message: "invalid user scope"})
		}
	}

	return errors
}

// validateIDField validates a UID or GID string: must be a non-negative
// integer and unique within the collection. On success the id is recorded in
// seen. labelKind is used in error messages ("user UID", "group GID") so one
// helper covers both entry types.
func validateIDField(field, labelKind, raw string, seen map[string]bool) []ValidationError {
	if strings.TrimSpace(raw) == "" {
		return []ValidationError{{Field: field, Message: labelKind + " is required"}}
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return []ValidationError{{Field: field, Message: labelKind + " must be a non-negative integer"}}
	}

	if seen[raw] {
		return []ValidationError{{Field: field, Message: labelKind + " must be unique"}}
	}
	seen[raw] = true
	return nil
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
