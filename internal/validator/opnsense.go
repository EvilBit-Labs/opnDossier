package validator

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidateOpnsense validates the given OPNsense configuration and returns a slice of ValidationErrors.
func ValidateOpnsense(o *model.Opnsense) []ValidationError {
	var errors []ValidationError

	// Validate system configuration
	errors = append(errors, validateSystem(&o.System)...)

	// Validate interfaces
	errors = append(errors, validateInterfaces(&o.Interfaces)...)

	// Validate DHCP configuration
	errors = append(errors, validateDhcpd(&o.Dhcpd)...)

	// Validate filter rules
	errors = append(errors, validateFilter(&o.Filter)...)

	// Validate NAT configuration
	errors = append(errors, validateNat(&o.Nat)...)

	// Validate system users and groups
	errors = append(errors, validateUsersAndGroups(&o.System)...)

	// Validate sysctl items
	errors = append(errors, validateSysctl(o.Sysctl)...)

	return errors
}

// validateSystem validates system-level configuration.
func validateSystem(system *model.System) []ValidationError {
	var errors []ValidationError

	// Hostname is required and must be valid
	if system.Hostname == "" {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: "hostname is required",
		})
	} else if !isValidHostname(system.Hostname) {
		errors = append(errors, ValidationError{
			Field:   "system.hostname",
			Message: fmt.Sprintf("hostname '%s' contains invalid characters", system.Hostname),
		})
	}

	// Domain is required
	if system.Domain == "" {
		errors = append(errors, ValidationError{
			Field:   "system.domain",
			Message: "domain is required",
		})
	}

	// Validate timezone format
	if system.Timezone != "" && !isValidTimezone(system.Timezone) {
		errors = append(errors, ValidationError{
			Field:   "system.timezone",
			Message: "invalid timezone format: " + system.Timezone,
		})
	}

	// Validate optimization setting
	validOptimizations := []string{"normal", "high-latency", "aggressive", "conservative"}
	if system.Optimization != "" && !contains(validOptimizations, system.Optimization) {
		errors = append(errors, ValidationError{
			Field:   "system.optimization",
			Message: fmt.Sprintf("optimization '%s' must be one of: %v", system.Optimization, validOptimizations),
		})
	}

	// Validate webgui protocol
	validProtocols := []string{"http", "https"}
	if system.Webgui.Protocol != "" && !contains(validProtocols, system.Webgui.Protocol) {
		errors = append(errors, ValidationError{
			Field:   "system.webgui.protocol",
			Message: fmt.Sprintf("protocol '%s' must be one of: %v", system.Webgui.Protocol, validProtocols),
		})
	}

	// Validate power management modes
	validPowerModes := []string{"hadp", "hiadp", "adaptive", "minimum", "maximum"}
	if system.PowerdAcMode != "" && !contains(validPowerModes, system.PowerdAcMode) {
		errors = append(errors, ValidationError{
			Field:   "system.powerd_ac_mode",
			Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdAcMode, validPowerModes),
		})
	}

	if system.PowerdBatteryMode != "" && !contains(validPowerModes, system.PowerdBatteryMode) {
		errors = append(errors, ValidationError{
			Field:   "system.powerd_battery_mode",
			Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdBatteryMode, validPowerModes),
		})
	}

	if system.PowerdNormalMode != "" && !contains(validPowerModes, system.PowerdNormalMode) {
		errors = append(errors, ValidationError{
			Field:   "system.powerd_normal_mode",
			Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdNormalMode, validPowerModes),
		})
	}

	// Validate bogons interval
	validBogonsIntervals := []string{"monthly", "weekly", "daily", "never"}
	if system.Bogons.Interval != "" && !contains(validBogonsIntervals, system.Bogons.Interval) {
		errors = append(errors, ValidationError{
			Field:   "system.bogons.interval",
			Message: fmt.Sprintf("bogons interval '%s' must be one of: %v", system.Bogons.Interval, validBogonsIntervals),
		})
	}

	return errors
}

// validateInterfaces validates network interface configuration.
func validateInterfaces(interfaces *model.Interfaces) []ValidationError {
	var errors []ValidationError

	// Validate WAN interface
	errors = append(errors, validateInterface(&interfaces.Wan, "wan")...)

	// Validate LAN interface
	errors = append(errors, validateInterface(&interfaces.Lan, "lan")...)

	return errors
}

// validateInterface validates a single interface configuration.
func validateInterface(iface *model.Interface, name string) []ValidationError {
	var errors []ValidationError

	// Validate IP address configuration
	if iface.IPAddr != "" {
		validIPTypes := []string{"dhcp", "dhcp6", "track6", "none"}
		if !contains(validIPTypes, iface.IPAddr) && !isValidIP(iface.IPAddr) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.ipaddr", name),
				Message: fmt.Sprintf("IP address '%s' must be a valid IP address or one of: %v", iface.IPAddr, validIPTypes),
			})
		}
	}

	// Validate IPv6 address configuration
	if iface.IPAddrv6 != "" {
		validIPv6Types := []string{"dhcp6", "slaac", "track6", "none"}
		if !contains(validIPv6Types, iface.IPAddrv6) && !isValidIPv6(iface.IPAddrv6) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.ipaddrv6", name),
				Message: fmt.Sprintf("IPv6 address '%s' must be a valid IPv6 address or one of: %v", iface.IPAddrv6, validIPv6Types),
			})
		}
	}

	// Validate subnet mask
	if iface.Subnet != "" {
		if subnet, err := strconv.Atoi(iface.Subnet); err != nil || subnet < 0 || subnet > 32 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnet", name),
				Message: fmt.Sprintf("subnet mask '%s' must be a valid subnet mask (0-32)", iface.Subnet),
			})
		}
	}

	// Validate IPv6 subnet
	if iface.Subnetv6 != "" {
		if subnet, err := strconv.Atoi(iface.Subnetv6); err != nil || subnet < 0 || subnet > 128 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.subnetv6", name),
				Message: fmt.Sprintf("IPv6 subnet mask '%s' must be a valid IPv6 subnet mask (0-128)", iface.Subnetv6),
			})
		}
	}

	// Validate MTU
	if iface.MTU != "" {
		if mtu, err := strconv.Atoi(iface.MTU); err != nil || mtu < 68 || mtu > 9000 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.mtu", name),
				Message: fmt.Sprintf("MTU '%s' must be a valid MTU (68-9000)", iface.MTU),
			})
		}
	}

	// Cross-field validation: track6 configuration
	if iface.IPAddrv6 == "track6" {
		if iface.Track6Interface == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-interface", name),
				Message: "track6-interface is required when using track6 IPv6 addressing",
			})
		}
		if iface.Track6PrefixID == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("interfaces.%s.track6-prefix-id", name),
				Message: "track6-prefix-id is required when using track6 IPv6 addressing",
			})
		}
	}

	return errors
}

// validateDhcpd validates DHCP server configuration.
func validateDhcpd(dhcpd *model.Dhcpd) []ValidationError {
	var errors []ValidationError

	// Validate LAN DHCP range
	if dhcpd.Lan.Range.From != "" || dhcpd.Lan.Range.To != "" {
		if dhcpd.Lan.Range.From != "" && !isValidIP(dhcpd.Lan.Range.From) {
			errors = append(errors, ValidationError{
				Field:   "dhcpd.lan.range.from",
				Message: fmt.Sprintf("DHCP range 'from' address '%s' must be a valid IP address", dhcpd.Lan.Range.From),
			})
		}
		if dhcpd.Lan.Range.To != "" && !isValidIP(dhcpd.Lan.Range.To) {
			errors = append(errors, ValidationError{
				Field:   "dhcpd.lan.range.to",
				Message: fmt.Sprintf("DHCP range 'to' address '%s' must be a valid IP address", dhcpd.Lan.Range.To),
			})
		}

		// Cross-validation: from address should be less than to address
		if isValidIP(dhcpd.Lan.Range.From) && isValidIP(dhcpd.Lan.Range.To) {
			fromIP := net.ParseIP(dhcpd.Lan.Range.From).To4()
			toIP := net.ParseIP(dhcpd.Lan.Range.To).To4()
			if fromIP != nil && toIP != nil {
				// Compare byte by byte
				for i := 0; i < 4; i++ {
					if fromIP[i] > toIP[i] {
						errors = append(errors, ValidationError{
							Field:   "dhcpd.lan.range",
							Message: fmt.Sprintf("DHCP range 'from' address (%s) must be less than 'to' address (%s)", dhcpd.Lan.Range.From, dhcpd.Lan.Range.To),
						})
						break
					} else if fromIP[i] < toIP[i] {
						break
					}
				}
			}
		}
	}

	return errors
}

// validateFilter validates firewall filter rules.
func validateFilter(filter *model.Filter) []ValidationError {
	var errors []ValidationError

	for i, rule := range filter.Rule {
		// Validate rule type
		validTypes := []string{"pass", "block", "reject"}
		if rule.Type != "" && !contains(validTypes, rule.Type) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].type", i),
				Message: fmt.Sprintf("rule type '%s' must be one of: %v", rule.Type, validTypes),
			})
		}

		// Validate IP protocol
		validIPProtocols := []string{"inet", "inet6"}
		if rule.IPProtocol != "" && !contains(validIPProtocols, rule.IPProtocol) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].ipprotocol", i),
				Message: fmt.Sprintf("IP protocol '%s' must be one of: %v", rule.IPProtocol, validIPProtocols),
			})
		}

		// Validate interface
		validInterfaces := []string{"wan", "lan", "opt1", "opt2", "opt3", "opt4"}
		if rule.Interface != "" && !contains(validInterfaces, rule.Interface) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].interface", i),
				Message: fmt.Sprintf("interface '%s' must be one of: %v", rule.Interface, validInterfaces),
			})
		}

		// Validate source network
		validNetworks := []string{"any", "lan", "wan"}
		if rule.Source.Network != "" && !contains(validNetworks, rule.Source.Network) && !isValidCIDR(rule.Source.Network) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("filter.rule[%d].source.network", i),
				Message: fmt.Sprintf("source network '%s' must be a valid CIDR or one of: %v", rule.Source.Network, validNetworks),
			})
		}
	}

	return errors
}

// validateNat validates NAT configuration.
func validateNat(nat *model.Nat) []ValidationError {
	var errors []ValidationError

	// Validate outbound NAT mode
	validModes := []string{"automatic", "hybrid", "advanced", "disabled"}
	if nat.Outbound.Mode != "" && !contains(validModes, nat.Outbound.Mode) {
		errors = append(errors, ValidationError{
			Field:   "nat.outbound.mode",
			Message: fmt.Sprintf("NAT outbound mode '%s' must be one of: %v", nat.Outbound.Mode, validModes),
		})
	}

	return errors
}

// validateUsersAndGroups validates system users and groups.
func validateUsersAndGroups(system *model.System) []ValidationError {
	var errors []ValidationError

	// Track group names and GIDs to ensure uniqueness
	groupNames := make(map[string]bool)
	groupGIDs := make(map[string]bool)

	// Validate groups
	for i, group := range system.Group {
		// Group name is required and must be unique
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

		// Validate GID
		if group.Gid == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].gid", i),
				Message: "group GID is required",
			})
		} else if gid, err := strconv.Atoi(group.Gid); err != nil || gid < 0 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].gid", i),
				Message: fmt.Sprintf("GID '%s' must be a positive integer", group.Gid),
			})
		} else if groupGIDs[group.Gid] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].gid", i),
				Message: fmt.Sprintf("group GID '%s' must be unique", group.Gid),
			})
		} else {
			groupGIDs[group.Gid] = true
		}

		// Validate scope
		validScopes := []string{"system", "local"}
		if group.Scope != "" && !contains(validScopes, group.Scope) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.group[%d].scope", i),
				Message: fmt.Sprintf("group scope '%s' must be one of: %v", group.Scope, validScopes),
			})
		}
	}

	// Track user names and UIDs to ensure uniqueness
	userNames := make(map[string]bool)
	userUIDs := make(map[string]bool)

	// Validate users
	for i, user := range system.User {
		// User name is required and must be unique
		switch {
		case user.Name == "":
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].name", i),
				Message: "user name is required",
			})
		case userNames[user.Name]:
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].name", i),
				Message: fmt.Sprintf("user name '%s' must be unique", user.Name),
			})
		default:
			userNames[user.Name] = true
		}

		// Validate UID
		if user.UID == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].uid", i),
				Message: "user UID is required",
			})
		} else if uid, err := strconv.Atoi(user.UID); err != nil || uid < 0 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].uid", i),
				Message: fmt.Sprintf("UID '%s' must be a positive integer", user.UID),
			})
		} else if userUIDs[user.UID] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].uid", i),
				Message: fmt.Sprintf("user UID '%s' must be unique", user.UID),
			})
		} else {
			userUIDs[user.UID] = true
		}

		// Validate group membership - group must exist
		if user.Groupname != "" && !groupNames[user.Groupname] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].groupname", i),
				Message: fmt.Sprintf("referenced group '%s' does not exist", user.Groupname),
			})
		}

		// Validate scope
		validScopes := []string{"system", "local"}
		if user.Scope != "" && !contains(validScopes, user.Scope) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("system.user[%d].scope", i),
				Message: fmt.Sprintf("user scope '%s' must be one of: %v", user.Scope, validScopes),
			})
		}
	}

	return errors
}

// validateSysctl validates sysctl configuration items.
func validateSysctl(items []model.SysctlItem) []ValidationError {
	var errors []ValidationError

	tunables := make(map[string]bool)

	for i, item := range items {
		// Tunable is required and must be unique
		switch {
		case item.Tunable == "":
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: "tunable name is required",
			})
		case tunables[item.Tunable]:
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: fmt.Sprintf("tunable name '%s' must be unique", item.Tunable),
			})
		default:
			tunables[item.Tunable] = true
		}

		// Validate tunable name format (basic validation)
		if item.Tunable != "" && !isValidSysctlName(item.Tunable) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].tunable", i),
				Message: fmt.Sprintf("tunable name '%s' has invalid format", item.Tunable),
			})
		}

		// Value is required
		if item.Value == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("sysctl[%d].value", i),
				Message: "tunable value is required",
			})
		}
	}

	return errors
}

// Helper functions for validation

// contains checks if a slice contains a specific string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isValidHostname validates hostname format.
func isValidHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 {
		return false
	}
	// Basic hostname validation - allows letters, numbers, and hyphens
	matched, err := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`, hostname)
	if err != nil {
		return false
	}
	return matched
}

// isValidTimezone validates timezone format.
func isValidTimezone(timezone string) bool {
	// More restrictive timezone validation - common timezone patterns
	// Allow: America/New_York, Europe/London, Etc/UTC, UTC, GMT+/-offset
	validPatterns := []string{
		`^(America|Europe|Asia|Africa|Australia|Antarctica)/[A-Za-z_]+$`,
		`^Etc/(UTC|GMT[+-]?\d*)$`,
		`^UTC$`,
		`^GMT[+-]?\d*$`,
	}

	for _, pattern := range validPatterns {
		if matched, err := regexp.MatchString(pattern, timezone); err == nil && matched {
			return true
		}
	}
	return false
}

// isValidIP validates IPv4 address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
}

// isValidIPv6 validates IPv6 address.
func isValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// isValidCIDR validates CIDR notation.
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// isValidSysctlName validates sysctl tunable names.
func isValidSysctlName(name string) bool {
	// Basic sysctl name validation - allows dots, letters, numbers, and underscores
	matched, err := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_.]*$`, name)
	if err != nil {
		return false
	}
	return matched && strings.Contains(name, ".")
}
