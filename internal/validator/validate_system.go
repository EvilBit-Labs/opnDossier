package validator

import (
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// validateSystem checks the system-level configuration fields for required values and valid formats.
// It returns a slice of ValidationError for any invalid or missing system configuration fields, including hostname, domain, timezone, optimization, web GUI protocol, power management modes, and bogons interval.
func validateSystem(system *schema.System) []ValidationError {
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
	if system.Optimization != "" {
		if _, ok := constants.ValidOptimizationModes[system.Optimization]; !ok {
			errors = append(errors, ValidationError{
				Field: "system.optimization",
				Message: fmt.Sprintf(
					"optimization '%s' must be one of: %v",
					system.Optimization,
					slices.Sorted(maps.Keys(constants.ValidOptimizationModes)),
				),
			})
		}
	}

	// Validate webgui protocol
	validProtocols := []string{"http", "https"}
	if system.WebGUI.Protocol != "" && !contains(validProtocols, system.WebGUI.Protocol) {
		errors = append(errors, ValidationError{
			Field:   "system.webgui.protocol",
			Message: fmt.Sprintf("protocol '%s' must be one of: %v", system.WebGUI.Protocol, validProtocols),
		})
	}

	// Validate power management modes
	validPowerdList := slices.Sorted(maps.Keys(constants.ValidPowerdModes))

	if system.PowerdACMode != "" {
		if _, ok := constants.ValidPowerdModes[system.PowerdACMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_ac_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdACMode, validPowerdList),
			})
		}
	}

	if system.PowerdBatteryMode != "" {
		if _, ok := constants.ValidPowerdModes[system.PowerdBatteryMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_battery_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdBatteryMode, validPowerdList),
			})
		}
	}

	if system.PowerdNormalMode != "" {
		if _, ok := constants.ValidPowerdModes[system.PowerdNormalMode]; !ok {
			errors = append(errors, ValidationError{
				Field:   "system.powerd_normal_mode",
				Message: fmt.Sprintf("power mode '%s' must be one of: %v", system.PowerdNormalMode, validPowerdList),
			})
		}
	}

	// Validate bogons interval
	validBogonsIntervals := []string{"monthly", "weekly", "daily", "never"}
	if system.Bogons.Interval != "" && !contains(validBogonsIntervals, system.Bogons.Interval) {
		errors = append(errors, ValidationError{
			Field: "system.bogons.interval",
			Message: fmt.Sprintf(
				"bogons interval '%s' must be one of: %v",
				system.Bogons.Interval,
				validBogonsIntervals,
			),
		})
	}

	return errors
}

// validateUsersAndGroups checks system users and groups for required fields, uniqueness, valid IDs, valid scopes, and correct group references.
// It returns a slice of ValidationError for any invalid or inconsistent user or group entries.
func validateUsersAndGroups(system *schema.System) []ValidationError {
	var errors []ValidationError

	// Track group names and GIDs to ensure uniqueness
	groupNames := make(map[string]bool)
	groupGIDs := make(map[string]bool)

	errors = append(errors, validateGroups(system.Group, groupNames, groupGIDs)...)
	errors = append(errors, validateUsers(system.User, groupNames)...)

	return errors
}

// validateGroups validates all groups and tracks names and GIDs for uniqueness.
func validateGroups(groups []schema.Group, groupNames, groupGIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	for i, group := range groups {
		errors = append(errors, validateGroupName(group, i, groupNames)...)
		errors = append(errors, validateGroupGID(group, i, groupGIDs)...)
		errors = append(errors, validateGroupScope(group, i)...)
	}

	return errors
}

// validateGroupName validates group name requirements and uniqueness.
func validateGroupName(group schema.Group, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	switch {
	case group.Name == "":
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].name", index),
			Message: "group name is required",
		})
	case groupNames[group.Name]:
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].name", index),
			Message: fmt.Sprintf("group name '%s' must be unique", group.Name),
		})
	default:
		groupNames[group.Name] = true
	}

	return errors
}

// validateGroupGID validates group GID requirements and uniqueness.
func validateGroupGID(group schema.Group, index int, groupGIDs map[string]bool) []ValidationError {
	var errors []ValidationError

	if group.Gid == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: "group GID is required",
		})
		return errors
	}

	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: fmt.Sprintf("GID '%s' must be a positive integer", group.Gid),
		})
		return errors
	}

	if groupGIDs[group.Gid] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].gid", index),
			Message: fmt.Sprintf("group GID '%s' must be unique", group.Gid),
		})
		return errors
	}

	groupGIDs[group.Gid] = true
	return errors
}

// validateGroupScope validates group scope requirements.
func validateGroupScope(group schema.Group, index int) []ValidationError {
	var errors []ValidationError

	if group.Scope == "" {
		return errors
	}

	validScopes := []string{"system", "local"}
	if !contains(validScopes, group.Scope) {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.group[%d].scope", index),
			Message: fmt.Sprintf("group scope '%s' must be one of: %v", group.Scope, validScopes),
		})
	}

	return errors
}

// validateUsers validates all users.
func validateUsers(users []schema.User, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError
	userNames := make(map[string]bool)
	userUIDs := make(map[string]bool)

	for i, user := range users {
		errors = append(errors, validateUserName(user, i, userNames)...)
		errors = append(errors, validateUserUID(user, i, userUIDs)...)
		errors = append(errors, validateUserGroupMembership(user, i, groupNames)...)
		errors = append(errors, validateUserScope(user, i)...)
	}

	return errors
}

// validateUserName validates user name requirements and uniqueness.
func validateUserName(user schema.User, index int, userNames map[string]bool) []ValidationError {
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

// validateUserUID validates user UID requirements and uniqueness.
func validateUserUID(user schema.User, index int, userUIDs map[string]bool) []ValidationError {
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
			Message: fmt.Sprintf("UID '%s' must be a positive integer", user.UID),
		})
		return errors
	}

	if userUIDs[user.UID] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].uid", index),
			Message: fmt.Sprintf("user UID '%s' must be unique", user.UID),
		})
		return errors
	}

	userUIDs[user.UID] = true
	return errors
}

// validateUserGroupMembership validates user group membership.
func validateUserGroupMembership(user schema.User, index int, groupNames map[string]bool) []ValidationError {
	var errors []ValidationError

	if user.Groupname != "" && !groupNames[user.Groupname] {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("system.user[%d].groupname", index),
			Message: fmt.Sprintf("referenced group '%s' does not exist", user.Groupname),
		})
	}

	return errors
}

// validateUserScope validates user scope requirements.
func validateUserScope(user schema.User, index int) []ValidationError {
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

// validateSysctl checks sysctl tunable items for required fields, uniqueness, valid naming format, and presence of values.
// It returns a slice of ValidationError for any missing, duplicate, or improperly formatted tunable names, or missing values.
func validateSysctl(items []schema.SysctlItem) []ValidationError {
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
