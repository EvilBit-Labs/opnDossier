// Package firewall provides a compliance plugin for firewall-specific security checks.
package firewall

import (
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// defaultUsernames contains factory-default administrative usernames that should
// be renamed or disabled.
var defaultUsernames = []string{"admin", "root"}

// pageAllPrivilege is the OPNsense privilege granting full web GUI access.
const pageAllPrivilege = "page-all"

// checkNonDefaultWebGUIPort checks whether the web GUI uses a non-default port.
// The CommonDevice model does not expose the web GUI port, so this cannot be evaluated.
func (fp *Plugin) checkNonDefaultWebGUIPort(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkManagementInterfaceRestriction checks whether web GUI access is restricted
// to specific management interfaces. The CommonDevice model does not expose the
// web GUI interface binding, so this cannot be evaluated.
func (fp *Plugin) checkManagementInterfaceRestriction(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkTLSVersionMinimum checks whether a minimum TLS version is enforced for
// web GUI access. The CommonDevice model does not expose the TLS version setting,
// so this cannot be evaluated.
func (fp *Plugin) checkTLSVersionMinimum(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkAntiLockoutRuleAwareness checks whether the anti-lockout rule is configured.
// The CommonDevice model does not expose the anti-lockout setting, so this cannot
// be evaluated.
func (fp *Plugin) checkAntiLockoutRuleAwareness(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkSessionTimeout checks whether a session timeout is configured for the
// management interface. The CommonDevice model does not expose session timeout
// settings, so this cannot be evaluated.
func (fp *Plugin) checkSessionTimeout(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkConsoleMenuProtection checks whether the serial/VGA console menu is
// disabled. When disabled, physical access to the console does not grant
// immediate access to the system shell.
func (fp *Plugin) checkConsoleMenuProtection(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.System.DisableConsoleMenu, Known: true}
}

// checkLoginProtection checks whether login brute-force protection is enabled.
// The CommonDevice model does not expose login protection settings, so this
// cannot be evaluated.
func (fp *Plugin) checkLoginProtection(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkDefaultCredentialReset checks that no users with default administrative
// usernames (admin, root) exist in an enabled state.
func (fp *Plugin) checkDefaultCredentialReset(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, user := range device.Users {
		if !user.Disabled && slices.ContainsFunc(defaultUsernames, func(name string) bool {
			return strings.EqualFold(user.Name, name)
		}) {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkUniqueAdministratorAccounts checks that the generic "admin" account is
// not in active use. Organizations should create individual named accounts
// instead of sharing a single admin account.
func (fp *Plugin) checkUniqueAdministratorAccounts(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, user := range device.Users {
		if !user.Disabled && strings.EqualFold(user.Name, "admin") {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkLeastPrivilegeAccess checks that no user or group is granted the
// page-all privilege, which provides unrestricted web GUI access.
func (fp *Plugin) checkLeastPrivilegeAccess(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, group := range device.Groups {
		if slices.Contains(strings.Split(group.Privileges, ","), pageAllPrivilege) {
			return checkResult{Result: false, Known: true}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkCentralizedAuthentication checks whether a centralized authentication
// server (RADIUS, LDAP) is configured. The CommonDevice model does not expose
// auth server configuration, so this cannot be evaluated.
func (fp *Plugin) checkCentralizedAuthentication(_ *common.CommonDevice) checkResult {
	return unknown
}

// checkDisabledUnusedAccounts checks for enabled user accounts that appear to
// be system/default accounts which may no longer be needed. Accounts with
// scope "system" that are still enabled are flagged.
func (fp *Plugin) checkDisabledUnusedAccounts(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: true, Known: true}
	}

	for _, user := range device.Users {
		if !user.Disabled && strings.EqualFold(user.Scope, "system") {
			// System-scope accounts that remain enabled represent potential risk.
			// However, at least the "root" system account is expected to be
			// enabled on most systems, so only flag default admin usernames.
			if slices.ContainsFunc(defaultUsernames, func(name string) bool {
				return strings.EqualFold(user.Name, name)
			}) {
				return checkResult{Result: false, Known: true}
			}
		}
	}

	return checkResult{Result: true, Known: true}
}

// checkGroupBasedPrivileges checks whether privileges are assigned through
// groups rather than directly to individual users. At least one group with
// non-empty privileges indicates group-based access control is in use.
func (fp *Plugin) checkGroupBasedPrivileges(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	for _, group := range device.Groups {
		if group.Privileges != "" {
			return checkResult{Result: true, Known: true}
		}
	}

	return checkResult{Result: false, Known: true}
}
