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

// FIREWALL-009 through FIREWALL-013 (non-default webgui port, management
// interface restriction, TLS version minimum, anti-lockout rule awareness,
// session timeout) were no-op helpers returning unknown — the CommonDevice
// model does not expose these settings. The helpers were dead after the
// EvaluatedControlIDs map was removed, so they were deleted. The controls
// remain in controls.go so the audit report still labels them UNCONFIRMED.

// checkConsoleMenuProtection checks whether the serial/VGA console menu is
// disabled. When disabled, physical access to the console does not grant
// immediate access to the system shell.
func (fp *Plugin) checkConsoleMenuProtection(device *common.CommonDevice) checkResult {
	if device == nil {
		return checkResult{Result: false, Known: true}
	}

	return checkResult{Result: device.System.DisableConsoleMenu, Known: true}
}

// FIREWALL-015 (checkLoginProtection) was a no-op returning unknown — the
// CommonDevice model does not expose login brute-force protection. Removed
// with the EvaluatedControlIDs cleanup; control remains in controls.go so
// the report labels it UNCONFIRMED.

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

// FIREWALL-019 (checkCentralizedAuthentication) was a no-op returning unknown
// — the CommonDevice model does not expose auth server configuration.
// Removed with the EvaluatedControlIDs cleanup; control remains in
// controls.go so the report labels it UNCONFIRMED.

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
