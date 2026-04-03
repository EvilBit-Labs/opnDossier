package diff

import (
	"fmt"
	"maps"
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

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

// usersEqual reports whether two users are semantically equal by comparing
// their name, description, scope, group, and disabled state.
func usersEqual(a, b common.User) bool {
	return a.Name == b.Name &&
		a.Description == b.Description &&
		a.Scope == b.Scope &&
		a.GroupName == b.GroupName &&
		a.Disabled == b.Disabled
}
