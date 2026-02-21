package common

// User represents a system user account.
type User struct {
	// Name is the login username.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Disabled indicates the user account is locked.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// Description is a human-readable description of the user.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Scope is the user scope (e.g., "system", "local").
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty"`
	// GroupName is the primary group the user belongs to.
	GroupName string `json:"groupName,omitempty" yaml:"groupName,omitempty"`
	// UID is the numeric user identifier.
	UID string `json:"uid,omitempty" yaml:"uid,omitempty"`
	// APIKeys contains API key credentials associated with the user.
	APIKeys []APIKey `json:"apiKeys,omitempty" yaml:"apiKeys,omitempty"`
}

// Group represents a system group.
type Group struct {
	// Name is the group name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Description is a human-readable description of the group.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Scope is the group scope (e.g., "system", "local").
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty"`
	// GID is the numeric group identifier.
	GID string `json:"gid,omitempty" yaml:"gid,omitempty"`
	// Member is a comma-separated list of user UIDs belonging to this group.
	Member string `json:"member,omitempty" yaml:"member,omitempty"`
	// Privileges is a comma-separated list of privileges assigned to the group.
	Privileges string `json:"privileges,omitempty" yaml:"privileges,omitempty"`
}

// APIKey represents an API key credential.
type APIKey struct {
	// Key is the API key identifier.
	Key string `json:"key,omitempty" yaml:"key,omitempty"`
	// Secret is the API key secret.
	Secret string `json:"secret,omitempty" yaml:"secret,omitempty"`
	// Privileges is a comma-separated list of privileges for this key.
	Privileges string `json:"privileges,omitempty" yaml:"privileges,omitempty"`
	// Scope is the API key scope.
	Scope string `json:"scope,omitempty" yaml:"scope,omitempty"`
	// UID is the numeric user identifier that owns this key.
	UID int `json:"uid,omitempty" yaml:"uid,omitempty"`
	// GID is the numeric group identifier for this key.
	GID int `json:"gid,omitempty" yaml:"gid,omitempty"`
	// Description is a human-readable description of the API key.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}
