package common

// Revision contains configuration revision metadata.
type Revision struct {
	// Username is the user who made the last configuration change.
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	// Time is the timestamp of the last configuration change.
	Time string `json:"time,omitempty" yaml:"time,omitempty"`
	// Description is a human-readable description of the revision.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}
