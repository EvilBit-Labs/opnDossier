// Package schema defines the data structures for OPNsense configurations.
package schema

// Revision represents configuration revision information.
type Revision struct {
	Username    string `xml:"username,omitempty"    json:"username,omitempty"    yaml:"username,omitempty"`
	Time        string `xml:"time,omitempty"        json:"time,omitempty"        yaml:"time,omitempty"`
	Description string `xml:"description,omitempty" json:"description,omitempty" yaml:"description,omitempty"`
}
