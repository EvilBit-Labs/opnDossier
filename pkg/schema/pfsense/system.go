// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// System contains the pfSense system configuration.
// It mirrors the OPNsense System struct but with pfSense-specific differences:
// multiple DNS servers, bcrypt-hash user passwords, and additional system fields.
type System struct {
	Optimization                  string             `xml:"optimization"                         json:"optimization,omitempty"                  yaml:"optimization,omitempty"`
	Hostname                      string             `xml:"hostname"                             json:"hostname"                                yaml:"hostname"`
	Domain                        string             `xml:"domain"                               json:"domain"                                  yaml:"domain"`
	DNSAllowOverride              int                `xml:"dnsallowoverride"                     json:"dnsAllowOverride,omitempty"              yaml:"dnsAllowOverride,omitempty"`
	DNSServers                    []string           `xml:"dnsserver"                            json:"dnsServers,omitempty"                    yaml:"dnsServers,omitempty"`
	DNS1GW                        string             `xml:"dns1gw,omitempty"                     json:"dns1gw,omitempty"                        yaml:"dns1gw,omitempty"`
	DNS2GW                        string             `xml:"dns2gw,omitempty"                     json:"dns2gw,omitempty"                        yaml:"dns2gw,omitempty"`
	Language                      string             `xml:"language"                             json:"language,omitempty"                      yaml:"language,omitempty"`
	Group                         []Group            `xml:"group"                                json:"groups,omitempty"                        yaml:"groups,omitempty"`
	User                          []User             `xml:"user"                                 json:"users,omitempty"                         yaml:"users,omitempty"`
	WebGUI                        WebGUI             `xml:"webgui"                               json:"webgui"                                  yaml:"webgui,omitempty"`
	SSH                           opnsense.SSHConfig `xml:"ssh"                                  json:"ssh"                                     yaml:"ssh,omitempty"`
	Timezone                      string             `xml:"timezone"                             json:"timezone,omitempty"                      yaml:"timezone,omitempty"`
	TimeServers                   string             `xml:"timeservers"                          json:"timeServers,omitempty"                   yaml:"timeServers,omitempty"`
	DisableNATReflection          string             `xml:"disablenatreflection"                 json:"disableNatReflection,omitempty"          yaml:"disableNatReflection,omitempty"`
	DisableSegmentationOffloading int                `xml:"disablesegmentationoffloading"        json:"disableSegmentationOffloading,omitempty" yaml:"disableSegmentationOffloading,omitempty"`
	DisableLargeReceiveOffloading int                `xml:"disablelargereceiveoffloading"        json:"disableLargeReceiveOffloading,omitempty" yaml:"disableLargeReceiveOffloading,omitempty"`
	IPv6Allow                     string             `xml:"ipv6allow"                            json:"ipv6Allow,omitempty"                     yaml:"ipv6Allow,omitempty"`
	MaximumTableEntries           string             `xml:"maximumtableentries,omitempty"        json:"maximumTableEntries,omitempty"           yaml:"maximumTableEntries,omitempty"`
	CryptoHardware                string             `xml:"crypto_hardware,omitempty"            json:"cryptoHardware,omitempty"                yaml:"cryptoHardware,omitempty"`
	EnableSerial                  opnsense.BoolFlag  `xml:"enableserial,omitempty"               json:"enableSerial"                            yaml:"enableSerial,omitempty"`
	AlreadyRunConfigUpgrade       opnsense.BoolFlag  `xml:"already_run_config_upgrade,omitempty" json:"alreadyRunConfigUpgrade"                 yaml:"alreadyRunConfigUpgrade,omitempty"`
	NextUID                       int                `xml:"nextuid"                              json:"nextUid,omitempty"                       yaml:"nextUid,omitempty"`
	NextGID                       int                `xml:"nextgid"                              json:"nextGid,omitempty"                       yaml:"nextGid,omitempty"`
	PowerdACMode                  string             `xml:"powerd_ac_mode"                       json:"powerdAcMode,omitempty"                  yaml:"powerdAcMode,omitempty"`
	PowerdBatteryMode             string             `xml:"powerd_battery_mode"                  json:"powerdBatteryMode,omitempty"             yaml:"powerdBatteryMode,omitempty"`
	PowerdNormalMode              string             `xml:"powerd_normal_mode"                   json:"powerdNormalMode,omitempty"              yaml:"powerdNormalMode,omitempty"`
	Bogons                        struct {
		Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty"`
	} `xml:"bogons"                               json:"bogons"                                  yaml:"bogons,omitempty"`
}

// Group represents a pfSense group.
// Forked from opnsense.Group because pfSense supports multiple <priv> elements
// per group (copy-on-write per AGENTS.md §6.1).
type Group struct {
	Name        string   `xml:"name"        json:"name"                  yaml:"name"`
	Description string   `xml:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Scope       string   `xml:"scope"       json:"scope"                 yaml:"scope"`
	Gid         string   `xml:"gid"         json:"gid"                   yaml:"gid"` //nolint:staticcheck // Field name matches pfSense schema
	Member      string   `xml:"member"      json:"member,omitempty"      yaml:"member,omitempty"`
	Priv        []string `xml:"priv"        json:"privileges,omitempty"  yaml:"privileges,omitempty"`
}

// NewSystem returns a System with all slice fields initialized for safe use.
func NewSystem() System {
	return System{
		Group:      make([]Group, 0),
		User:       make([]User, 0),
		DNSServers: make([]string, 0),
	}
}

// User represents a pfSense user.
// The critical difference from OPNsense is the use of bcrypt-hash instead of password,
// and user-level privileges via the Priv field.
type User struct {
	Name           string            `xml:"name"           json:"name"                     yaml:"name"`
	Disabled       opnsense.BoolFlag `xml:"disabled"       json:"disabled"                 yaml:"disabled"`
	Descr          string            `xml:"descr"          json:"description,omitempty"    yaml:"description,omitempty"`
	Scope          string            `xml:"scope"          json:"scope"                    yaml:"scope"`
	Groupname      string            `xml:"groupname"      json:"groupname"                yaml:"groupname"`
	BcryptHash     string            `xml:"bcrypt-hash"    json:"bcryptHash"               yaml:"bcryptHash"`
	UID            string            `xml:"uid"            json:"uid"                      yaml:"uid"`
	Priv           []string          `xml:"priv,omitempty" json:"priv,omitempty"           yaml:"priv,omitempty"`
	Expires        string            `xml:"expires"        json:"expires,omitempty"        yaml:"expires,omitempty"`
	AuthorizedKeys string            `xml:"authorizedkeys" json:"authorizedKeys,omitempty" yaml:"authorizedKeys,omitempty"`
}

// NewUser returns a User with zero-value defaults.
func NewUser() User {
	return User{}
}

// WebGUI represents the pfSense WebGUI configuration.
// It extends the OPNsense WebGUIConfig with pfSense-specific fields
// such as dashboard columns, CSS theme, login CSS, and alternate hostnames.
type WebGUI struct {
	Protocol          string            `xml:"protocol"                    json:"protocol"                   yaml:"protocol"`
	SSLCertRef        string            `xml:"ssl-certref,omitempty"       json:"sslCertRef,omitempty"       yaml:"sslCertRef,omitempty"`
	LoginAutocomplete opnsense.BoolFlag `xml:"loginautocomplete,omitempty" json:"loginAutocomplete"          yaml:"loginAutocomplete,omitempty"`
	MaxProcesses      string            `xml:"max_procs,omitempty"         json:"maxProcesses,omitempty"     yaml:"maxProcesses,omitempty"`
	DashboardColumns  string            `xml:"dashboardcolumns,omitempty"  json:"dashboardColumns,omitempty" yaml:"dashboardColumns,omitempty"`
	WebGUICSS         string            `xml:"webguicss,omitempty"         json:"webguiCss,omitempty"        yaml:"webguiCss,omitempty"`
	LoginCSS          string            `xml:"logincss,omitempty"          json:"loginCss,omitempty"         yaml:"loginCss,omitempty"`
	AltHostnames      string            `xml:"althostnames,omitempty"      json:"altHostnames,omitempty"     yaml:"altHostnames,omitempty"`
}
