// Package model defines the data structures for OPNsense configurations.
package model

// SystemConfig groups system-related configuration.
type SystemConfig struct {
	System System       `json:"system,omitempty" yaml:"system,omitempty" validate:"required"`
	Sysctl []SysctlItem `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
}

// SysctlItem represents a single sysctl item.
// This supports both the simple format (direct elements) and nested item format.
type SysctlItem struct {
	Descr   string `xml:"descr" json:"description,omitempty" yaml:"description,omitempty"`
	Tunable string `xml:"tunable" json:"tunable" yaml:"tunable" validate:"required"`
	Value   string `xml:"value" json:"value" yaml:"value" validate:"required"`
}

// System contains the system configuration.
type System struct {
	Optimization                  string   `xml:"optimization" json:"optimization,omitempty" yaml:"optimization,omitempty" validate:"omitempty,oneof=normal high-latency conservative aggressive"`
	Hostname                      string   `xml:"hostname" json:"hostname" yaml:"hostname" validate:"required,hostname"`
	Domain                        string   `xml:"domain" json:"domain" yaml:"domain" validate:"required,fqdn"`
	DNSAllowOverride              string   `xml:"dnsallowoverride" json:"dnsAllowOverride,omitempty" yaml:"dnsAllowOverride,omitempty"`
	DNSServer                     string   `xml:"dnsserver" json:"dnsServer,omitempty" yaml:"dnsServer,omitempty"`
	Language                      string   `xml:"language" json:"language,omitempty" yaml:"language,omitempty"`
	Firmware                      Firmware `xml:"firmware" json:"firmware,omitempty" yaml:"firmware,omitempty"`
	Group                         []Group  `xml:"group" json:"groups,omitempty" yaml:"groups,omitempty" validate:"dive"`
	User                          []User   `xml:"user" json:"users,omitempty" yaml:"users,omitempty" validate:"dive"`
	NextUID                       string   `xml:"nextuid" json:"nextUid,omitempty" yaml:"nextUid,omitempty" validate:"omitempty,numeric,min=1000"`
	NextGID                       string   `xml:"nextgid" json:"nextGid,omitempty" yaml:"nextGid,omitempty" validate:"omitempty,numeric,min=1000"`
	Timezone                      string   `xml:"timezone" json:"timezone,omitempty" yaml:"timezone,omitempty"`
	Timeservers                   string   `xml:"timeservers" json:"timeservers,omitempty" yaml:"timeservers,omitempty"`
	Webgui                        Webgui   `xml:"webgui" json:"webgui,omitempty" yaml:"webgui,omitempty"`
	DisableNATReflection          string   `xml:"disablenatreflection" json:"disableNatReflection,omitempty" yaml:"disableNatReflection,omitempty"`
	UseVirtualTerminal            string   `xml:"usevirtualterminal" json:"useVirtualTerminal,omitempty" yaml:"useVirtualTerminal,omitempty"`
	DisableConsoleMenu            struct{} `xml:"disableconsolemenu" json:"disableConsoleMenu,omitempty" yaml:"disableConsoleMenu,omitempty"`
	DisableVLANHWFilter           string   `xml:"disablevlanhwfilter" json:"disableVlanHwFilter,omitempty" yaml:"disableVlanHwFilter,omitempty"`
	DisableChecksumOffloading     string   `xml:"disablechecksumoffloading" json:"disableChecksumOffloading,omitempty" yaml:"disableChecksumOffloading,omitempty"`
	DisableSegmentationOffloading string   `xml:"disablesegmentationoffloading" json:"disableSegmentationOffloading,omitempty" yaml:"disableSegmentationOffloading,omitempty"`
	DisableLargeReceiveOffloading string   `xml:"disablelargereceiveoffloading" json:"disableLargeReceiveOffloading,omitempty" yaml:"disableLargeReceiveOffloading,omitempty"`
	IPv6Allow                     struct{} `xml:"ipv6allow" json:"ipv6Allow,omitempty" yaml:"ipv6Allow,omitempty"`
	PowerdAcMode                  string   `xml:"powerd_ac_mode" json:"powerdAcMode,omitempty" yaml:"powerdAcMode,omitempty" validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	PowerdBatteryMode             string   `xml:"powerd_battery_mode" json:"powerdBatteryMode,omitempty" yaml:"powerdBatteryMode,omitempty" validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	PowerdNormalMode              string   `xml:"powerd_normal_mode" json:"powerdNormalMode,omitempty" yaml:"powerdNormalMode,omitempty" validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	Bogons                        Bogons   `xml:"bogons" json:"bogons,omitempty" yaml:"bogons,omitempty"`
	PfShareForward                string   `xml:"pf_share_forward" json:"pfShareForward,omitempty" yaml:"pfShareForward,omitempty"`
	LbUseSticky                   string   `xml:"lb_use_sticky" json:"lbUseSticky,omitempty" yaml:"lbUseSticky,omitempty"`
	SSH                           SSH      `xml:"ssh" json:"ssh,omitempty" yaml:"ssh,omitempty"`
	RrdBackup                     string   `xml:"rrdbackup" json:"rrdBackup,omitempty" yaml:"rrdBackup,omitempty"`
	NetflowBackup                 string   `xml:"netflowbackup" json:"netflowBackup,omitempty" yaml:"netflowBackup,omitempty"`
}

// Group represents a user group.
type Group struct {
	Name        string `xml:"name" json:"name" yaml:"name" validate:"required,alphanum"`
	Description string `xml:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Scope       string `xml:"scope" json:"scope" yaml:"scope" validate:"required,oneof=system local"`
	Gid         string `xml:"gid" json:"gid" yaml:"gid" validate:"required,numeric"`
	Member      string `xml:"member" json:"member,omitempty" yaml:"member,omitempty"`
	Priv        string `xml:"priv" json:"privileges,omitempty" yaml:"privileges,omitempty"`
}

// Firmware represents the firmware configuration.
type Firmware struct {
	Version string `xml:"version,attr" json:"version,omitempty" yaml:"version,omitempty"`
	Mirror  string `xml:"mirror" json:"mirror,omitempty" yaml:"mirror,omitempty"`
	Flavour string `xml:"flavour" json:"flavour,omitempty" yaml:"flavour,omitempty"`
	Plugins string `xml:"plugins" json:"plugins,omitempty" yaml:"plugins,omitempty"`
}

// User represents a user.
type User struct {
	Name           string   `xml:"name" json:"name" yaml:"name" validate:"required,alphanum"`
	Descr          string   `xml:"descr" json:"description,omitempty" yaml:"description,omitempty"`
	Scope          string   `xml:"scope" json:"scope" yaml:"scope" validate:"required,oneof=system local"`
	Groupname      string   `xml:"groupname" json:"groupname" yaml:"groupname" validate:"required"`
	Password       string   `xml:"password" json:"password" yaml:"password" validate:"required"`
	UID            string   `xml:"uid" json:"uid" yaml:"uid" validate:"required,numeric"`
	APIKeys        []APIKey `xml:"apikeys>item" json:"apiKeys,omitempty" yaml:"apiKeys,omitempty"`
	Expires        struct{} `xml:"expires" json:"expires,omitempty" yaml:"expires,omitempty"`
	AuthorizedKeys struct{} `xml:"authorizedkeys" json:"authorizedKeys,omitempty" yaml:"authorizedKeys,omitempty"`
	IPSecPSK       struct{} `xml:"ipsecpsk" json:"ipsecPsk,omitempty" yaml:"ipsecPsk,omitempty"`
	OTPSeed        struct{} `xml:"otp_seed" json:"otpSeed,omitempty" yaml:"otpSeed,omitempty"`
}

// APIKey represents a user API key.
type APIKey struct {
	Key    string `xml:"key" json:"key" yaml:"key"`
	Secret string `xml:"secret" json:"secret" yaml:"secret"`
}

// Webgui contains the web GUI configuration.
type Webgui struct {
	Protocol string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
}

// Bogons contains the bogons configuration.
type Bogons struct {
	Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
}

// SSH contains the SSH configuration.
type SSH struct {
	Group string `xml:"group" json:"group" yaml:"group" validate:"required"`
}

// Widgets contains the dashboard widget configuration.
type Widgets struct {
	Sequence    string `xml:"sequence"`
	ColumnCount string `xml:"column_count"`
}

// Constructor functions for system models

// NewSystemConfig creates a new SystemConfig with properly initialized slices.
func NewSystemConfig() SystemConfig {
	return SystemConfig{
		Sysctl: make([]SysctlItem, 0),
	}
}

// NewUser creates a new User with properly initialized slices.
func NewUser() User {
	return User{
		APIKeys: make([]APIKey, 0),
	}
}
