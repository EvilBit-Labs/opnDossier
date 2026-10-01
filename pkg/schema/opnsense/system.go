package opnsense

import "encoding/xml"

// WebGUIConfig represents the web management interface configuration, including
// protocol (HTTP/HTTPS), SSL certificate reference, login autocomplete, and process limits.
type WebGUIConfig struct {
	Protocol string `xml:"protocol" json:"protocol" yaml:"protocol" validate:"required,oneof=http https"`
	// Port is the custom WebGUI listening port, if configured. Empty means the
	// protocol default (80 for http, 443 for https) applies.
	Port              string   `xml:"port,omitempty"              json:"port,omitempty"         yaml:"port,omitempty"`
	SSLCertRef        string   `xml:"ssl-certref,omitempty"       json:"sslCertRef,omitempty"   yaml:"sslCertRef,omitempty"`
	LoginAutocomplete BoolFlag `xml:"loginautocomplete,omitempty" json:"loginAutocomplete"      yaml:"loginAutocomplete,omitempty"`
	MaxProcesses      string   `xml:"max_procs,omitempty"         json:"maxProcesses,omitempty" yaml:"maxProcesses,omitempty"`
}

// SSHConfig represents the SSH daemon configuration, including whether it is enabled,
// the listening port, and the permitted login group.
type SSHConfig struct {
	Enabled BoolFlag `xml:"enabled,omitempty" json:"enabled"        yaml:"enabled,omitempty"`
	Port    string   `xml:"port,omitempty"    json:"port,omitempty" yaml:"port,omitempty"`
	Group   string   `xml:"group"             json:"group"          yaml:"group"             validate:"required"`
}

// SystemConfig groups system-related configuration, combining the core [System] settings
// with kernel tunables ([SysctlItem] entries).
type SystemConfig struct {
	System System      `json:"system"           yaml:"system,omitempty" validate:"required"`
	Sysctl SysctlItems `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
}

// SysctlItem represents a single kernel tunable (sysctl) entry with its name, value, and description.
// This supports both the simple format (direct elements) and nested item format used in OPNsense XML.
type SysctlItem struct {
	Descr   string `xml:"descr"         json:"description,omitempty" yaml:"description,omitempty"`
	Tunable string `xml:"tunable"       json:"tunable"               yaml:"tunable"               validate:"required"`
	Value   string `xml:"value"         json:"value"                 yaml:"value"                 validate:"required"`
	Key     string `xml:"key,omitempty" json:"key,omitempty"         yaml:"key,omitempty"`

	Secret string `xml:"secret,omitempty" json:"secret,omitempty" yaml:"secret,omitempty"`
}

// SysctlItems is the list of kernel tunables held under <sysctl>.
//
// It exists because the vendor shape and the Go shape disagree. OPNsense
// writes ONE <sysctl> container holding repeated <item> children:
//
//	<sysctl>
//	  <item><descr/><tunable/><value/></item>
//	  <item>...</item>
//	</sysctl>
//
// Binding a plain []SysctlItem to xml:"sysctl" tells encoding/xml to expect
// <sysctl> itself to repeat, so every tunable in the file collapsed into a
// single entry with empty Tunable and Value -- silently, because a config
// with no tunables and a config with two hundred decoded to the same thing.
// Decoding the container explicitly is what restores them.
//
// Older configs wrote the fields directly under <sysctl> (the "simple
// format" [SysctlItem] documents), so both shapes are accepted.
type SysctlItems []SysctlItem

// UnmarshalXML decodes one <sysctl> container into zero or more tunables.
//
// It appends rather than assigns: encoding/xml calls this once per <sysctl>
// element it encounters, and a config carrying more than one container must
// accumulate across the calls instead of keeping only the last.
func (s *SysctlItems) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// The anonymous struct captures both layouts in a single pass: Items
	// takes the <item> children, the remaining fields take a tunable
	// written directly under <sysctl>. Only one of the two is populated by
	// any given container.
	var container struct {
		Items   []SysctlItem `xml:"item"`
		Descr   string       `xml:"descr"`
		Tunable string       `xml:"tunable"`
		Value   string       `xml:"value"`
		Key     string       `xml:"key"`
		Secret  string       `xml:"secret"`
	}
	if err := d.DecodeElement(&container, &start); err != nil {
		return err
	}

	for i := range container.Items {
		if container.Items[i].IsPlaceholder() {
			continue
		}
		*s = append(*s, container.Items[i])
	}

	// Keep a directly-written tunable only when it carries content, by the
	// same predicate the <item> children go through above. An
	// OPNsense-shaped container leaves these fields empty, so appending
	// unconditionally would put a blank entry after every real one.
	direct := SysctlItem{
		Descr:   container.Descr,
		Tunable: container.Tunable,
		Value:   container.Value,
		Key:     container.Key,
		Secret:  container.Secret,
	}
	if !direct.IsPlaceholder() {
		*s = append(*s, direct)
	}

	return nil
}

// IsPlaceholder reports whether the entry carries no configuration at all.
//
// The DTD's content model for <item> makes every child optional --
// "<!ELEMENT item (((number,type)|(descr,tunable))?,(value|(key,secret))?)>" --
// so a bare <item/> is valid and unmarshals into an entry whose fields are all
// zero. Appending it would report a tunable that is not configured, the same
// phantom-entry problem GOTCHAS.md section 3.4 describes for the EMPTY-declared
// elements. No shipped fixture contains one; the guard is here because the
// schema permits it, not because a fixture forced it.
//
// Conservative by the same rule as the section 3.4 predicates: an entry is
// dropped only when every configuration field is zero, so one carrying just a
// description survives.
func (s SysctlItem) IsPlaceholder() bool {
	return s.Descr == "" &&
		s.Tunable == "" &&
		s.Value == "" &&
		s.Key == "" &&
		s.Secret == ""
}

// MarshalXML writes the tunables back in the container shape they were read
// from: one <sysctl> element holding a repeated <item> per tunable.
//
// Without this, the default encoder would emit one <sysctl> per tunable with
// the fields as direct children -- the legacy flat shape. That still decodes,
// because UnmarshalXML accepts both, so the values survive a round trip; but
// the document would no longer match what the vendor writes, and every other
// custom container in this package (Dhcpd, Interfaces, InterfaceList) pairs
// its unmarshaler with a marshaler for exactly that reason.
func (s SysctlItems) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(s) == 0 {
		return nil
	}

	if err := e.EncodeToken(start); err != nil {
		return err
	}

	itemStart := xml.StartElement{Name: xml.Name{Local: "item"}}
	for i := range s {
		if err := e.EncodeElement(s[i], itemStart); err != nil {
			return err
		}
	}

	return e.EncodeToken(xml.EndElement{Name: start.Name})
}

// System contains the core system configuration including hostname, domain, DNS, users, groups,
// web GUI settings, SSH access, firmware, power management, and hardware offloading options.
type System struct {
	Optimization                  string       `xml:"optimization"                  json:"optimization,omitempty"                  yaml:"optimization,omitempty"                  validate:"omitempty,oneof=normal high-latency conservative aggressive"`
	Hostname                      string       `xml:"hostname"                      json:"hostname"                                yaml:"hostname"                                validate:"required,hostname"`
	Domain                        string       `xml:"domain"                        json:"domain"                                  yaml:"domain"                                  validate:"required,fqdn"`
	DNSAllowOverride              BoolFlag     `xml:"dnsallowoverride"              json:"dnsAllowOverride,omitempty"              yaml:"dnsAllowOverride,omitempty"`
	DNSServers                    []string     `xml:"dnsserver"                     json:"dnsServers,omitempty"                    yaml:"dnsServers,omitempty"`
	Language                      string       `xml:"language"                      json:"language,omitempty"                      yaml:"language,omitempty"`
	Firmware                      Firmware     `xml:"firmware"                      json:"firmware"                                yaml:"firmware,omitempty"`
	Group                         []Group      `xml:"group"                         json:"groups,omitempty"                        yaml:"groups,omitempty"                        validate:"dive"`
	User                          []User       `xml:"user"                          json:"users,omitempty"                         yaml:"users,omitempty"                         validate:"dive"`
	WebGUI                        WebGUIConfig `xml:"webgui"                        json:"webgui"                                  yaml:"webgui,omitempty"`
	SSH                           SSHConfig    `xml:"ssh"                           json:"ssh"                                     yaml:"ssh,omitempty"`
	Timezone                      string       `xml:"timezone"                      json:"timezone,omitempty"                      yaml:"timezone,omitempty"`
	TimeServers                   string       `xml:"timeservers"                   json:"timeServers,omitempty"                   yaml:"timeServers,omitempty"`
	UseVirtualTerminal            BoolFlag     `xml:"usevirtualterminal"            json:"useVirtualTerminal,omitempty"            yaml:"useVirtualTerminal,omitempty"`
	DisableVLANHWFilter           BoolFlag     `xml:"disablevlanhwfilter"           json:"disableVlanHwFilter,omitempty"           yaml:"disableVlanHwFilter,omitempty"`
	DisableChecksumOffloading     BoolFlag     `xml:"disablechecksumoffloading"     json:"disableChecksumOffloading,omitempty"     yaml:"disableChecksumOffloading,omitempty"`
	DisableSegmentationOffloading BoolFlag     `xml:"disablesegmentationoffloading" json:"disableSegmentationOffloading,omitempty" yaml:"disableSegmentationOffloading,omitempty"`
	DisableLargeReceiveOffloading BoolFlag     `xml:"disablelargereceiveoffloading" json:"disableLargeReceiveOffloading,omitempty" yaml:"disableLargeReceiveOffloading,omitempty"`
	IPv6Allow                     BoolFlag     `xml:"ipv6allow"                     json:"ipv6Allow,omitempty"                     yaml:"ipv6Allow,omitempty"`
	DisableNATReflection          string       `xml:"disablenatreflection"          json:"disableNatReflection,omitempty"          yaml:"disableNatReflection,omitempty"`
	DisableConsoleMenu            BoolFlag     `xml:"disableconsolemenu"            json:"disableConsoleMenu"                      yaml:"disableConsoleMenu,omitempty"`
	NextUID                       int          `xml:"nextuid"                       json:"nextUid,omitempty"                       yaml:"nextUid,omitempty"`
	NextGID                       int          `xml:"nextgid"                       json:"nextGid,omitempty"                       yaml:"nextGid,omitempty"`
	PowerdACMode                  string       `xml:"powerd_ac_mode"                json:"powerdAcMode,omitempty"                  yaml:"powerdAcMode,omitempty"                  validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	PowerdBatteryMode             string       `xml:"powerd_battery_mode"           json:"powerdBatteryMode,omitempty"             yaml:"powerdBatteryMode,omitempty"             validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	PowerdNormalMode              string       `xml:"powerd_normal_mode"            json:"powerdNormalMode,omitempty"              yaml:"powerdNormalMode,omitempty"              validate:"omitempty,oneof=hadp hiadp adaptive minimum maximum"`
	Bogons                        struct {
		Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty" validate:"omitempty,oneof=monthly weekly daily never"`
	} `xml:"bogons"                        json:"bogons"                                  yaml:"bogons,omitempty"`
	PfShareForward BoolFlag `xml:"pf_share_forward"              json:"pfShareForward,omitempty"                yaml:"pfShareForward,omitempty"`
	LbUseSticky    BoolFlag `xml:"lb_use_sticky"                 json:"lbUseSticky,omitempty"                   yaml:"lbUseSticky,omitempty"`
	RrdBackup      BoolFlag `xml:"rrdbackup"                     json:"rrdBackup,omitempty"                     yaml:"rrdBackup,omitempty"`
	NetflowBackup  BoolFlag `xml:"netflowbackup"                 json:"netflowBackup,omitempty"                 yaml:"netflowBackup,omitempty"`

	// Missing service configurations
	NTPD struct {
		Prefer string `xml:"prefer" json:"prefer,omitempty" yaml:"prefer,omitempty"`
	} `xml:"ntpd"          json:"ntpd"         yaml:"ntpd,omitempty"`
	SNMPD struct {
		SysLocation string `xml:"syslocation"`
		SysContact  string `xml:"syscontact"`
		ROCommunity string `xml:"rocommunity"`
	} `xml:"snmpd"         json:"snmpd"        yaml:"snmpd,omitempty"`
	RRD struct {
		Enable BoolFlag `xml:"enable"`
	} `xml:"rrd"           json:"rrd"          yaml:"rrd,omitempty"`
	LoadBalancer struct {
		MonitorType []MonitorType `xml:"monitor_type"`
	} `xml:"load_balancer" json:"loadBalancer" yaml:"loadBalancer,omitempty"`
	Unbound Unbound `xml:"unbound"       json:"unbound"      yaml:"unbound,omitempty"`

	// System notes for additional configuration information
	Notes []string `xml:"notes>note" json:"notes,omitempty" yaml:"notes,omitempty"`
}

// Widgets represents the OPNsense dashboard widgets layout configuration,
// including the widget display sequence and column count.
type Widgets struct {
	Sequence    string `xml:"sequence"     json:"sequence,omitempty"    yaml:"sequence,omitempty"`
	ColumnCount string `xml:"column_count" json:"columnCount,omitempty" yaml:"columnCount,omitempty"`
}

// Group represents a user group with a name, GID, scope (system or local), member list,
// and assigned privileges.
type Group struct {
	Name        string   `xml:"name"        json:"name"                  yaml:"name"                  validate:"required,alphanum"`
	Description string   `xml:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Scope       string   `xml:"scope"       json:"scope"                 yaml:"scope"                 validate:"required,oneof=system local"`
	Gid         string   `xml:"gid"         json:"gid"                   yaml:"gid"                   validate:"required,numeric"` //nolint:staticcheck // Field name matches OPNsense schema
	Member      []string `xml:"member"      json:"member,omitempty"      yaml:"member,omitempty"`
	Priv        []string `xml:"priv"        json:"privileges,omitempty"  yaml:"privileges,omitempty"`
}

// Firmware represents the OPNsense firmware configuration, including the update mirror,
// flavour, installed plugins, and subscription/reboot flags.
type Firmware struct {
	Version      string   `xml:"version,attr"           json:"version,omitempty" yaml:"version,omitempty"`
	Mirror       string   `xml:"mirror"                 json:"mirror,omitempty"  yaml:"mirror,omitempty"`
	Flavour      string   `xml:"flavour"                json:"flavour,omitempty" yaml:"flavour,omitempty"`
	Plugins      string   `xml:"plugins"                json:"plugins,omitempty" yaml:"plugins,omitempty"`
	Type         BoolFlag `xml:"type,omitempty"         json:"type"              yaml:"type,omitempty"`
	Subscription BoolFlag `xml:"subscription,omitempty" json:"subscription"      yaml:"subscription,omitempty"`
	Reboot       BoolFlag `xml:"reboot,omitempty"       json:"reboot"            yaml:"reboot,omitempty"`
}

// User represents a local user account with authentication credentials, group membership,
// UID, scope, API keys, and optional OTP/IPsec PSK/SSH authorized key flags.
type User struct {
	Name      string   `xml:"name"      json:"name"                  yaml:"name"                  validate:"required,alphanum"`
	Disabled  BoolFlag `xml:"disabled"  json:"disabled"              yaml:"disabled"`
	Descr     string   `xml:"descr"     json:"description,omitempty" yaml:"description,omitempty"`
	Scope     string   `xml:"scope"     json:"scope"                 yaml:"scope"                 validate:"required,oneof=system local"`
	Groupname string   `xml:"groupname" json:"groupname"             yaml:"groupname"             validate:"required"`

	Password       string   `xml:"password"       json:"password"             yaml:"password"                 validate:"required"`
	UID            string   `xml:"uid"            json:"uid"                  yaml:"uid"                      validate:"required,numeric"`
	Priv           []string `xml:"priv"           json:"privileges,omitempty" yaml:"privileges,omitempty"`
	APIKeys        []APIKey `xml:"apikeys>item"   json:"apiKeys,omitempty"    yaml:"apiKeys,omitempty"`
	Expires        BoolFlag `xml:"expires"        json:"expires"              yaml:"expires,omitempty"`
	AuthorizedKeys BoolFlag `xml:"authorizedkeys" json:"authorizedKeys"       yaml:"authorizedKeys,omitempty"`
	IPSecPSK       BoolFlag `xml:"ipsecpsk"       json:"ipsecPsk"             yaml:"ipsecPsk,omitempty"`
	OTPSeed        BoolFlag `xml:"otp_seed"       json:"otpSeed"              yaml:"otpSeed,omitempty"`
}

// APIKey represents a user API key pair with its key, secret, associated privileges,
// scope, ownership (UID/GID), and creation/modification timestamps.
type APIKey struct {
	Key string `xml:"key" json:"key" yaml:"key"`

	Secret      string `xml:"secret"               json:"secret"                yaml:"secret"`
	Privileges  string `xml:"privileges,omitempty" json:"privileges,omitempty"  yaml:"privileges,omitempty"`
	Priv        string `xml:"priv,omitempty"       json:"priv,omitempty"        yaml:"priv,omitempty"`
	Scope       string `xml:"scope,omitempty"      json:"scope,omitempty"       yaml:"scope,omitempty"`
	UID         int    `xml:"uid,omitempty"        json:"uid,omitempty"         yaml:"uid,omitempty"`
	GID         int    `xml:"gid,omitempty"        json:"gid,omitempty"         yaml:"gid,omitempty"`
	Description string `xml:"descr,omitempty"      json:"description,omitempty" yaml:"description,omitempty"`
	CTime       int64  `xml:"ctime,omitempty"      json:"ctime,omitempty"       yaml:"ctime,omitempty"`
	MTime       int64  `xml:"mtime,omitempty"      json:"mtime,omitempty"       yaml:"mtime,omitempty"`
	CTimeUSec   int    `xml:"ctime_usec,omitempty" json:"ctimeUsec,omitempty"   yaml:"ctimeUsec,omitempty"`
	MTimeUSec   int    `xml:"mtime_usec,omitempty" json:"mtimeUsec,omitempty"   yaml:"mtimeUsec,omitempty"`
	CTimeNSec   int    `xml:"ctime_nsec,omitempty" json:"ctimeNsec,omitempty"   yaml:"ctimeNsec,omitempty"`
	MTimeNSec   int    `xml:"mtime_nsec,omitempty" json:"mtimeNsec,omitempty"   yaml:"mtimeNsec,omitempty"`
	CTimeSec    int64  `xml:"ctime_sec,omitempty"  json:"ctimeSec,omitempty"    yaml:"ctimeSec,omitempty"`
	MTimeSec    int64  `xml:"mtime_sec,omitempty"  json:"mtimeSec,omitempty"    yaml:"mtimeSec,omitempty"`
}

// Constructor functions for system models

// NewSystemConfig returns a SystemConfig instance with the Sysctl slice initialized as empty.
func NewSystemConfig() SystemConfig {
	return SystemConfig{
		Sysctl: make([]SysctlItem, 0),
	}
}

// NewUser returns a User instance with the APIKeys slice initialized as empty.
func NewUser() User {
	return User{
		APIKeys: make([]APIKey, 0),
	}
}
