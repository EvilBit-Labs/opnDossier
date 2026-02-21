package common

// System contains system-level configuration settings.
type System struct {
	// Hostname is the device hostname.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Domain is the DNS domain name for the device.
	Domain string `json:"domain,omitempty" yaml:"domain,omitempty"`
	// Optimization is the TCP/IP stack optimization profile (e.g., "normal", "conservative").
	Optimization string `json:"optimization,omitempty" yaml:"optimization,omitempty"`
	// Language is the web GUI language code.
	Language string `json:"language,omitempty" yaml:"language,omitempty"`
	// Timezone is the system timezone in Region/City format.
	Timezone string `json:"timezone,omitempty" yaml:"timezone,omitempty"`
	// TimeServers contains configured NTP server addresses.
	TimeServers []string `json:"timeServers,omitempty" yaml:"timeServers,omitempty"`
	// DNSServers contains configured DNS resolver addresses.
	DNSServers []string `json:"dnsServers,omitempty" yaml:"dnsServers,omitempty"`

	// DNSAllowOverride indicates whether DHCP/PPP clients may override DNS settings.
	DNSAllowOverride bool `json:"dnsAllowOverride,omitempty" yaml:"dnsAllowOverride,omitempty"`

	// WebGUI contains web GUI access configuration.
	WebGUI WebGUI `json:"webGui" yaml:"webGui,omitempty"`
	// SSH contains SSH service configuration.
	SSH SSH `json:"ssh" yaml:"ssh,omitempty"`
	// Firmware contains firmware version and update settings.
	Firmware Firmware `json:"firmware" yaml:"firmware,omitempty"`

	// NextUID is the next available user ID for account creation.
	NextUID int `json:"nextUid,omitempty" yaml:"nextUid,omitempty"`
	// NextGID is the next available group ID for group creation.
	NextGID int `json:"nextGid,omitempty" yaml:"nextGid,omitempty"`

	// DisableNATReflection disables NAT reflection (hairpin NAT).
	DisableNATReflection bool `json:"disableNatReflection,omitempty" yaml:"disableNatReflection,omitempty"`
	// DisableConsoleMenu disables the serial/VGA console menu.
	DisableConsoleMenu bool `json:"disableConsoleMenu,omitempty" yaml:"disableConsoleMenu,omitempty"`
	// DisableVLANHWFilter disables VLAN hardware filtering.
	DisableVLANHWFilter bool `json:"disableVlanHwFilter,omitempty" yaml:"disableVlanHwFilter,omitempty"`
	// DisableChecksumOffloading disables hardware checksum offloading.
	DisableChecksumOffloading bool `json:"disableChecksumOffloading,omitempty" yaml:"disableChecksumOffloading,omitempty"`
	// DisableSegmentationOffloading disables TCP segmentation offloading.
	DisableSegmentationOffloading bool `json:"disableSegmentationOffloading,omitempty" yaml:"disableSegmentationOffloading,omitempty"`
	// DisableLargeReceiveOffloading disables large receive offloading.
	DisableLargeReceiveOffloading bool `json:"disableLargeReceiveOffloading,omitempty" yaml:"disableLargeReceiveOffloading,omitempty"`
	// IPv6Allow enables IPv6 traffic on the device.
	IPv6Allow bool `json:"ipv6Allow,omitempty" yaml:"ipv6Allow,omitempty"`

	// PowerdACMode is the power management mode when on AC power.
	PowerdACMode string `json:"powerdAcMode,omitempty" yaml:"powerdAcMode,omitempty"`
	// PowerdBatteryMode is the power management mode when on battery.
	PowerdBatteryMode string `json:"powerdBatteryMode,omitempty" yaml:"powerdBatteryMode,omitempty"`
	// PowerdNormalMode is the default power management mode.
	PowerdNormalMode string `json:"powerdNormalMode,omitempty" yaml:"powerdNormalMode,omitempty"`

	// PfShareForward enables pf share-forward optimization.
	PfShareForward bool `json:"pfShareForward,omitempty" yaml:"pfShareForward,omitempty"`
	// LbUseSticky enables sticky connections for load balancing.
	LbUseSticky bool `json:"lbUseSticky,omitempty" yaml:"lbUseSticky,omitempty"`
	// RrdBackup enables RRD data backup on shutdown.
	RrdBackup bool `json:"rrdBackup,omitempty" yaml:"rrdBackup,omitempty"`
	// NetflowBackup enables NetFlow data backup on shutdown.
	NetflowBackup bool `json:"netflowBackup,omitempty" yaml:"netflowBackup,omitempty"`

	// Bogons contains bogon network update configuration.
	Bogons Bogons `json:"bogons" yaml:"bogons,omitempty"`

	// Notes contains operator notes associated with the system.
	Notes []string `json:"notes,omitempty" yaml:"notes,omitempty"`

	// UseVirtualTerminal enables the virtual terminal.
	UseVirtualTerminal bool `json:"useVirtualTerminal,omitempty" yaml:"useVirtualTerminal,omitempty"`
	// DNSSearchDomain is the DNS search domain suffix.
	DNSSearchDomain string `json:"dnsSearchDomain,omitempty" yaml:"dnsSearchDomain,omitempty"`
}

// WebGUI contains web GUI configuration.
type WebGUI struct {
	// Protocol is the web GUI protocol (http or https).
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// SSLCertRef is the reference ID of the SSL certificate used by the web GUI.
	SSLCertRef string `json:"sslCertRef,omitempty" yaml:"sslCertRef,omitempty"`
	// LoginAutocomplete enables browser autocomplete on the login form.
	LoginAutocomplete bool `json:"loginAutocomplete,omitempty" yaml:"loginAutocomplete,omitempty"`
	// MaxProcesses is the maximum number of web server processes.
	MaxProcesses string `json:"maxProcesses,omitempty" yaml:"maxProcesses,omitempty"`
}

// SSH contains SSH service configuration.
type SSH struct {
	// Group is the system group allowed SSH access.
	Group string `json:"group,omitempty" yaml:"group,omitempty"`
	// Enabled indicates whether the SSH service is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Port is the TCP port the SSH daemon listens on.
	Port string `json:"port,omitempty" yaml:"port,omitempty"`
	// AuthenticationMethod is the SSH authentication method (e.g., "publickey").
	AuthenticationMethod string `json:"authenticationMethod,omitempty" yaml:"authenticationMethod,omitempty"`
}

// Firmware contains firmware and update configuration.
type Firmware struct {
	// Version is the firmware version string.
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	// Mirror is the firmware update mirror URL.
	Mirror string `json:"mirror,omitempty" yaml:"mirror,omitempty"`
	// Flavour is the firmware flavour (e.g., "OpenSSL", "LibreSSL").
	Flavour string `json:"flavour,omitempty" yaml:"flavour,omitempty"`
	// Plugins is a comma-separated list of installed firmware plugins.
	Plugins string `json:"plugins,omitempty" yaml:"plugins,omitempty"`
}

// Bogons contains bogon update configuration.
type Bogons struct {
	// Interval is the bogon list update frequency (e.g., "monthly", "weekly").
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`
}

// SysctlItem represents a single sysctl tunable.
type SysctlItem struct {
	// Tunable is the sysctl parameter name (e.g., "net.inet.tcp.recvspace").
	Tunable string `json:"tunable,omitempty" yaml:"tunable,omitempty"`
	// Value is the configured value for the tunable.
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
	// Description is a human-readable description of the tunable.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}
