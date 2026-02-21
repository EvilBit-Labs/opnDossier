package common

// IDSConfig contains intrusion detection/prevention (Suricata) configuration.
type IDSConfig struct {
	// Enabled indicates whether the IDS/IPS engine is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// IPSMode indicates inline IPS (prevention) mode is active rather than passive IDS.
	IPSMode bool `json:"ipsMode,omitempty" yaml:"ipsMode,omitempty"`
	// Promiscuous enables promiscuous mode on monitored interfaces.
	Promiscuous bool `json:"promiscuous,omitempty" yaml:"promiscuous,omitempty"`
	// Interfaces lists the interface names being monitored.
	Interfaces []string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	// HomeNetworks contains CIDR ranges defining the protected network.
	HomeNetworks []string `json:"homeNetworks,omitempty" yaml:"homeNetworks,omitempty"`
	// Detect contains detection profile settings.
	Detect IDSDetect `json:"detect" yaml:"detect,omitempty"`
	// MPMAlgo is the multi-pattern matching algorithm (e.g., "auto", "hs", "ac").
	MPMAlgo string `json:"mpmAlgo,omitempty" yaml:"mpmAlgo,omitempty"`
	// DefaultPacketSize is the default packet size for stream reassembly.
	DefaultPacketSize string `json:"defaultPacketSize,omitempty" yaml:"defaultPacketSize,omitempty"`
	// SyslogEnabled enables logging to syslog.
	SyslogEnabled bool `json:"syslogEnabled,omitempty" yaml:"syslogEnabled,omitempty"`
	// SyslogEveEnabled enables EVE JSON logging to syslog.
	SyslogEveEnabled bool `json:"syslogEveEnabled,omitempty" yaml:"syslogEveEnabled,omitempty"`
	// LogPayload enables logging of packet payload data.
	LogPayload string `json:"logPayload,omitempty" yaml:"logPayload,omitempty"`
	// Verbosity is the engine logging verbosity level.
	Verbosity string `json:"verbosity,omitempty" yaml:"verbosity,omitempty"`
	// AlertLogrotate is the number of alert log files to keep.
	AlertLogrotate string `json:"alertLogrotate,omitempty" yaml:"alertLogrotate,omitempty"`
	// AlertSaveLogs is the number of days to retain alert logs.
	AlertSaveLogs string `json:"alertSaveLogs,omitempty" yaml:"alertSaveLogs,omitempty"`
	// UpdateCron is the cron expression for automatic rule updates.
	UpdateCron string `json:"updateCron,omitempty" yaml:"updateCron,omitempty"`
}

// IDSDetect contains IDS detection profile settings.
type IDSDetect struct {
	// Profile is the detection profile (e.g., "medium", "high", "custom").
	Profile string `json:"profile,omitempty" yaml:"profile,omitempty"`
	// ToclientGroups contains rule groups applied to client-bound traffic.
	ToclientGroups string `json:"toclientGroups,omitempty" yaml:"toclientGroups,omitempty"`
	// ToserverGroups contains rule groups applied to server-bound traffic.
	ToserverGroups string `json:"toserverGroups,omitempty" yaml:"toserverGroups,omitempty"`
}
