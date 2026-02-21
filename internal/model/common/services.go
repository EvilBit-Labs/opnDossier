package common

// DHCPScope represents DHCP server configuration for a single interface.
type DHCPScope struct {
	// Interface is the logical interface name this DHCP scope is bound to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// Enabled indicates whether the DHCP server is active on this interface.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Range defines the start and end of the DHCP address pool.
	Range DHCPRange `json:"range" yaml:"range,omitempty"`
	// Gateway is the default gateway advertised to DHCP clients.
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	// DNSServer is the DNS server advertised to DHCP clients.
	DNSServer string `json:"dnsServer,omitempty" yaml:"dnsServer,omitempty"`
	// NTPServer is the NTP server advertised to DHCP clients.
	NTPServer string `json:"ntpServer,omitempty" yaml:"ntpServer,omitempty"`
	// WINSServer is the WINS/NetBIOS name server advertised to DHCP clients.
	WINSServer string `json:"winsServer,omitempty" yaml:"winsServer,omitempty"`
	// StaticLeases contains fixed MAC-to-IP address mappings.
	StaticLeases []DHCPStaticLease `json:"staticLeases,omitempty" yaml:"staticLeases,omitempty"`
	// NumberOptions contains custom DHCP number options.
	NumberOptions []DHCPNumberOption `json:"numberOptions,omitempty" yaml:"numberOptions,omitempty"`

	// Alias and rejection fields.

	// AliasAddress is an additional IP alias for the DHCP server interface.
	AliasAddress string `json:"aliasAddress,omitempty" yaml:"aliasAddress,omitempty"`
	// AliasSubnet is the subnet mask for the alias address.
	AliasSubnet string `json:"aliasSubnet,omitempty" yaml:"aliasSubnet,omitempty"`
	// DHCPRejectFrom is a comma-separated list of MAC addresses to reject.
	DHCPRejectFrom string `json:"dhcpRejectFrom,omitempty" yaml:"dhcpRejectFrom,omitempty"`

	// Advanced DHCPv4 DNS fields.

	// AdvDHCPDNSDomain is the advanced DHCP DNS domain override.
	AdvDHCPDNSDomain string `json:"advDhcpDnsDomain,omitempty" yaml:"advDhcpDnsDomain,omitempty"`
	// AdvDHCPDNSServer1 is the first advanced DHCP DNS server override.
	AdvDHCPDNSServer1 string `json:"advDhcpDnsServer1,omitempty" yaml:"advDhcpDnsServer1,omitempty"`
	// AdvDHCPDNSServer2 is the second advanced DHCP DNS server override.
	AdvDHCPDNSServer2 string `json:"advDhcpDnsServer2,omitempty" yaml:"advDhcpDnsServer2,omitempty"`
	// AdvDHCPDNSServer3 is the third advanced DHCP DNS server override.
	AdvDHCPDNSServer3 string `json:"advDhcpDnsServer3,omitempty" yaml:"advDhcpDnsServer3,omitempty"`
	// AdvDHCPDNSServer4 is the fourth advanced DHCP DNS server override.
	AdvDHCPDNSServer4 string `json:"advDhcpDnsServer4,omitempty" yaml:"advDhcpDnsServer4,omitempty"`
	// AdvDHCPOptionEnabled indicates whether advanced DHCP option overrides are active.
	AdvDHCPOptionEnabled string `json:"advDhcpOptionEnabled,omitempty" yaml:"advDhcpOptionEnabled,omitempty"`
	// AdvDHCPOptionServer is the advanced DHCP option server address.
	AdvDHCPOptionServer string `json:"advDhcpOptionServer,omitempty" yaml:"advDhcpOptionServer,omitempty"`

	// Advanced DHCPv4 protocol timing fields.

	// AdvDHCPPTTimeout is the protocol timeout for DHCP client requests.
	AdvDHCPPTTimeout string `json:"advDhcpPtTimeout,omitempty" yaml:"advDhcpPtTimeout,omitempty"`
	// AdvDHCPPTRetry is the retry interval for DHCP client requests.
	AdvDHCPPTRetry string `json:"advDhcpPtRetry,omitempty" yaml:"advDhcpPtRetry,omitempty"`
	// AdvDHCPPTSelectTimeout is the timeout for selecting a DHCP offer.
	AdvDHCPPTSelectTimeout string `json:"advDhcpPtSelectTimeout,omitempty" yaml:"advDhcpPtSelectTimeout,omitempty"`
	// AdvDHCPPTReboot is the time to wait before rebooting the DHCP client.
	AdvDHCPPTReboot string `json:"advDhcpPtReboot,omitempty" yaml:"advDhcpPtReboot,omitempty"`
	// AdvDHCPPTBackoffCutoff is the maximum backoff time for DHCP retries.
	AdvDHCPPTBackoffCutoff string `json:"advDhcpPtBackoffCutoff,omitempty" yaml:"advDhcpPtBackoffCutoff,omitempty"`
	// AdvDHCPPTInitialInterval is the initial retry interval for DHCP requests.
	AdvDHCPPTInitialInterval string `json:"advDhcpPtInitialInterval,omitempty" yaml:"advDhcpPtInitialInterval,omitempty"`
	// AdvDHCPPTValues contains additional protocol timing values.
	AdvDHCPPTValues string `json:"advDhcpPtValues,omitempty" yaml:"advDhcpPtValues,omitempty"`

	// Advanced DHCPv4 option fields.

	// AdvDHCPSendOptions specifies additional DHCP options to send.
	AdvDHCPSendOptions string `json:"advDhcpSendOptions,omitempty" yaml:"advDhcpSendOptions,omitempty"`
	// AdvDHCPRequestOptions specifies additional DHCP options to request.
	AdvDHCPRequestOptions string `json:"advDhcpRequestOptions,omitempty" yaml:"advDhcpRequestOptions,omitempty"`
	// AdvDHCPRequiredOptions specifies DHCP options that must be present.
	AdvDHCPRequiredOptions string `json:"advDhcpRequiredOptions,omitempty" yaml:"advDhcpRequiredOptions,omitempty"`
	// AdvDHCPOptionModifiers contains DHCP option modifier expressions.
	AdvDHCPOptionModifiers string `json:"advDhcpOptionModifiers,omitempty" yaml:"advDhcpOptionModifiers,omitempty"`

	// Advanced DHCPv4 configuration override fields.

	// AdvDHCPConfigAdvanced contains raw advanced DHCP configuration text.
	AdvDHCPConfigAdvanced string `json:"advDhcpConfigAdvanced,omitempty" yaml:"advDhcpConfigAdvanced,omitempty"`
	// AdvDHCPConfigFileOverride enables overriding the DHCP config file.
	AdvDHCPConfigFileOverride string `json:"advDhcpConfigFileOverride,omitempty" yaml:"advDhcpConfigFileOverride,omitempty"`
	// AdvDHCPConfigFileOverridePath is the filesystem path for the DHCP config override file.
	AdvDHCPConfigFileOverridePath string `json:"advDhcpConfigFileOverridePath,omitempty" yaml:"advDhcpConfigFileOverridePath,omitempty"`

	// DHCPv6 basic fields.

	// DHCPv6ConfigAdvanced contains raw advanced DHCPv6 configuration text.
	DHCPv6ConfigAdvanced string `json:"dhcpv6ConfigAdvanced,omitempty" yaml:"dhcpv6ConfigAdvanced,omitempty"`
	// DHCPv6PrefixOnly restricts DHCPv6 to prefix delegation only.
	DHCPv6PrefixOnly string `json:"dhcpv6PrefixOnly,omitempty" yaml:"dhcpv6PrefixOnly,omitempty"`
	// DHCPv6PrefixDelegationSize is the size of the delegated IPv6 prefix.
	DHCPv6PrefixDelegationSize string `json:"dhcpv6PrefixDelegationSize,omitempty" yaml:"dhcpv6PrefixDelegationSize,omitempty"`

	// IPv6 tracking fields.

	// Track6Interface is the upstream interface used for IPv6 prefix tracking.
	Track6Interface string `json:"track6Interface,omitempty" yaml:"track6Interface,omitempty"`
	// Track6PrefixID is the prefix delegation ID for IPv6 tracking.
	Track6PrefixID string `json:"track6PrefixId,omitempty" yaml:"track6PrefixId,omitempty"`

	// Advanced DHCPv6 interface statement fields.

	// AdvDHCP6InterfaceStatementSendOptions specifies DHCPv6 options to send.
	AdvDHCP6InterfaceStatementSendOptions string `json:"advDhcp6InterfaceStatementSendOptions,omitempty" yaml:"advDhcp6InterfaceStatementSendOptions,omitempty"`
	// AdvDHCP6InterfaceStatementRequestOptions specifies DHCPv6 options to request.
	AdvDHCP6InterfaceStatementRequestOptions string `json:"advDhcp6InterfaceStatementRequestOptions,omitempty" yaml:"advDhcp6InterfaceStatementRequestOptions,omitempty"`
	// AdvDHCP6InterfaceStatementInformationOnlyEnable enables information-only mode.
	AdvDHCP6InterfaceStatementInformationOnlyEnable string `json:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty" yaml:"advDhcp6InterfaceStatementInformationOnlyEnable,omitempty"`
	// AdvDHCP6InterfaceStatementScript is the script path for DHCPv6 events.
	AdvDHCP6InterfaceStatementScript string `json:"advDhcp6InterfaceStatementScript,omitempty" yaml:"advDhcp6InterfaceStatementScript,omitempty"`

	// Advanced DHCPv6 identity association address fields.

	// AdvDHCP6IDAssocStatementAddressEnable enables IA_NA address assignment.
	AdvDHCP6IDAssocStatementAddressEnable string `json:"advDhcp6IdAssocStatementAddressEnable,omitempty" yaml:"advDhcp6IdAssocStatementAddressEnable,omitempty"`
	// AdvDHCP6IDAssocStatementAddress is the requested IA_NA address.
	AdvDHCP6IDAssocStatementAddress string `json:"advDhcp6IdAssocStatementAddress,omitempty" yaml:"advDhcp6IdAssocStatementAddress,omitempty"`
	// AdvDHCP6IDAssocStatementAddressID is the identity association ID for addresses.
	AdvDHCP6IDAssocStatementAddressID string `json:"advDhcp6IdAssocStatementAddressId,omitempty" yaml:"advDhcp6IdAssocStatementAddressId,omitempty"`
	// AdvDHCP6IDAssocStatementAddressPLTime is the preferred lifetime for IA_NA addresses.
	AdvDHCP6IDAssocStatementAddressPLTime string `json:"advDhcp6IdAssocStatementAddressPlTime,omitempty" yaml:"advDhcp6IdAssocStatementAddressPlTime,omitempty"`
	// AdvDHCP6IDAssocStatementAddressVLTime is the valid lifetime for IA_NA addresses.
	AdvDHCP6IDAssocStatementAddressVLTime string `json:"advDhcp6IdAssocStatementAddressVlTime,omitempty" yaml:"advDhcp6IdAssocStatementAddressVlTime,omitempty"`

	// Advanced DHCPv6 identity association prefix fields.

	// AdvDHCP6IDAssocStatementPrefixEnable enables IA_PD prefix delegation.
	AdvDHCP6IDAssocStatementPrefixEnable string `json:"advDhcp6IdAssocStatementPrefixEnable,omitempty" yaml:"advDhcp6IdAssocStatementPrefixEnable,omitempty"`
	// AdvDHCP6IDAssocStatementPrefix is the requested IA_PD prefix.
	AdvDHCP6IDAssocStatementPrefix string `json:"advDhcp6IdAssocStatementPrefix,omitempty" yaml:"advDhcp6IdAssocStatementPrefix,omitempty"`
	// AdvDHCP6IDAssocStatementPrefixID is the identity association ID for prefixes.
	AdvDHCP6IDAssocStatementPrefixID string `json:"advDhcp6IdAssocStatementPrefixId,omitempty" yaml:"advDhcp6IdAssocStatementPrefixId,omitempty"`
	// AdvDHCP6IDAssocStatementPrefixPLTime is the preferred lifetime for IA_PD prefixes.
	AdvDHCP6IDAssocStatementPrefixPLTime string `json:"advDhcp6IdAssocStatementPrefixPlTime,omitempty" yaml:"advDhcp6IdAssocStatementPrefixPlTime,omitempty"`
	// AdvDHCP6IDAssocStatementPrefixVLTime is the valid lifetime for IA_PD prefixes.
	AdvDHCP6IDAssocStatementPrefixVLTime string `json:"advDhcp6IdAssocStatementPrefixVlTime,omitempty" yaml:"advDhcp6IdAssocStatementPrefixVlTime,omitempty"`

	// Advanced DHCPv6 SLA prefix interface field.

	// AdvDHCP6PrefixInterfaceStatementSLALen is the SLA prefix length for interface delegation.
	AdvDHCP6PrefixInterfaceStatementSLALen string `json:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty" yaml:"advDhcp6PrefixInterfaceStatementSlaLen,omitempty"`

	// Advanced DHCPv6 authentication fields.

	// AdvDHCP6AuthenticationStatementAuthName is the authentication profile name.
	AdvDHCP6AuthenticationStatementAuthName string `json:"advDhcp6AuthenticationStatementAuthName,omitempty" yaml:"advDhcp6AuthenticationStatementAuthName,omitempty"`
	// AdvDHCP6AuthenticationStatementProtocol is the authentication protocol.
	AdvDHCP6AuthenticationStatementProtocol string `json:"advDhcp6AuthenticationStatementProtocol,omitempty" yaml:"advDhcp6AuthenticationStatementProtocol,omitempty"`
	// AdvDHCP6AuthenticationStatementAlgorithm is the authentication algorithm.
	AdvDHCP6AuthenticationStatementAlgorithm string `json:"advDhcp6AuthenticationStatementAlgorithm,omitempty" yaml:"advDhcp6AuthenticationStatementAlgorithm,omitempty"`
	// AdvDHCP6AuthenticationStatementRDM is the replay detection method.
	AdvDHCP6AuthenticationStatementRDM string `json:"advDhcp6AuthenticationStatementRdm,omitempty" yaml:"advDhcp6AuthenticationStatementRdm,omitempty"`

	// Advanced DHCPv6 key info fields.

	// AdvDHCP6KeyInfoStatementKeyName is the key name for DHCPv6 authentication.
	AdvDHCP6KeyInfoStatementKeyName string `json:"advDhcp6KeyInfoStatementKeyName,omitempty" yaml:"advDhcp6KeyInfoStatementKeyName,omitempty"`
	// AdvDHCP6KeyInfoStatementRealm is the authentication realm.
	AdvDHCP6KeyInfoStatementRealm string `json:"advDhcp6KeyInfoStatementRealm,omitempty" yaml:"advDhcp6KeyInfoStatementRealm,omitempty"`
	// AdvDHCP6KeyInfoStatementKeyID is the key identifier.
	AdvDHCP6KeyInfoStatementKeyID string `json:"advDhcp6KeyInfoStatementKeyId,omitempty" yaml:"advDhcp6KeyInfoStatementKeyId,omitempty"`
	// AdvDHCP6KeyInfoStatementSecret is the shared secret for DHCPv6 authentication.
	AdvDHCP6KeyInfoStatementSecret string `json:"advDhcp6KeyInfoStatementSecret,omitempty" yaml:"advDhcp6KeyInfoStatementSecret,omitempty"`
	// AdvDHCP6KeyInfoStatementExpire is the key expiration time.
	AdvDHCP6KeyInfoStatementExpire string `json:"advDhcp6KeyInfoStatementExpire,omitempty" yaml:"advDhcp6KeyInfoStatementExpire,omitempty"`

	// Advanced DHCPv6 configuration override fields.

	// AdvDHCP6ConfigAdvanced contains raw advanced DHCPv6 configuration text.
	AdvDHCP6ConfigAdvanced string `json:"advDhcp6ConfigAdvanced,omitempty" yaml:"advDhcp6ConfigAdvanced,omitempty"`
	// AdvDHCP6ConfigFileOverride enables overriding the DHCPv6 config file.
	AdvDHCP6ConfigFileOverride string `json:"advDhcp6ConfigFileOverride,omitempty" yaml:"advDhcp6ConfigFileOverride,omitempty"`
	// AdvDHCP6ConfigFileOverridePath is the filesystem path for the DHCPv6 config override file.
	AdvDHCP6ConfigFileOverridePath string `json:"advDhcp6ConfigFileOverridePath,omitempty" yaml:"advDhcp6ConfigFileOverridePath,omitempty"`
}

// DHCPRange represents the start and end of a DHCP address range.
type DHCPRange struct {
	// From is the first IP address in the DHCP pool.
	From string `json:"from,omitempty" yaml:"from,omitempty"`
	// To is the last IP address in the DHCP pool.
	To string `json:"to,omitempty" yaml:"to,omitempty"`
}

// DHCPStaticLease represents a static DHCP lease mapping.
type DHCPStaticLease struct {
	// MAC is the hardware MAC address for the static lease.
	MAC string `json:"mac,omitempty" yaml:"mac,omitempty"`
	// CID is the DHCP client identifier.
	CID string `json:"cid,omitempty" yaml:"cid,omitempty"`
	// IPAddress is the fixed IP address assigned to the client.
	IPAddress string `json:"ipAddress,omitempty" yaml:"ipAddress,omitempty"`
	// Hostname is the hostname assigned to the client.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Description is a human-readable description of the static lease.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Filename is the TFTP boot filename for network boot clients.
	Filename string `json:"filename,omitempty" yaml:"filename,omitempty"`
	// Rootpath is the NFS root path for network boot clients.
	Rootpath string `json:"rootpath,omitempty" yaml:"rootpath,omitempty"`
	// DefaultLeaseTime is the default lease duration in seconds.
	DefaultLeaseTime string `json:"defaultLeaseTime,omitempty" yaml:"defaultLeaseTime,omitempty"`
	// MaxLeaseTime is the maximum lease duration in seconds.
	MaxLeaseTime string `json:"maxLeaseTime,omitempty" yaml:"maxLeaseTime,omitempty"`
}

// DHCPNumberOption represents a custom DHCP number option.
type DHCPNumberOption struct {
	// Number is the DHCP option number.
	Number string `json:"number,omitempty" yaml:"number,omitempty"`
	// Type is the option value type (e.g., "text", "string", "boolean").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Value is the option value.
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// DNSConfig contains aggregated DNS configuration.
type DNSConfig struct {
	// Servers contains DNS server addresses.
	Servers []string `json:"servers,omitempty" yaml:"servers,omitempty"`
	// Unbound contains Unbound DNS resolver configuration.
	Unbound UnboundConfig `json:"unbound" yaml:"unbound,omitempty"`
	// DNSMasq contains dnsmasq forwarder configuration.
	DNSMasq DNSMasqConfig `json:"dnsMasq" yaml:"dnsMasq,omitempty"`
}

// UnboundConfig contains Unbound DNS resolver configuration.
type UnboundConfig struct {
	// Enabled indicates whether the Unbound resolver is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// DNSSEC enables DNSSEC validation.
	DNSSEC bool `json:"dnssec,omitempty" yaml:"dnssec,omitempty"`
	// DNSSECStripped enables DNSSEC stripped mode.
	DNSSECStripped bool `json:"dnssecStripped,omitempty" yaml:"dnssecStripped,omitempty"`
}

// DNSMasqConfig contains dnsmasq forwarder configuration.
type DNSMasqConfig struct {
	// Enabled indicates whether the dnsmasq forwarder is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Hosts contains static DNS host entries.
	Hosts []DNSMasqHost `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	// DomainOverrides contains DNS domain override entries.
	DomainOverrides []DomainOverride `json:"domainOverrides,omitempty" yaml:"domainOverrides,omitempty"`
	// Forwarders contains DNS forwarding server configurations.
	Forwarders []ForwarderGroup `json:"forwarders,omitempty" yaml:"forwarders,omitempty"`
}

// DNSMasqHost represents a static DNS host entry.
type DNSMasqHost struct {
	// Host is the hostname for the DNS entry.
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
	// Domain is the domain name for the DNS entry.
	Domain string `json:"domain,omitempty" yaml:"domain,omitempty"`
	// IP is the IP address the hostname resolves to.
	IP string `json:"ip,omitempty" yaml:"ip,omitempty"`
	// Description is a human-readable description of the host entry.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Aliases contains additional hostnames that resolve to the same IP.
	Aliases []string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
}

// DomainOverride represents a DNS domain override entry.
type DomainOverride struct {
	// Domain is the domain name to override.
	Domain string `json:"domain,omitempty" yaml:"domain,omitempty"`
	// IP is the DNS server address for the overridden domain.
	IP string `json:"ip,omitempty" yaml:"ip,omitempty"`
	// Description is a human-readable description of the override.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// ForwarderGroup represents a DNS forwarding server.
type ForwarderGroup struct {
	// IP is the forwarder server IP address.
	IP string `json:"ip,omitempty" yaml:"ip,omitempty"`
	// Port is the forwarder server port.
	Port string `json:"port,omitempty" yaml:"port,omitempty"`
	// Description is a human-readable description of the forwarder.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// NTPConfig contains NTP service configuration.
type NTPConfig struct {
	// PreferredServer is the preferred NTP server address.
	PreferredServer string `json:"preferredServer,omitempty" yaml:"preferredServer,omitempty"`
}

// SNMPConfig contains SNMP service configuration.
type SNMPConfig struct {
	// ROCommunity is the read-only SNMP community string.
	ROCommunity string `json:"roCommunity,omitempty" yaml:"roCommunity,omitempty"`
	// SysLocation is the SNMP system location.
	SysLocation string `json:"sysLocation,omitempty" yaml:"sysLocation,omitempty"`
	// SysContact is the SNMP system contact.
	SysContact string `json:"sysContact,omitempty" yaml:"sysContact,omitempty"`
}

// LoadBalancerConfig contains load balancer configuration.
type LoadBalancerConfig struct {
	// MonitorTypes contains health monitor configurations.
	MonitorTypes []MonitorType `json:"monitorTypes,omitempty" yaml:"monitorTypes,omitempty"`
}

// MonitorType represents a load balancer health monitor.
type MonitorType struct {
	// Name is the monitor name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Type is the monitor type (e.g., "http", "https", "icmp", "tcp").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Description is a human-readable description of the monitor.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Options contains health check options for the monitor.
	Options MonitorOptions `json:"options" yaml:"options,omitempty"`
}

// MonitorOptions contains health check options for a monitor.
type MonitorOptions struct {
	// Path is the HTTP path to check for HTTP/HTTPS monitors.
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	// Host is the HTTP Host header value for the health check.
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
	// Code is the expected HTTP status code.
	Code string `json:"code,omitempty" yaml:"code,omitempty"`
	// Send is the data payload to send for TCP monitors.
	Send string `json:"send,omitempty" yaml:"send,omitempty"`
	// Expect is the expected response string for TCP monitors.
	Expect string `json:"expect,omitempty" yaml:"expect,omitempty"`
}

// SyslogConfig contains remote syslog configuration.
type SyslogConfig struct {
	// Enabled indicates whether remote syslog forwarding is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// SystemLogging enables forwarding of system log messages.
	SystemLogging bool `json:"systemLogging,omitempty" yaml:"systemLogging,omitempty"`
	// AuthLogging enables forwarding of authentication log messages.
	AuthLogging bool `json:"authLogging,omitempty" yaml:"authLogging,omitempty"`
	// FilterLogging enables forwarding of firewall filter log messages.
	FilterLogging bool `json:"filterLogging,omitempty" yaml:"filterLogging,omitempty"`
	// DHCPLogging enables forwarding of DHCP log messages.
	DHCPLogging bool `json:"dhcpLogging,omitempty" yaml:"dhcpLogging,omitempty"`
	// VPNLogging enables forwarding of VPN log messages.
	VPNLogging bool `json:"vpnLogging,omitempty" yaml:"vpnLogging,omitempty"`
	// RemoteServer is the primary remote syslog server address.
	RemoteServer string `json:"remoteServer,omitempty" yaml:"remoteServer,omitempty"`
	// RemoteServer2 is the secondary remote syslog server address.
	RemoteServer2 string `json:"remoteServer2,omitempty" yaml:"remoteServer2,omitempty"`
	// RemoteServer3 is the tertiary remote syslog server address.
	RemoteServer3 string `json:"remoteServer3,omitempty" yaml:"remoteServer3,omitempty"`
	// SourceIP is the source IP address for syslog messages.
	SourceIP string `json:"sourceIp,omitempty" yaml:"sourceIp,omitempty"`
	// IPProtocol is the IP protocol for syslog transport (e.g., "ipv4", "ipv6").
	IPProtocol string `json:"ipProtocol,omitempty" yaml:"ipProtocol,omitempty"`
	// LogFileSize is the maximum log file size.
	LogFileSize string `json:"logFileSize,omitempty" yaml:"logFileSize,omitempty"`
	// RotateCount is the number of rotated log files to retain.
	RotateCount string `json:"rotateCount,omitempty" yaml:"rotateCount,omitempty"`
	// Format is the syslog message format.
	Format string `json:"format,omitempty" yaml:"format,omitempty"`
}
