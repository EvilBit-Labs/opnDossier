package common

// VPN contains all VPN subsystem configurations.
type VPN struct {
	// OpenVPN contains OpenVPN server and client configurations.
	OpenVPN OpenVPNConfig `json:"openVpn" yaml:"openVpn,omitempty"`
	// WireGuard contains WireGuard VPN configuration.
	WireGuard WireGuardConfig `json:"wireGuard" yaml:"wireGuard,omitempty"`
	// IPsec contains IPsec VPN configuration.
	IPsec IPsecConfig `json:"ipsec" yaml:"ipsec,omitempty"`
}

// OpenVPNConfig contains OpenVPN server and client configurations.
type OpenVPNConfig struct {
	// Servers contains OpenVPN server instances.
	Servers []OpenVPNServer `json:"servers,omitempty" yaml:"servers,omitempty"`
	// Clients contains OpenVPN client instances.
	Clients []OpenVPNClient `json:"clients,omitempty" yaml:"clients,omitempty"`
	// ClientSpecificConfigs contains per-client overrides keyed by certificate common name.
	ClientSpecificConfigs []OpenVPNCSC `json:"clientSpecificConfigs,omitempty" yaml:"clientSpecificConfigs,omitempty"`
}

// OpenVPNServer represents an OpenVPN server instance.
type OpenVPNServer struct {
	// VPNID is the unique VPN instance identifier.
	VPNID string `json:"vpnId,omitempty" yaml:"vpnId,omitempty"`
	// Mode is the server mode (e.g., "server_tls", "server_user", "p2p_tls").
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Protocol is the transport protocol (e.g., "UDP4", "TCP4").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// DevMode is the tunnel device mode (e.g., "tun", "tap").
	DevMode string `json:"devMode,omitempty" yaml:"devMode,omitempty"`
	// Interface is the interface the server listens on.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// LocalPort is the local port the server listens on.
	LocalPort string `json:"localPort,omitempty" yaml:"localPort,omitempty"`
	// Description is a human-readable description of the server instance.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// TunnelNetwork is the IPv4 tunnel network CIDR.
	TunnelNetwork string `json:"tunnelNetwork,omitempty" yaml:"tunnelNetwork,omitempty"`
	// TunnelNetworkV6 is the IPv6 tunnel network CIDR.
	TunnelNetworkV6 string `json:"tunnelNetworkV6,omitempty" yaml:"tunnelNetworkV6,omitempty"`
	// RemoteNetwork is the IPv4 remote network CIDR accessible through the tunnel.
	RemoteNetwork string `json:"remoteNetwork,omitempty" yaml:"remoteNetwork,omitempty"`
	// RemoteNetworkV6 is the IPv6 remote network CIDR accessible through the tunnel.
	RemoteNetworkV6 string `json:"remoteNetworkV6,omitempty" yaml:"remoteNetworkV6,omitempty"`
	// LocalNetwork is the IPv4 local network CIDR pushed to clients.
	LocalNetwork string `json:"localNetwork,omitempty" yaml:"localNetwork,omitempty"`
	// LocalNetworkV6 is the IPv6 local network CIDR pushed to clients.
	LocalNetworkV6 string `json:"localNetworkV6,omitempty" yaml:"localNetworkV6,omitempty"`
	// MaxClients is the maximum number of simultaneous client connections.
	MaxClients string `json:"maxClients,omitempty" yaml:"maxClients,omitempty"`
	// Compression is the compression algorithm (e.g., "lzo", "lz4", "no").
	Compression string `json:"compression,omitempty" yaml:"compression,omitempty"`
	// DNSServers contains DNS servers pushed to clients.
	DNSServers []string `json:"dnsServers,omitempty" yaml:"dnsServers,omitempty"`
	// NTPServers contains NTP servers pushed to clients.
	NTPServers []string `json:"ntpServers,omitempty" yaml:"ntpServers,omitempty"`
	// CertRef is the reference ID of the server certificate.
	CertRef string `json:"certRef,omitempty" yaml:"certRef,omitempty"`
	// CARef is the reference ID of the certificate authority.
	CARef string `json:"caRef,omitempty" yaml:"caRef,omitempty"`
	// CRLRef is the reference ID of the certificate revocation list.
	CRLRef string `json:"crlRef,omitempty" yaml:"crlRef,omitempty"`
	// DHLength is the Diffie-Hellman key length in bits.
	DHLength string `json:"dhLength,omitempty" yaml:"dhLength,omitempty"`
	// ECDHCurve is the elliptic curve for ECDH key exchange.
	ECDHCurve string `json:"ecdhCurve,omitempty" yaml:"ecdhCurve,omitempty"`
	// CertDepth is the maximum certificate chain verification depth.
	CertDepth string `json:"certDepth,omitempty" yaml:"certDepth,omitempty"`
	// TLSType is the TLS authentication type (e.g., "auth", "crypt").
	TLSType string `json:"tlsType,omitempty" yaml:"tlsType,omitempty"`
	// VerbosityLevel is the logging verbosity level (0-11).
	VerbosityLevel string `json:"verbosityLevel,omitempty" yaml:"verbosityLevel,omitempty"`
	// Topology is the server topology (e.g., "subnet", "net30").
	Topology string `json:"topology,omitempty" yaml:"topology,omitempty"`
	// StrictUserCN enforces matching of certificate CN to username.
	StrictUserCN bool `json:"strictUserCn,omitempty" yaml:"strictUserCn,omitempty"`
	// GWRedir redirects all client traffic through the VPN gateway.
	GWRedir bool `json:"gwRedir,omitempty" yaml:"gwRedir,omitempty"`
	// DynamicIP allows clients with dynamic IP addresses.
	DynamicIP bool `json:"dynamicIp,omitempty" yaml:"dynamicIp,omitempty"`
	// ServerBridgeDHCP enables DHCP for bridged server mode.
	ServerBridgeDHCP bool `json:"serverBridgeDhcp,omitempty" yaml:"serverBridgeDhcp,omitempty"`
	// DNSDomain is the DNS domain pushed to clients.
	DNSDomain string `json:"dnsDomain,omitempty" yaml:"dnsDomain,omitempty"`
	// NetBIOSEnable enables NetBIOS over TCP/IP for clients.
	NetBIOSEnable bool `json:"netBiosEnable,omitempty" yaml:"netBiosEnable,omitempty"`
	// NetBIOSNType is the NetBIOS node type.
	NetBIOSNType string `json:"netBiosNType,omitempty" yaml:"netBiosNType,omitempty"`
	// NetBIOSScope is the NetBIOS scope ID.
	NetBIOSScope string `json:"netBiosScope,omitempty" yaml:"netBiosScope,omitempty"`
}

// OpenVPNClient represents an OpenVPN client instance.
type OpenVPNClient struct {
	// VPNID is the unique VPN instance identifier.
	VPNID string `json:"vpnId,omitempty" yaml:"vpnId,omitempty"`
	// Mode is the client mode (e.g., "p2p_tls", "p2p_shared_key").
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Protocol is the transport protocol (e.g., "UDP4", "TCP4").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// DevMode is the tunnel device mode (e.g., "tun", "tap").
	DevMode string `json:"devMode,omitempty" yaml:"devMode,omitempty"`
	// Interface is the interface the client binds to.
	Interface string `json:"interface,omitempty" yaml:"interface,omitempty"`
	// ServerAddr is the remote server address.
	ServerAddr string `json:"serverAddr,omitempty" yaml:"serverAddr,omitempty"`
	// ServerPort is the remote server port.
	ServerPort string `json:"serverPort,omitempty" yaml:"serverPort,omitempty"`
	// Description is a human-readable description of the client instance.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// CertRef is the reference ID of the client certificate.
	CertRef string `json:"certRef,omitempty" yaml:"certRef,omitempty"`
	// CARef is the reference ID of the certificate authority.
	CARef string `json:"caRef,omitempty" yaml:"caRef,omitempty"`
	// Compression is the compression algorithm.
	Compression string `json:"compression,omitempty" yaml:"compression,omitempty"`
	// VerbosityLevel is the logging verbosity level.
	VerbosityLevel string `json:"verbosityLevel,omitempty" yaml:"verbosityLevel,omitempty"`
}

// WireGuardConfig contains WireGuard VPN configuration.
type WireGuardConfig struct {
	// Enabled indicates whether WireGuard is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Servers contains WireGuard server (local) instances.
	Servers []WireGuardServer `json:"servers,omitempty" yaml:"servers,omitempty"`
	// Clients contains WireGuard peer (client) instances.
	Clients []WireGuardClient `json:"clients,omitempty" yaml:"clients,omitempty"`
}

// WireGuardServer represents a WireGuard server (local) instance.
type WireGuardServer struct {
	// UUID is the unique identifier for the WireGuard server.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Enabled indicates whether this server instance is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Name is the human-readable name for the server instance.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// PublicKey is the WireGuard public key.
	PublicKey string `json:"publicKey,omitempty" yaml:"publicKey,omitempty"`
	// Port is the UDP listening port.
	Port string `json:"port,omitempty" yaml:"port,omitempty"`
	// MTU is the tunnel maximum transmission unit.
	MTU string `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// TunnelAddress is the tunnel IP address with prefix.
	TunnelAddress string `json:"tunnelAddress,omitempty" yaml:"tunnelAddress,omitempty"`
	// DNS is the DNS server address for the tunnel.
	DNS string `json:"dns,omitempty" yaml:"dns,omitempty"`
	// Gateway is the gateway address for the tunnel.
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
}

// WireGuardClient represents a WireGuard peer (client) instance.
type WireGuardClient struct {
	// UUID is the unique identifier for the WireGuard peer.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Enabled indicates whether this peer is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Name is the human-readable name for the peer.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// PublicKey is the peer's WireGuard public key.
	PublicKey string `json:"publicKey,omitempty" yaml:"publicKey,omitempty"`
	// PSK is the optional pre-shared key for additional security.
	PSK string `json:"psk,omitempty" yaml:"psk,omitempty"`
	// TunnelAddress is the allowed IP address for the peer.
	TunnelAddress string `json:"tunnelAddress,omitempty" yaml:"tunnelAddress,omitempty"`
	// ServerAddress is the endpoint address for the peer.
	ServerAddress string `json:"serverAddress,omitempty" yaml:"serverAddress,omitempty"`
	// ServerPort is the endpoint port for the peer.
	ServerPort string `json:"serverPort,omitempty" yaml:"serverPort,omitempty"`
	// Keepalive is the persistent keepalive interval in seconds.
	Keepalive string `json:"keepalive,omitempty" yaml:"keepalive,omitempty"`
}

// IPsecConfig contains IPsec VPN configuration.
type IPsecConfig struct {
	// Enabled indicates whether the IPsec subsystem is active.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// PreferredOldSA prefers old security associations over new ones.
	PreferredOldSA bool `json:"preferredOldSa,omitempty" yaml:"preferredOldSa,omitempty"`
	// DisableVPNRules disables automatic firewall rule generation for IPsec.
	DisableVPNRules bool `json:"disableVpnRules,omitempty" yaml:"disableVpnRules,omitempty"`
	// PassthroughNetworks contains networks that bypass IPsec processing.
	PassthroughNetworks string `json:"passthroughNetworks,omitempty" yaml:"passthroughNetworks,omitempty"`
	// KeyPairs contains IPsec key pair identifiers.
	KeyPairs string `json:"keyPairs,omitempty" yaml:"keyPairs,omitempty"`
	// PreSharedKeys contains IPsec pre-shared key identifiers.
	PreSharedKeys string `json:"preSharedKeys,omitempty" yaml:"preSharedKeys,omitempty"`
	// Charon contains strongSwan charon daemon settings.
	Charon IPsecCharon `json:"charon" yaml:"charon,omitempty"`
}

// IPsecCharon contains strongSwan charon daemon configuration.
type IPsecCharon struct {
	// Threads is the number of worker threads for the charon daemon.
	Threads string `json:"threads,omitempty" yaml:"threads,omitempty"`
	// IKEsaTableSize is the IKE SA hash table size.
	IKEsaTableSize string `json:"ikesaTableSize,omitempty" yaml:"ikesaTableSize,omitempty"`
	// IKEsaTableSegments is the number of IKE SA hash table segments.
	IKEsaTableSegments string `json:"ikesaTableSegments,omitempty" yaml:"ikesaTableSegments,omitempty"`
	// MaxIKEv1Exchanges is the maximum number of IKEv1 exchanges before giving up.
	MaxIKEv1Exchanges string `json:"maxIkev1Exchanges,omitempty" yaml:"maxIkev1Exchanges,omitempty"`
	// InitLimitHalfOpen is the limit of half-open IKE_SA during initialization.
	InitLimitHalfOpen string `json:"initLimitHalfOpen,omitempty" yaml:"initLimitHalfOpen,omitempty"`
	// IgnoreAcquireTS ignores traffic selector proposals from kernel acquire events.
	IgnoreAcquireTS bool `json:"ignoreAcquireTs,omitempty" yaml:"ignoreAcquireTs,omitempty"`
	// MakeBeforeBreak enables make-before-break for IKEv2 reauthentication.
	MakeBeforeBreak bool `json:"makeBeforeBreak,omitempty" yaml:"makeBeforeBreak,omitempty"`
	// RetransmitTries is the number of retransmit attempts before giving up.
	RetransmitTries string `json:"retransmitTries,omitempty" yaml:"retransmitTries,omitempty"`
	// RetransmitTimeout is the initial retransmission timeout in seconds.
	RetransmitTimeout string `json:"retransmitTimeout,omitempty" yaml:"retransmitTimeout,omitempty"`
	// RetransmitBase is the base for exponential backoff of retransmissions.
	RetransmitBase string `json:"retransmitBase,omitempty" yaml:"retransmitBase,omitempty"`
	// RetransmitJitter is the jitter percentage for retransmit intervals.
	RetransmitJitter string `json:"retransmitJitter,omitempty" yaml:"retransmitJitter,omitempty"`
	// RetransmitLimit is the upper limit in seconds for retransmission timeout.
	RetransmitLimit string `json:"retransmitLimit,omitempty" yaml:"retransmitLimit,omitempty"`
}

// OpenVPNCSC represents OpenVPN client-specific configuration overrides.
// These allow per-client settings based on the client's certificate common name.
type OpenVPNCSC struct {
	// CommonName is the certificate common name this override applies to.
	CommonName string `json:"commonName,omitempty" yaml:"commonName,omitempty"`
	// Block prevents this client from connecting.
	Block bool `json:"block,omitempty" yaml:"block,omitempty"`
	// TunnelNetwork is the IPv4 tunnel network override for this client.
	TunnelNetwork string `json:"tunnelNetwork,omitempty" yaml:"tunnelNetwork,omitempty"`
	// TunnelNetworkV6 is the IPv6 tunnel network override for this client.
	TunnelNetworkV6 string `json:"tunnelNetworkV6,omitempty" yaml:"tunnelNetworkV6,omitempty"`
	// LocalNetwork is the IPv4 local network pushed to this client.
	LocalNetwork string `json:"localNetwork,omitempty" yaml:"localNetwork,omitempty"`
	// LocalNetworkV6 is the IPv6 local network pushed to this client.
	LocalNetworkV6 string `json:"localNetworkV6,omitempty" yaml:"localNetworkV6,omitempty"`
	// RemoteNetwork is the IPv4 remote network accessible through this client.
	RemoteNetwork string `json:"remoteNetwork,omitempty" yaml:"remoteNetwork,omitempty"`
	// RemoteNetworkV6 is the IPv6 remote network accessible through this client.
	RemoteNetworkV6 string `json:"remoteNetworkV6,omitempty" yaml:"remoteNetworkV6,omitempty"`
	// GWRedir redirects all client traffic through the VPN gateway.
	GWRedir bool `json:"gwRedir,omitempty" yaml:"gwRedir,omitempty"`
	// PushReset clears all previously pushed options before applying overrides.
	PushReset bool `json:"pushReset,omitempty" yaml:"pushReset,omitempty"`
	// RemoveRoute removes server-side routes for this client.
	RemoveRoute bool `json:"removeRoute,omitempty" yaml:"removeRoute,omitempty"`
	// DNSDomain is the DNS domain override for this client.
	DNSDomain string `json:"dnsDomain,omitempty" yaml:"dnsDomain,omitempty"`
	// DNSServers contains DNS server overrides pushed to this client.
	DNSServers []string `json:"dnsServers,omitempty" yaml:"dnsServers,omitempty"`
	// NTPServers contains NTP server overrides pushed to this client.
	NTPServers []string `json:"ntpServers,omitempty" yaml:"ntpServers,omitempty"`
}
