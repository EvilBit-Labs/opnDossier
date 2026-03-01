package common

// HighAvailability contains CARP/pfsync high-availability configuration.
type HighAvailability struct {
	// DisablePreempt disables CARP preemption (higher-priority node reclaiming master role).
	DisablePreempt bool `json:"disablePreempt,omitempty" yaml:"disablePreempt,omitempty"`
	// DisconnectPPPs disconnects PPP connections on CARP failover.
	DisconnectPPPs bool `json:"disconnectPpps,omitempty" yaml:"disconnectPpps,omitempty"`
	// PfsyncInterface is the interface used for pfsync state synchronization.
	PfsyncInterface string `json:"pfsyncInterface,omitempty" yaml:"pfsyncInterface,omitempty"`
	// PfsyncPeerIP is the IP address of the pfsync peer for state replication.
	PfsyncPeerIP string `json:"pfsyncPeerIp,omitempty" yaml:"pfsyncPeerIp,omitempty"`
	// PfsyncVersion is the pfsync protocol version.
	PfsyncVersion string `json:"pfsyncVersion,omitempty" yaml:"pfsyncVersion,omitempty"`
	// SynchronizeToIP is the IP address of the peer to synchronize configuration to.
	SynchronizeToIP string `json:"synchronizeToIp,omitempty" yaml:"synchronizeToIp,omitempty"`
	// Username is the username for XMLRPC configuration synchronization.
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	// Password is the password for XMLRPC configuration synchronization.
	//nolint:gosec // Domain model field intentionally represents parsed configuration data, not embedded credentials.
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	// SyncItems contains the configuration sections to synchronize.
	SyncItems []string `json:"syncItems,omitempty" yaml:"syncItems,omitempty"`
}
