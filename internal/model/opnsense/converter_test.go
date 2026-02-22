package opnsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/model/opnsense"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_NilInput(t *testing.T) {
	t.Parallel()

	device, err := opnsense.NewConverter().ToCommonDevice(nil)
	require.ErrorIs(t, err, opnsense.ErrNilDocument)
	require.Nil(t, device)
}

func TestConverter_System(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.Hostname = "fw01"
	doc.System.Domain = "example.com"
	doc.System.DNSServer = "8.8.8.8 8.8.4.4"
	doc.System.TimeServers = "0.pool.ntp.org 1.pool.ntp.org"
	doc.System.DisableNATReflection = "yes"
	doc.System.DisableConsoleMenu = true
	doc.System.PfShareForward = 1
	doc.System.IPv6Allow = "1"
	doc.System.DNSAllowOverride = 1
	doc.System.DisableVLANHWFilter = 1
	doc.System.DisableChecksumOffloading = 1
	doc.System.DisableSegmentationOffloading = 1
	doc.System.DisableLargeReceiveOffloading = 1
	doc.System.LbUseSticky = 1
	doc.System.RrdBackup = 1
	doc.System.NetflowBackup = 1
	doc.System.UseVirtualTerminal = 1
	doc.System.NextUID = 2000
	doc.System.NextGID = 2000
	doc.System.PowerdACMode = "hadp"
	doc.System.Bogons.Interval = "monthly"
	doc.System.WebGUI.Protocol = "https"
	doc.System.WebGUI.SSLCertRef = "cert-abc"
	doc.System.SSH.Group = "admins"
	doc.System.Firmware.Version = "24.7"
	doc.System.Firmware.Mirror = "https://mirror.example.com"
	doc.System.Notes = []string{"test note"}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	sys := device.System
	assert.Equal(t, "fw01", sys.Hostname)
	assert.Equal(t, "example.com", sys.Domain)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, sys.DNSServers)
	assert.Equal(t, []string{"0.pool.ntp.org", "1.pool.ntp.org"}, sys.TimeServers)
	assert.True(t, sys.DisableNATReflection)
	assert.True(t, sys.DisableConsoleMenu)
	assert.True(t, sys.PfShareForward)
	assert.True(t, sys.IPv6Allow)
	assert.True(t, sys.DNSAllowOverride)
	assert.True(t, sys.DisableVLANHWFilter)
	assert.True(t, sys.DisableChecksumOffloading)
	assert.True(t, sys.DisableSegmentationOffloading)
	assert.True(t, sys.DisableLargeReceiveOffloading)
	assert.True(t, sys.LbUseSticky)
	assert.True(t, sys.RrdBackup)
	assert.True(t, sys.NetflowBackup)
	assert.True(t, sys.UseVirtualTerminal)
	assert.Equal(t, 2000, sys.NextUID)
	assert.Equal(t, 2000, sys.NextGID)
	assert.Equal(t, "hadp", sys.PowerdACMode)
	assert.Equal(t, "monthly", sys.Bogons.Interval)
	assert.Equal(t, "https", sys.WebGUI.Protocol)
	assert.Equal(t, "cert-abc", sys.WebGUI.SSLCertRef)
	assert.Equal(t, "admins", sys.SSH.Group)
	assert.Equal(t, "24.7", sys.Firmware.Version)
	assert.Equal(t, "https://mirror.example.com", sys.Firmware.Mirror)
	assert.Equal(t, []string{"test note"}, sys.Notes)
}

func TestConverter_Interfaces(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Interfaces.Items["wan"] = schema.Interface{
		Enable:    "1",
		If:        "igb0",
		Descr:     "WAN",
		IPAddr:    "203.0.113.1",
		Subnet:    "24",
		BlockPriv: "1",
		Virtual:   1,
		Lock:      1,
	}
	doc.Interfaces.Items["lan"] = schema.Interface{
		Enable:      "1",
		If:          "igb1",
		Descr:       "LAN",
		IPAddr:      "192.168.1.1",
		Subnet:      "24",
		BlockBogons: "1",
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Len(t, device.Interfaces, 2)

	// Find the WAN interface by name
	var wan *common.Interface
	for i := range device.Interfaces {
		if device.Interfaces[i].Name == "wan" {
			wan = &device.Interfaces[i]
			break
		}
	}
	require.NotNil(t, wan, "wan interface not found")
	assert.Equal(t, "igb0", wan.PhysicalIf)
	assert.Equal(t, "WAN", wan.Description)
	assert.True(t, wan.Enabled)
	assert.True(t, wan.BlockPrivate)
	assert.True(t, wan.Virtual)
	assert.True(t, wan.Lock)
}

func TestConverter_FirewallRules(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()

	anyStr := ""
	doc.Filter.Rule = []schema.Rule{
		{
			Type:       "pass",
			Descr:      "Allow LAN",
			Interface:  schema.InterfaceList{"lan"},
			IPProtocol: "inet",
			Floating:   "yes",
			Quick:      true,
			Log:        true,
			Disabled:   false,
			Source: schema.Source{
				Any:  &anyStr,
				Port: "443",
			},
			Destination: schema.Destination{
				Network: "lan",
				Port:    "80",
				Not:     true,
			},
			TCPFlagsAny:    true,
			AllowOpts:      true,
			DisableReplyTo: true,
			NoPfSync:       true,
			NoSync:         true,
			UUID:           "abc-123",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 1)

	rule := device.FirewallRules[0]
	assert.Equal(t, "pass", rule.Type)
	assert.Equal(t, "Allow LAN", rule.Description)
	assert.Equal(t, []string{"lan"}, rule.Interfaces)
	assert.True(t, rule.Floating)
	assert.True(t, rule.Quick)
	assert.True(t, rule.Log)
	assert.False(t, rule.Disabled)
	assert.Equal(t, "any", rule.Source.Address)
	assert.Equal(t, "443", rule.Source.Port)
	assert.False(t, rule.Source.Negated)
	assert.Equal(t, "lan", rule.Destination.Address)
	assert.Equal(t, "80", rule.Destination.Port)
	assert.True(t, rule.Destination.Negated)
	assert.True(t, rule.TCPFlagsAny)
	assert.True(t, rule.AllowOpts)
	assert.True(t, rule.DisableReplyTo)
	assert.True(t, rule.NoPfSync)
	assert.True(t, rule.NoSync)
	assert.Equal(t, "abc-123", rule.UUID)
}

func TestConverter_NAT(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Nat.Outbound.Mode = "hybrid"
	doc.System.DisableNATReflection = "yes"
	doc.System.PfShareForward = 1

	anyStr := ""
	doc.Nat.Outbound.Rule = []schema.NATRule{
		{
			Interface: schema.InterfaceList{"wan"},
			Source:    schema.Source{Any: &anyStr},
			Destination: schema.Destination{
				Network: "10.0.0.0/8",
			},
			StaticNatPort: true,
			NoNat:         false,
			Disabled:      false,
			Log:           true,
		},
	}
	doc.Nat.Inbound = []schema.InboundRule{
		{
			Interface: schema.InterfaceList{"wan"},
			Source:    schema.Source{Any: &anyStr},
			Destination: schema.Destination{
				Network: "wanip",
				Port:    "443",
			},
			InternalIP:   "192.168.1.10",
			InternalPort: "443",
			NoRDR:        true,
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.Equal(t, "hybrid", device.NAT.OutboundMode)
	assert.True(t, device.NAT.ReflectionDisabled)
	assert.True(t, device.NAT.PfShareForward)
	require.Len(t, device.NAT.OutboundRules, 1)
	assert.True(t, device.NAT.OutboundRules[0].StaticNatPort)
	assert.True(t, device.NAT.OutboundRules[0].Log)
	require.Len(t, device.NAT.InboundRules, 1)
	assert.Equal(t, "192.168.1.10", device.NAT.InboundRules[0].InternalIP)
	assert.True(t, device.NAT.InboundRules[0].NoRDR)
}

func TestConverter_DHCP(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Dhcpd.Items["lan"] = schema.DhcpdInterface{
		Enable:  "1",
		Range:   schema.Range{From: "192.168.1.100", To: "192.168.1.200"},
		Gateway: "192.168.1.1",
		Staticmap: []schema.DHCPStaticLease{
			{
				Mac:      "aa:bb:cc:dd:ee:ff",
				IPAddr:   "192.168.1.50",
				Hostname: "server1",
				Descr:    "Web server",
			},
		},
		NumberOptions: []schema.DHCPNumberOption{
			{Number: "66", Type: "text", Value: "tftp.example.com"},
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.DHCP, 1)

	scope := device.DHCP[0]
	assert.Equal(t, "lan", scope.Interface)
	assert.True(t, scope.Enabled)
	assert.Equal(t, "192.168.1.100", scope.Range.From)
	assert.Equal(t, "192.168.1.200", scope.Range.To)
	assert.Equal(t, "192.168.1.1", scope.Gateway)
	require.Len(t, scope.StaticLeases, 1)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", scope.StaticLeases[0].MAC)
	assert.Equal(t, "server1", scope.StaticLeases[0].Hostname)
	require.Len(t, scope.NumberOptions, 1)
	assert.Equal(t, "66", scope.NumberOptions[0].Number)
}

func TestConverter_VPN_OpenVPN(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OpenVPN.Servers = []schema.OpenVPNServer{
		{
			VPN_ID:            "1",
			Description:       "Main VPN",
			DNS_server1:       "8.8.8.8",
			DNS_server2:       "8.8.4.4",
			DNS_server3:       "",
			DNS_server4:       "",
			NTP_server1:       "pool.ntp.org",
			NTP_server2:       "",
			Strictusercn:      true,
			Gwredir:           true,
			Dynamic_ip:        true,
			Serverbridge_dhcp: true,
			Netbios_enable:    true,
		},
	}
	doc.OpenVPN.Clients = []schema.OpenVPNClient{
		{
			VPN_ID:      "2",
			Description: "Remote client",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	require.Len(t, device.VPN.OpenVPN.Servers, 1)
	srv := device.VPN.OpenVPN.Servers[0]
	assert.Equal(t, "1", srv.VPNID)
	assert.Equal(t, "Main VPN", srv.Description)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, srv.DNSServers)
	assert.Equal(t, []string{"pool.ntp.org"}, srv.NTPServers)
	assert.True(t, srv.StrictUserCN)
	assert.True(t, srv.GWRedir)
	assert.True(t, srv.DynamicIP)
	assert.True(t, srv.ServerBridgeDHCP)
	assert.True(t, srv.NetBIOSEnable)

	require.Len(t, device.VPN.OpenVPN.Clients, 1)
	assert.Equal(t, "2", device.VPN.OpenVPN.Clients[0].VPNID)
}

func TestConverter_VPN_WireGuard(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.Wireguard = &schema.WireGuard{}
	doc.OPNsense.Wireguard.General.Enabled = "1"
	doc.OPNsense.Wireguard.Server.Servers.Server = []schema.WireGuardServerItem{
		{
			UUID:    "wg-srv-1",
			Enabled: "1",
			Name:    "wg0",
			Pubkey:  "pubkey-abc",
			Port:    "51820",
		},
	}
	doc.OPNsense.Wireguard.Client.Clients.Client = []schema.WireGuardClientItem{
		{
			UUID:    "wg-cl-1",
			Enabled: "1",
			Name:    "peer1",
			Pubkey:  "pubkey-def",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.True(t, device.VPN.WireGuard.Enabled)
	require.Len(t, device.VPN.WireGuard.Servers, 1)
	assert.Equal(t, "wg0", device.VPN.WireGuard.Servers[0].Name)
	assert.True(t, device.VPN.WireGuard.Servers[0].Enabled)
	require.Len(t, device.VPN.WireGuard.Clients, 1)
	assert.Equal(t, "peer1", device.VPN.WireGuard.Clients[0].Name)
}

func TestConverter_VPN_IPsec(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.IPsec = &schema.IPsec{}
	doc.OPNsense.IPsec.General.Enabled = "1"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.True(t, device.VPN.IPsec.Enabled)
}

func TestConverter_Routing(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Gateways.Gateway = []schema.Gateway{
		{
			Name:      "GW_WAN",
			Interface: "wan",
			Gateway:   "203.0.113.254",
			Disabled:  false,
			FarGW:     "1",
		},
	}
	doc.StaticRoutes.Route = []schema.StaticRoute{
		{
			Network:  "10.10.0.0/16",
			Gateway:  "GW_WAN",
			Descr:    "Remote office",
			Disabled: true,
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	require.Len(t, device.Routing.Gateways, 1)
	gw := device.Routing.Gateways[0]
	assert.Equal(t, "GW_WAN", gw.Name)
	assert.False(t, gw.Disabled)
	assert.True(t, gw.FarGW)

	require.Len(t, device.Routing.StaticRoutes, 1)
	route := device.Routing.StaticRoutes[0]
	assert.Equal(t, "10.10.0.0/16", route.Network)
	assert.True(t, route.Disabled)
}

func TestConverter_HA(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.HighAvailabilitySync.Disablepreempt = "on"
	doc.HighAvailabilitySync.Disconnectppps = "on"
	doc.HighAvailabilitySync.Pfsyncinterface = "lan"
	doc.HighAvailabilitySync.Pfsyncpeerip = "10.0.0.2"
	doc.HighAvailabilitySync.Username = "admin"
	doc.HighAvailabilitySync.Syncitems = "virtualip,certs,dhcpd"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.True(t, device.HighAvailability.DisablePreempt)
	assert.True(t, device.HighAvailability.DisconnectPPPs)
	assert.Equal(t, "lan", device.HighAvailability.PfsyncInterface)
	assert.Equal(t, "10.0.0.2", device.HighAvailability.PfsyncPeerIP)
	assert.Equal(t, "admin", device.HighAvailability.Username)
	assert.Equal(t, []string{"virtualip", "certs", "dhcpd"}, device.HighAvailability.SyncItems)
}

func TestConverter_IDS_Nil(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.IntrusionDetectionSystem = nil

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Nil(t, device.IDS)
}

func TestConverter_IDS_Enabled(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.IntrusionDetectionSystem = &schema.IDS{}
	doc.OPNsense.IntrusionDetectionSystem.General.Enabled = "1"
	doc.OPNsense.IntrusionDetectionSystem.General.Ips = "1"
	doc.OPNsense.IntrusionDetectionSystem.General.Promisc = "1"
	doc.OPNsense.IntrusionDetectionSystem.General.Interfaces = "wan,lan"
	doc.OPNsense.IntrusionDetectionSystem.General.Syslog = "1"
	doc.OPNsense.IntrusionDetectionSystem.General.SyslogEve = "1"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.NotNil(t, device.IDS)
	assert.True(t, device.IDS.Enabled)
	assert.True(t, device.IDS.IPSMode)
	assert.True(t, device.IDS.Promiscuous)
	assert.Equal(t, []string{"wan", "lan"}, device.IDS.Interfaces)
	assert.True(t, device.IDS.SyslogEnabled)
	assert.True(t, device.IDS.SyslogEveEnabled)
}

func TestConverter_Syslog(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Syslog.Enable = true
	doc.Syslog.System = true
	doc.Syslog.Auth = true
	doc.Syslog.Filter = true
	doc.Syslog.Dhcp = true
	doc.Syslog.VPN = true
	doc.Syslog.Remoteserver = "10.0.0.100"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.True(t, device.Syslog.Enabled)
	assert.True(t, device.Syslog.SystemLogging)
	assert.True(t, device.Syslog.AuthLogging)
	assert.True(t, device.Syslog.FilterLogging)
	assert.True(t, device.Syslog.DHCPLogging)
	assert.True(t, device.Syslog.VPNLogging)
	assert.Equal(t, "10.0.0.100", device.Syslog.RemoteServer)
}

func TestConverter_Users(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.User = []schema.User{
		{
			Name:      "admin",
			Disabled:  false,
			Descr:     "System Administrator",
			Scope:     "system",
			Groupname: "admins",
			UID:       "0",
			APIKeys: []schema.APIKey{
				{Key: "key1", Secret: "secret1"},
			},
		},
		{
			Name:     "operator",
			Disabled: true,
			Scope:    "local",
			UID:      "2001",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.Users, 2)

	admin := device.Users[0]
	assert.Equal(t, "admin", admin.Name)
	assert.False(t, admin.Disabled)
	assert.Equal(t, "System Administrator", admin.Description)
	require.Len(t, admin.APIKeys, 1)
	assert.Equal(t, "key1", admin.APIKeys[0].Key)

	op := device.Users[1]
	assert.True(t, op.Disabled)
}

func TestConverter_Sysctl(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Sysctl = []schema.SysctlItem{
		{Tunable: "net.inet.tcp.recvspace", Value: "65536", Descr: "TCP receive buffer"},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.Sysctl, 1)
	assert.Equal(t, "net.inet.tcp.recvspace", device.Sysctl[0].Tunable)
	assert.Equal(t, "65536", device.Sysctl[0].Value)
	assert.Equal(t, "TCP receive buffer", device.Sysctl[0].Description)
}

func TestConverter_Revision(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Revision.Username = "admin@10.0.0.1"
	doc.Revision.Time = "1700000000"
	doc.Revision.Description = "config backup"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.Equal(t, "admin@10.0.0.1", device.Revision.Username)
	assert.Equal(t, "1700000000", device.Revision.Time)
	assert.Equal(t, "config backup", device.Revision.Description)
}

func TestConverter_ComputedFieldsNil(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.Nil(t, device.Statistics)
	assert.Nil(t, device.Analysis)
	assert.Nil(t, device.SecurityAssessment)
	assert.Nil(t, device.PerformanceMetrics)
	assert.Nil(t, device.ComplianceChecks)
}

func TestConverter_DNS(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.DNSServer = "1.1.1.1 9.9.9.9"
	doc.Unbound.Enable = "1"
	doc.Unbound.Dnssec = "1"
	doc.Unbound.Dnssecstripped = "1"
	doc.DNSMasquerade.Enable = true
	doc.DNSMasquerade.Hosts = []schema.DNSMasqHost{
		{Host: "server", Domain: "local", IP: "10.0.0.1"},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.Equal(t, []string{"1.1.1.1", "9.9.9.9"}, device.DNS.Servers)
	assert.True(t, device.DNS.Unbound.Enabled)
	assert.True(t, device.DNS.Unbound.DNSSEC)
	assert.True(t, device.DNS.Unbound.DNSSECStripped)
	assert.True(t, device.DNS.DNSMasq.Enabled)
	require.Len(t, device.DNS.DNSMasq.Hosts, 1)
	assert.Equal(t, "server", device.DNS.DNSMasq.Hosts[0].Host)
}

func TestConverter_VLANs(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.VLANs.VLAN = []schema.VLAN{
		{If: "igb0", Tag: "100", Descr: "Guest VLAN", Vlanif: "igb0_vlan100"},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.VLANs, 1)
	assert.Equal(t, "igb0", device.VLANs[0].PhysicalIf)
	assert.Equal(t, "100", device.VLANs[0].Tag)
	assert.Equal(t, "Guest VLAN", device.VLANs[0].Description)
	assert.Equal(t, "igb0_vlan100", device.VLANs[0].VLANIf)
}

func TestConverter_Groups(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.Group = []schema.Group{
		{
			Name:        "admins",
			Description: "System Administrators",
			Scope:       "local",
			Gid:         "1999",
			Member:      "0",
			Priv:        "page-all",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.Groups, 1)
	assert.Equal(t, "admins", device.Groups[0].Name)
	assert.Equal(t, "1999", device.Groups[0].GID)
	assert.Equal(t, "page-all", device.Groups[0].Privileges)
}

func TestConverter_LoadBalancer(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.LoadBalancer.MonitorType = []schema.MonitorType{
		{
			Name:  "http_check",
			Type:  "http",
			Descr: "HTTP health check",
			Options: schema.Options{
				Path: "/health",
				Code: "200",
			},
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.LoadBalancer.MonitorTypes, 1)
	assert.Equal(t, "http_check", device.LoadBalancer.MonitorTypes[0].Name)
	assert.Equal(t, "/health", device.LoadBalancer.MonitorTypes[0].Options.Path)
	assert.Equal(t, "200", device.LoadBalancer.MonitorTypes[0].Options.Code)
}

func TestConverter_NTP(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Ntpd.Prefer = "0.opnsense.pool.ntp.org"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Equal(t, "0.opnsense.pool.ntp.org", device.NTP.PreferredServer)
}

func TestConverter_SNMP(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Snmpd.ROCommunity = "public"
	doc.Snmpd.SysLocation = "Server Room"
	doc.Snmpd.SysContact = "admin@example.com"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Equal(t, "public", device.SNMP.ROCommunity)
	assert.Equal(t, "Server Room", device.SNMP.SysLocation)
	assert.Equal(t, "admin@example.com", device.SNMP.SysContact)
}
