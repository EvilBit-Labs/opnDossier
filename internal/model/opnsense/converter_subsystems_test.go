package opnsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/opnsense"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_IPsec_FullMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OPNsense.IPsec = &schema.IPsec{}
	doc.OPNsense.IPsec.General.Enabled = "1"
	doc.OPNsense.IPsec.General.PreferredOldsa = "1"
	doc.OPNsense.IPsec.General.Disablevpnrules = "1"
	doc.OPNsense.IPsec.General.PassthroughNetworks = "10.0.0.0/8,172.16.0.0/12"
	doc.OPNsense.IPsec.KeyPairs = "kp-uuid-1"
	doc.OPNsense.IPsec.PreSharedKeys = "psk-uuid-1"
	doc.OPNsense.IPsec.Charon.Threads = "4"
	doc.OPNsense.IPsec.Charon.IkesaTableSize = "32"
	doc.OPNsense.IPsec.Charon.IkesaTableSegments = "4"
	doc.OPNsense.IPsec.Charon.MaxIkev1Exchanges = "3"
	doc.OPNsense.IPsec.Charon.InitLimitHalfOpen = "1000"
	doc.OPNsense.IPsec.Charon.IgnoreAcquireTs = "1"
	doc.OPNsense.IPsec.Charon.MakeBeforeBreak = "1"
	doc.OPNsense.IPsec.Charon.RetransmitTries = "5"
	doc.OPNsense.IPsec.Charon.RetransmitTimeout = "4.0"
	doc.OPNsense.IPsec.Charon.RetransmitBase = "1.8"
	doc.OPNsense.IPsec.Charon.RetransmitJitter = "20"
	doc.OPNsense.IPsec.Charon.RetransmitLimit = "60"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	ipsec := device.VPN.IPsec
	assert.True(t, ipsec.Enabled)
	assert.True(t, ipsec.PreferredOldSA)
	assert.True(t, ipsec.DisableVPNRules)
	assert.Equal(t, "10.0.0.0/8,172.16.0.0/12", ipsec.PassthroughNetworks)
	assert.Equal(t, "kp-uuid-1", ipsec.KeyPairs)
	assert.Equal(t, "psk-uuid-1", ipsec.PreSharedKeys)

	charon := ipsec.Charon
	assert.Equal(t, "4", charon.Threads)
	assert.Equal(t, "32", charon.IKEsaTableSize)
	assert.Equal(t, "4", charon.IKEsaTableSegments)
	assert.Equal(t, "3", charon.MaxIKEv1Exchanges)
	assert.Equal(t, "1000", charon.InitLimitHalfOpen)
	assert.True(t, charon.IgnoreAcquireTS)
	assert.True(t, charon.MakeBeforeBreak)
	assert.Equal(t, "5", charon.RetransmitTries)
	assert.Equal(t, "4.0", charon.RetransmitTimeout)
	assert.Equal(t, "1.8", charon.RetransmitBase)
	assert.Equal(t, "20", charon.RetransmitJitter)
	assert.Equal(t, "60", charon.RetransmitLimit)
}

func TestConverter_IPsec_NilReturnsZeroValue(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	// OPNsense.IPsec is nil by default

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.False(t, device.VPN.IPsec.Enabled)
}

func TestConverter_OpenVPNCSC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cscs    []schema.OpenVPNCSC
		wantLen int
	}{
		{
			name:    "empty CSCs returns nil",
			cscs:    nil,
			wantLen: 0,
		},
		{
			name: "single CSC",
			cscs: []schema.OpenVPNCSC{
				{Common_name: "user1"},
			},
			wantLen: 1,
		},
		{
			name: "multiple CSCs",
			cscs: []schema.OpenVPNCSC{
				{Common_name: "user1"},
				{Common_name: "user2"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.OpenVPN.CSC = tt.cscs

			device, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantLen == 0 {
				assert.Nil(t, device.VPN.OpenVPN.ClientSpecificConfigs)
				return
			}
			require.Len(t, device.VPN.OpenVPN.ClientSpecificConfigs, tt.wantLen)
		})
	}
}

func TestConverter_OpenVPNCSC_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.OpenVPN.CSC = []schema.OpenVPNCSC{
		{
			Common_name:      "admin-cert",
			Block:            schema.BoolFlag(true),
			Tunnel_network:   "10.8.1.0/24",
			Tunnel_networkv6: "fd00::1/64",
			Local_network:    "192.168.1.0/24",
			Local_networkv6:  "fd01::0/64",
			Remote_network:   "172.16.0.0/12",
			Remote_networkv6: "fd02::0/64",
			Gwredir:          schema.BoolFlag(true),
			Push_reset:       schema.BoolFlag(true),
			Remove_route:     schema.BoolFlag(true),
			DNS_domain:       "vpn.example.com",
			DNS_server1:      "10.8.0.1",
			DNS_server2:      "10.8.0.2",
			NTP_server1:      "10.8.0.3",
		},
	}

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, device.VPN.OpenVPN.ClientSpecificConfigs, 1)

	csc := device.VPN.OpenVPN.ClientSpecificConfigs[0]
	assert.Equal(t, "admin-cert", csc.CommonName)
	assert.True(t, csc.Block)
	assert.Equal(t, "10.8.1.0/24", csc.TunnelNetwork)
	assert.Equal(t, "fd00::1/64", csc.TunnelNetworkV6)
	assert.Equal(t, "192.168.1.0/24", csc.LocalNetwork)
	assert.Equal(t, "fd01::0/64", csc.LocalNetworkV6)
	assert.Equal(t, "172.16.0.0/12", csc.RemoteNetwork)
	assert.Equal(t, "fd02::0/64", csc.RemoteNetworkV6)
	assert.True(t, csc.GWRedir)
	assert.True(t, csc.PushReset)
	assert.True(t, csc.RemoveRoute)
	assert.Equal(t, "vpn.example.com", csc.DNSDomain)
	assert.Equal(t, []string{"10.8.0.1", "10.8.0.2"}, csc.DNSServers)
	assert.Equal(t, []string{"10.8.0.3"}, csc.NTPServers)
}

func TestConverter_Monit(t *testing.T) {
	t.Parallel()

	t.Run("nil monit returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.Monit)
	})

	t.Run("populated monit", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.Monit = &schema.Monit{}
		doc.OPNsense.Monit.General.Enabled = "1"
		doc.OPNsense.Monit.General.Interval = "120"
		doc.OPNsense.Monit.General.Startdelay = "60"
		doc.OPNsense.Monit.General.Mailserver = "smtp.example.com"
		doc.OPNsense.Monit.General.Port = "587"
		doc.OPNsense.Monit.General.Ssl = "1"
		doc.OPNsense.Monit.General.HttpdEnabled = "1"
		doc.OPNsense.Monit.General.HttpdPort = "2812"
		doc.OPNsense.Monit.General.MmonitURL = "https://mmonit.example.com"
		doc.OPNsense.Monit.Alert.Enabled = "1"
		doc.OPNsense.Monit.Alert.Recipient = "admin@example.com"
		doc.OPNsense.Monit.Service = []schema.MonitService{
			{UUID: "svc-1", Enabled: "1", Name: "sshd", Type: "3"},
		}
		doc.OPNsense.Monit.Test = []schema.MonitTest{
			{UUID: "test-1", Name: "Memory", Type: "ResourceTesting", Condition: "memory usage > 90%", Action: "alert"},
		}

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.Monit)

		m := device.Monit
		assert.True(t, m.Enabled)
		assert.Equal(t, "120", m.Interval)
		assert.Equal(t, "60", m.StartDelay)
		assert.Equal(t, "smtp.example.com", m.MailServer)
		assert.Equal(t, "587", m.MailPort)
		assert.True(t, m.SSLEnabled)
		assert.True(t, m.HTTPDEnabled)
		assert.Equal(t, "2812", m.HTTPDPort)
		assert.Equal(t, "https://mmonit.example.com", m.MMonitURL)

		require.NotNil(t, m.Alert)
		assert.True(t, m.Alert.Enabled)
		assert.Equal(t, "admin@example.com", m.Alert.Recipient)

		require.Len(t, m.Services, 1)
		assert.Equal(t, "svc-1", m.Services[0].UUID)
		assert.True(t, m.Services[0].Enabled)
		assert.Equal(t, "sshd", m.Services[0].Name)

		require.Len(t, m.Tests, 1)
		assert.Equal(t, "test-1", m.Tests[0].UUID)
		assert.Equal(t, "Memory", m.Tests[0].Name)
		assert.Equal(t, "memory usage > 90%", m.Tests[0].Condition)
		assert.Equal(t, "alert", m.Tests[0].Action)
	})
}

func TestConverter_Netflow(t *testing.T) {
	t.Parallel()

	t.Run("empty netflow returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.Netflow)
	})

	t.Run("populated netflow", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.Netflow.Capture.Interfaces = "lan,wan"
		doc.OPNsense.Netflow.Capture.Version = "9"
		doc.OPNsense.Netflow.Capture.EgressOnly = "1"
		doc.OPNsense.Netflow.Capture.Targets = "10.0.0.1:2055"
		doc.OPNsense.Netflow.Collect.Enable = "1"
		doc.OPNsense.Netflow.InactiveTimeout = "15"
		doc.OPNsense.Netflow.ActiveTimeout = "1800"

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.Netflow)

		nf := device.Netflow
		assert.Equal(t, "lan,wan", nf.CaptureInterfaces)
		assert.Equal(t, "9", nf.CaptureVersion)
		assert.True(t, nf.EgressOnly)
		assert.Equal(t, "10.0.0.1:2055", nf.CaptureTargets)
		assert.True(t, nf.CollectEnabled)
		assert.Equal(t, "15", nf.InactiveTimeout)
		assert.Equal(t, "1800", nf.ActiveTimeout)
	})
}

func TestConverter_TrafficShaper(t *testing.T) {
	t.Parallel()

	t.Run("empty shaper returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.TrafficShaper)
	})

	t.Run("populated shaper", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.TrafficShaper.Pipes = "pipe-uuid-1"
		doc.OPNsense.TrafficShaper.Queues = "queue-uuid-1"
		doc.OPNsense.TrafficShaper.Rules = "rule-uuid-1"

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.TrafficShaper)

		ts := device.TrafficShaper
		assert.Equal(t, "pipe-uuid-1", ts.Pipes)
		assert.Equal(t, "queue-uuid-1", ts.Queues)
		assert.Equal(t, "rule-uuid-1", ts.Rules)
	})
}

func TestConverter_CaptivePortal(t *testing.T) {
	t.Parallel()

	t.Run("empty captive portal returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.CaptivePortal)
	})

	t.Run("populated captive portal", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.Captiveportal.Zones = "zone-uuid-1"
		doc.OPNsense.Captiveportal.Templates = "tmpl-uuid-1"

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.CaptivePortal)

		cp := device.CaptivePortal
		assert.Equal(t, "zone-uuid-1", cp.Zones)
		assert.Equal(t, "tmpl-uuid-1", cp.Templates)
	})
}

func TestConverter_Cron(t *testing.T) {
	t.Parallel()

	t.Run("empty cron returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.Cron)
	})

	t.Run("populated cron", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.Cron.Jobs = "job-uuid-1,job-uuid-2"

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.Cron)

		assert.Equal(t, "job-uuid-1,job-uuid-2", device.Cron.Jobs)
	})
}

func TestConverter_Trust(t *testing.T) {
	t.Parallel()

	t.Run("default trust returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.Trust)
	})

	t.Run("populated trust", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.Trust.General.StoreIntermediateCerts = "1"
		doc.OPNsense.Trust.General.InstallCrls = "1"
		doc.OPNsense.Trust.General.FetchCrls = "1"
		doc.OPNsense.Trust.General.EnableLegacySect = "1"
		doc.OPNsense.Trust.General.EnableConfigConstraints = "1"
		doc.OPNsense.Trust.General.CipherString = "DEFAULT:!EXP:!LOW"
		doc.OPNsense.Trust.General.Ciphersuites = "TLS_AES_256_GCM_SHA384"
		doc.OPNsense.Trust.General.Groups = "X25519:P-256"
		doc.OPNsense.Trust.General.MinProtocol = "TLSv1.2"
		doc.OPNsense.Trust.General.MinProtocolDTLS = "DTLSv1.2"

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.Trust)

		tr := device.Trust
		assert.True(t, tr.StoreIntermediateCerts)
		assert.True(t, tr.InstallCRLs)
		assert.True(t, tr.FetchCRLs)
		assert.True(t, tr.EnableLegacySect)
		assert.True(t, tr.EnableConfigConstraints)
		assert.Equal(t, "DEFAULT:!EXP:!LOW", tr.CipherString)
		assert.Equal(t, "TLS_AES_256_GCM_SHA384", tr.Ciphersuites)
		assert.Equal(t, "X25519:P-256", tr.Groups)
		assert.Equal(t, "TLSv1.2", tr.MinProtocol)
		assert.Equal(t, "DTLSv1.2", tr.MinProtocolDTLS)
	})
}

func TestConverter_KeaDHCP(t *testing.T) {
	t.Parallel()

	t.Run("unconfigured kea returns nil", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		assert.Nil(t, device.KeaDHCP)
	})

	t.Run("populated kea", func(t *testing.T) {
		t.Parallel()

		doc := schema.NewOpnSenseDocument()
		doc.OPNsense.Kea.Dhcp4.General.Enabled = "1"
		doc.OPNsense.Kea.Dhcp4.General.Interfaces = "lan,opt1"
		doc.OPNsense.Kea.Dhcp4.General.FirewallRules = "1"
		doc.OPNsense.Kea.Dhcp4.General.ValidLifetime = "4000"
		doc.OPNsense.Kea.Dhcp4.HighAvailability.Enabled = "1"
		doc.OPNsense.Kea.Dhcp4.HighAvailability.ThisServerName = "primary"
		doc.OPNsense.Kea.Dhcp4.HighAvailability.MaxUnackedClients = "5"
		doc.OPNsense.Kea.Dhcp4.Subnets = "subnet-uuid-1"
		doc.OPNsense.Kea.Dhcp4.Reservations = "res-uuid-1"

		device, err := opnsense.NewConverter().ToCommonDevice(doc)
		require.NoError(t, err)
		require.NotNil(t, device.KeaDHCP)

		kea := device.KeaDHCP
		assert.True(t, kea.Enabled)
		assert.Equal(t, "lan,opt1", kea.Interfaces)
		assert.True(t, kea.FirewallRules)
		assert.Equal(t, "4000", kea.ValidLifetime)
		assert.True(t, kea.HA.Enabled)
		assert.Equal(t, "primary", kea.HA.ThisServerName)
		assert.Equal(t, "5", kea.HA.MaxUnackedClients)
		assert.Equal(t, "subnet-uuid-1", kea.Subnets)
		assert.Equal(t, "res-uuid-1", kea.Reservations)
	})
}

func TestConverter_Syslog_ExtendedCategories(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Syslog.Enable = schema.BoolFlag(true)
	doc.Syslog.Portalauth = schema.BoolFlag(true)
	doc.Syslog.DPinger = schema.BoolFlag(true)
	doc.Syslog.Hostapd = schema.BoolFlag(true)
	doc.Syslog.Resolver = schema.BoolFlag(true)
	doc.Syslog.PPP = schema.BoolFlag(true)
	doc.Syslog.IgmpProxy = schema.BoolFlag(true)

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	sl := device.Syslog
	assert.True(t, sl.Enabled)
	assert.True(t, sl.PortalAuthLogging)
	assert.True(t, sl.DPingerLogging)
	assert.True(t, sl.HostapdLogging)
	assert.True(t, sl.ResolverLogging)
	assert.True(t, sl.PPPLogging)
	assert.True(t, sl.IGMPProxyLogging)
}

func TestConverter_SSH_Expansion(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.SSH.Enabled = schema.BoolFlag(true)
	doc.System.SSH.Port = "2222"
	doc.System.SSH.Group = "wheel"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.True(t, device.System.SSH.Enabled)
	assert.Equal(t, "2222", device.System.SSH.Port)
	assert.Equal(t, "wheel", device.System.SSH.Group)
}

func TestConverter_WebGUI_Expansion(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.WebGUI.LoginAutocomplete = schema.BoolFlag(true)
	doc.System.WebGUI.MaxProcesses = "4"

	device, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)

	assert.True(t, device.System.WebGUI.LoginAutocomplete)
	assert.Equal(t, "4", device.System.WebGUI.MaxProcesses)
}
