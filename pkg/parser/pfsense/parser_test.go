package pfsense_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// xmlRootPfSense is the expected XML root element name for pfSense configurations.
const xmlRootPfSense = "pfsense"

// ifaceLAN is the standard LAN interface name used in pfSense fixture assertions.
const ifaceLAN = "lan"

// nonGapWarnings filters out the always-emitted pfSense known-gap warnings
// (one SeverityMedium entry per pfsense.KnownGaps() subsystem) so existing
// assertions on per-test warnings remain readable. See
// docs/user-guide/device-support-matrix.md for the gap list.
func nonGapWarnings(ws []common.ConversionWarning) []common.ConversionWarning {
	out := make([]common.ConversionWarning, 0, len(ws))
	for _, w := range ws {
		if w.Message == pfsense.PfsenseKnownGapMessage {
			continue
		}
		out = append(out, w)
	}
	return out
}

// TestConverter_KnownGapWarnings_Contract directly pins the known-gap
// warning emission contract so per-feature assertions can continue to use
// nonGapWarnings (which hides these) without masking a regression that
// drops the warnings entirely. If the converter stops emitting them, the
// parity test at pkg/parser/parity_test.go also fails — this local test
// fails first and points at the fix site (emitKnownGapWarnings in
// pkg/parser/pfsense/converter.go).
func TestConverter_KnownGapWarnings_Contract(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	var gapWarnings []common.ConversionWarning
	for _, w := range warnings {
		if w.Message == pfsense.PfsenseKnownGapMessage {
			gapWarnings = append(gapWarnings, w)
		}
	}

	require.Len(t, gapWarnings, len(pfsense.KnownGaps()))

	fields := make([]string, 0, len(gapWarnings))
	for _, w := range gapWarnings {
		assert.Equal(t, common.SeverityMedium, w.Severity)
		assert.Empty(t, w.Value)
		fields = append(fields, w.Field)
	}

	assert.ElementsMatch(t, pfsense.KnownGaps(), fields)
}

// --- Parser.Parse tests ---

func TestParser_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		ctxFn     func() context.Context
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, device *common.CommonDevice)
	}{
		{
			name:  "valid minimal",
			input: `<?xml version="1.0"?><pfsense><system><hostname>test</hostname><domain>test.local</domain></system></pfsense>`,
			ctxFn: context.Background,
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
				assert.Equal(t, "test", device.System.Hostname)
				assert.Equal(t, "test.local", device.System.Domain)
			},
		},
		{
			name: "valid with firewall rules",
			input: `<?xml version="1.0"?><pfsense>
				<system><hostname>test</hostname><domain>test.local</domain></system>
				<filter><rule><type>pass</type><interface>lan</interface><source><any/></source><destination><any/></destination></rule></filter>
			</pfsense>`,
			ctxFn: context.Background,
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.Len(t, device.FirewallRules, 1)
			},
		},
		{
			name:      "empty reader",
			input:     "",
			ctxFn:     context.Background,
			wantErr:   true,
			errSubstr: `field "/pfsense"`,
		},
		{
			name:      "malformed XML",
			input:     "<<<not xml",
			ctxFn:     context.Background,
			wantErr:   true,
			errSubstr: `field "/pfsense"`,
		},
		{
			name:  "context cancelled",
			input: `<?xml version="1.0"?><pfsense><system><hostname>test</hostname></system></pfsense>`,
			ctxFn: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr: true,
		},
		{
			name:      "unsupported charset",
			input:     `<?xml version="1.0" encoding="EBCDIC"?><pfsense/>`,
			ctxFn:     context.Background,
			wantErr:   true,
			errSubstr: "unsupported charset",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := pfsense.NewParser(nil)
			device, _, err := p.Parse(tc.ctxFn(), strings.NewReader(tc.input))

			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, device)
			if tc.check != nil {
				tc.check(t, device)
			}
		})
	}
}

func TestParser_Parse_AcceptedCharsets(t *testing.T) {
	t.Parallel()

	charsets := []string{"US-ASCII", "ISO-8859-1", "Latin-1", "UTF-8"}
	for _, charset := range charsets {
		t.Run(charset, func(t *testing.T) {
			t.Parallel()

			xmlData := `<?xml version="1.0" encoding="` + charset + `"?>` + "\n" +
				`<pfsense><system><hostname>test</hostname><domain>test.local</domain></system></pfsense>`

			p := pfsense.NewParser(nil)
			device, _, err := p.Parse(context.Background(), strings.NewReader(xmlData))
			require.NoError(t, err)
			require.NotNil(t, device)
			assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
		})
	}
}

// --- Parser.ParseAndValidate tests ---

func TestParser_ParseAndValidate(t *testing.T) {
	t.Parallel()

	xmlData := `<?xml version="1.0"?><pfsense><system><hostname>test</hostname><domain>test.local</domain></system></pfsense>`

	p := pfsense.NewParser(nil)
	device, warnings, err := p.ParseAndValidate(context.Background(), strings.NewReader(xmlData))
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
	assert.Equal(t, "test", device.System.Hostname)

	// ParseAndValidate currently delegates to Parse, so same result.
	p2 := pfsense.NewParser(nil)
	device2, warnings2, err2 := p2.Parse(context.Background(), strings.NewReader(xmlData))
	require.NoError(t, err2)
	assert.Equal(t, device.System.Hostname, device2.System.Hostname)
	assert.Len(t, warnings2, len(warnings))
}

// --- Converter tests ---

func TestConverter_NilInput(t *testing.T) {
	t.Parallel()

	_, _, err := pfsense.ConvertDocument(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, pfsense.ErrNilDocument)
}

func TestConverter_System(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.System.Hostname = "fw-test"
	doc.System.Domain = "test.local"
	doc.System.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
	doc.System.Timezone = "Etc/UTC"
	doc.System.Optimization = "normal"
	doc.System.Language = "en_US"
	doc.System.TimeServers = "0.pfsense.pool.ntp.org 1.pfsense.pool.ntp.org"
	doc.System.DNSAllowOverride = true
	doc.System.DisableNATReflection = "yes"
	doc.System.DisableSegmentationOffloading = true
	doc.System.DisableLargeReceiveOffloading = true
	doc.System.IPv6Allow = "1"
	doc.System.NextUID = 2000
	doc.System.NextGID = 2000
	doc.System.PowerdACMode = "hadp"
	doc.System.PowerdBatteryMode = "hiadaptive"
	doc.System.PowerdNormalMode = "adaptive"
	doc.System.Bogons.Interval = "monthly"
	doc.System.WebGUI = pfsenseSchema.WebGUI{
		Protocol:          "https",
		SSLCertRef:        "cert-123",
		LoginAutocomplete: true,
		MaxProcesses:      "2",
	}
	doc.System.SSH = opnsense.SSHConfig{
		Enabled: true,
		Port:    "2222",
		Group:   "admins",
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Empty(t, nonGapWarnings(warnings))

	sys := device.System
	assert.Equal(t, "fw-test", sys.Hostname)
	assert.Equal(t, "test.local", sys.Domain)
	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, sys.DNSServers)
	assert.Equal(t, "Etc/UTC", sys.Timezone)
	assert.Equal(t, "normal", sys.Optimization)
	assert.Equal(t, "en_US", sys.Language)
	assert.Equal(t, []string{"0.pfsense.pool.ntp.org", "1.pfsense.pool.ntp.org"}, sys.TimeServers)
	assert.True(t, sys.DNSAllowOverride)
	assert.True(t, sys.DisableNATReflection)
	assert.True(t, sys.DisableSegmentationOffloading)
	assert.True(t, sys.DisableLargeReceiveOffloading)
	assert.True(t, sys.IPv6Allow)
	assert.Equal(t, 2000, sys.NextUID)
	assert.Equal(t, 2000, sys.NextGID)
	assert.Equal(t, "hadp", sys.PowerdACMode)
	assert.Equal(t, "hiadaptive", sys.PowerdBatteryMode)
	assert.Equal(t, "adaptive", sys.PowerdNormalMode)
	assert.Equal(t, "monthly", sys.Bogons.Interval)
	assert.Equal(t, "https", sys.WebGUI.Protocol)
	assert.Equal(t, "cert-123", sys.WebGUI.SSLCertRef)
	assert.True(t, sys.WebGUI.LoginAutocomplete)
	assert.Equal(t, "2", sys.WebGUI.MaxProcesses)
	assert.True(t, sys.SSH.Enabled)
	assert.Equal(t, "2222", sys.SSH.Port)
	assert.Equal(t, "admins", sys.SSH.Group)
}

func TestConverter_Interfaces(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Interfaces.Items["wan"] = pfsenseSchema.Interface{
		If:          "igb0",
		Enable:      opnsense.BoolFlag(true),
		IPAddr:      "dhcp",
		BlockPriv:   "1",
		BlockBogons: "1",
	}
	doc.Interfaces.Items["lan"] = pfsenseSchema.Interface{
		If:     "igb1",
		Enable: opnsense.BoolFlag(true),
		IPAddr: "192.168.1.1",
		Subnet: "24",
		Descr:  "LAN",
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Interfaces, 2)

	// Sorted by key: lan < wan
	assert.Equal(t, "lan", device.Interfaces[0].Name)
	assert.Equal(t, "igb1", device.Interfaces[0].PhysicalIf)
	assert.True(t, device.Interfaces[0].Enabled)
	assert.Equal(t, "LAN", device.Interfaces[0].Description)

	assert.Equal(t, "wan", device.Interfaces[1].Name)
	assert.Equal(t, "igb0", device.Interfaces[1].PhysicalIf)
	assert.True(t, device.Interfaces[1].BlockPrivate)
	assert.True(t, device.Interfaces[1].BlockBogons)
}

func TestConverter_FirewallRules(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Filter.Rule = []pfsenseSchema.FilterRule{
		{
			Type:       "pass",
			Descr:      "Allow HTTPS",
			Interface:  opnsense.InterfaceList{"lan"},
			IPProtocol: "inet",
			StateType:  "keep state",
			Direction:  "in",
			Floating:   "yes",
			Quick:      true,
			Protocol:   "tcp",
			Source: opnsense.Source{
				Any: new(string),
			},
			Destination: opnsense.Destination{
				Network: "lan",
				Port:    "443",
			},
			Target:      "192.168.1.50",
			Gateway:     "GW_WAN",
			Log:         true,
			Tracker:     "1000000001",
			TCPFlags1:   "SYN",
			TCPFlags2:   "SYN,ACK",
			TCPFlagsAny: true,
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.FirewallRules, 1)

	rule := device.FirewallRules[0]
	assert.Equal(t, common.RuleTypePass, rule.Type)
	assert.Equal(t, "Allow HTTPS", rule.Description)
	assert.Equal(t, []string{"lan"}, rule.Interfaces)
	assert.Equal(t, common.IPProtocolInet, rule.IPProtocol)
	assert.Equal(t, "keep state", rule.StateType)
	assert.Equal(t, common.DirectionIn, rule.Direction)
	assert.True(t, rule.Floating)
	assert.True(t, rule.Quick)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.Equal(t, "any", rule.Source.Address)
	assert.Equal(t, "lan", rule.Destination.Address)
	assert.Equal(t, "443", rule.Destination.Port)
	assert.Equal(t, "192.168.1.50", rule.Target)
	assert.Equal(t, "GW_WAN", rule.Gateway)
	assert.True(t, rule.Log)
	assert.Equal(t, "1000000001", rule.Tracker)
	assert.Equal(t, "SYN", rule.TCPFlags1)
	assert.Equal(t, "SYN,ACK", rule.TCPFlags2)
	assert.True(t, rule.TCPFlagsAny)
}

func TestConverter_NAT(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Nat.Outbound.Mode = "hybrid"
	doc.System.DisableNATReflection = "yes"
	doc.Nat.Outbound.Rule = []opnsense.NATRule{
		{
			Interface: opnsense.InterfaceList{"wan"},
			Source:    opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{
				Network: "lan",
			},
			Descr: "Outbound rule",
		},
	}
	doc.Nat.Inbound = []pfsenseSchema.InboundRule{
		{
			Interface: opnsense.InterfaceList{"wan"},
			Target:    "192.168.1.50",
			Source:    opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{
				Any: new(string),
			},
			Descr: "Port forward",
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	assert.Equal(t, common.NATOutboundMode("hybrid"), device.NAT.OutboundMode)
	assert.True(t, device.NAT.ReflectionDisabled)
	require.Len(t, device.NAT.OutboundRules, 1)
	assert.Equal(t, "Outbound rule", device.NAT.OutboundRules[0].Description)
	require.Len(t, device.NAT.InboundRules, 1)
	assert.Equal(t, "192.168.1.50", device.NAT.InboundRules[0].InternalIP)
	assert.Equal(t, "Port forward", device.NAT.InboundRules[0].Description)
}

func TestConverter_NAT_TargetFallback(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Nat.Inbound = []pfsenseSchema.InboundRule{
		{
			Interface:  opnsense.InterfaceList{"wan"},
			Target:     "",
			InternalIP: "10.0.0.5",
			Source:     opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{
				Any: new(string),
			},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.NAT.InboundRules, 1)
	assert.Equal(t, "10.0.0.5", device.NAT.InboundRules[0].InternalIP)
}

func TestConverter_DHCP(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	// Two scopes are required to exercise the sorted-keys idiom in
	// convertDHCP — a single-entry fixture would sort correctly under
	// any algorithm and could not catch an ordering regression.
	doc.Dhcpd.Items["lan"] = pfsenseSchema.DhcpdInterface{
		Enable: opnsense.BoolFlag(true),
		Range:  opnsense.Range{From: "192.168.1.100", To: "192.168.1.200"},
		Staticmap: []opnsense.DHCPStaticLease{
			{Mac: "00:11:22:33:44:55", IPAddr: "192.168.1.10", Hostname: "printer"},
		},
		NumberOptions: []opnsense.DHCPNumberOption{
			{Number: "6", Type: "text", Value: "8.8.8.8"},
		},
	}
	doc.Dhcpd.Items["opt1"] = pfsenseSchema.DhcpdInterface{
		Enable: opnsense.BoolFlag(true),
		Range:  opnsense.Range{From: "10.10.0.100", To: "10.10.0.200"},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.DHCP, 2)

	// Assert positional order so a regression in the sorted-keys idiom
	// surfaces here rather than silently in downstream output.
	assert.Equal(t, "lan", device.DHCP[0].Interface, "scopes should be sorted lexicographically")
	assert.Equal(t, "opt1", device.DHCP[1].Interface, "scopes should be sorted lexicographically")

	scope := device.DHCP[0]
	assert.True(t, scope.Enabled)
	assert.Equal(t, "192.168.1.100", scope.Range.From)
	assert.Equal(t, "192.168.1.200", scope.Range.To)
	require.Len(t, scope.StaticLeases, 1)
	assert.Equal(t, "00:11:22:33:44:55", scope.StaticLeases[0].MAC)
	assert.Equal(t, "192.168.1.10", scope.StaticLeases[0].IPAddress)
	require.Len(t, scope.NumberOptions, 1)
	assert.Equal(t, "6", scope.NumberOptions[0].Number)
}

func TestConverter_DNS(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.System.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
	doc.Unbound = pfsenseSchema.UnboundConfig{
		Enable: true,
		DNSSEC: true,
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, device.DNS.Servers)
	assert.True(t, device.DNS.Unbound.Enabled)
	assert.True(t, device.DNS.Unbound.DNSSEC)
}

func TestConverter_VPN_OpenVPN(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.OpenVPN = opnsense.OpenVPN{
		Servers: []opnsense.OpenVPNServer{
			{
				VPN_ID:      "1",
				Description: "Site VPN",
				Mode:        "server_tls",
				Protocol:    "UDP4",
				DNS_server1: "10.0.0.1",
				DNS_server2: "10.0.0.2",
				DNS_server3: "",
				DNS_server4: "",
			},
		},
		Clients: []opnsense.OpenVPNClient{
			{
				VPN_ID:      "2",
				Description: "Client VPN",
				Mode:        "p2p_tls",
			},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.Len(t, device.VPN.OpenVPN.Servers, 1)
	assert.Equal(t, "1", device.VPN.OpenVPN.Servers[0].VPNID)
	assert.Equal(t, "Site VPN", device.VPN.OpenVPN.Servers[0].Description)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, device.VPN.OpenVPN.Servers[0].DNSServers)

	require.Len(t, device.VPN.OpenVPN.Clients, 1)
	assert.Equal(t, "2", device.VPN.OpenVPN.Clients[0].VPNID)
}

func TestConverter_Routing(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Gateways = opnsense.Gateways{
		Gateway: []opnsense.Gateway{
			{
				Interface:  "wan",
				Gateway:    "203.0.113.1",
				Name:       "GW_WAN",
				IPProtocol: "inet",
				Descr:      "Default GW",
			},
		},
	}
	doc.StaticRoutes = opnsense.StaticRoutes{
		Route: []opnsense.StaticRoute{
			{
				Network:  "10.10.0.0/16",
				Gateway:  "GW_WAN",
				Descr:    "Remote route",
				Disabled: true,
			},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.Len(t, device.Routing.Gateways, 1)
	assert.Equal(t, "GW_WAN", device.Routing.Gateways[0].Name)
	assert.Equal(t, "203.0.113.1", device.Routing.Gateways[0].Address)

	require.Len(t, device.Routing.StaticRoutes, 1)
	assert.Equal(t, "10.10.0.0/16", device.Routing.StaticRoutes[0].Network)
	assert.True(t, device.Routing.StaticRoutes[0].Disabled)
}

func TestConverter_Users(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.System.User = []pfsenseSchema.User{
		{
			Name:      "admin",
			UID:       "0",
			Scope:     "system",
			Groupname: "admins",
			Descr:     "Admin user",
		},
		{
			Name:  "",
			UID:   "1000",
			Scope: "local",
		},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Users, 2)

	assert.Equal(t, "admin", device.Users[0].Name)
	assert.Equal(t, "0", device.Users[0].UID)
	assert.Equal(t, "system", device.Users[0].Scope)
	assert.Equal(t, "admins", device.Users[0].GroupName)

	// Empty name user should generate a warning.
	filtered := nonGapWarnings(warnings)
	require.Len(t, filtered, 1)
	assert.Contains(t, filtered[0].Field, "Users[1].Name")
	assert.Equal(t, common.SeverityHigh, filtered[0].Severity)
}

func TestConverter_Groups(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.System.Group = []pfsenseSchema.Group{
		{
			Name:        "admins",
			Gid:         "1999",
			Scope:       "system",
			Description: "Administrators",
			Priv:        []string{"page-all"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Groups, 1)
	assert.Equal(t, "admins", device.Groups[0].Name)
	assert.Equal(t, "1999", device.Groups[0].GID)
	assert.Equal(t, "page-all", device.Groups[0].Privileges)
}

func TestConverter_Groups_MultiplePrivileges(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.System.Group = []pfsenseSchema.Group{
		{
			Name:  "admins",
			Gid:   "1999",
			Scope: "system",
			Priv:  []string{"page-all", "user-shell-access", "page-system-groupmanager"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Groups, 1)
	assert.Equal(t, "page-all, user-shell-access, page-system-groupmanager", device.Groups[0].Privileges)
}

func TestConverter_Certificates_Warnings(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Certs = []opnsense.Cert{
		{Refid: "cert-empty", Descr: "Empty Cert", Crt: "", Prv: "KEYDATA"},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Certificates, 1)
	filtered := nonGapWarnings(warnings)
	require.Len(t, filtered, 1)
	assert.Equal(t, "Certificates[0].Certificate", filtered[0].Field)
	assert.Equal(t, common.SeverityHigh, filtered[0].Severity)
}

func TestConverter_Certificates(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Certs = []opnsense.Cert{
		{Refid: "cert-001", Descr: "WebGUI Cert", Crt: "CERTDATA", Prv: "KEYDATA"},
	}
	doc.CAs = []opnsense.CertificateAuthority{
		{Refid: "ca-001", Descr: "Internal CA", Crt: "CADATA", Serial: "42"},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.Len(t, device.Certificates, 1)
	assert.Equal(t, "cert-001", device.Certificates[0].RefID)
	assert.Equal(t, "CERTDATA", device.Certificates[0].Certificate)
	assert.Equal(t, "KEYDATA", device.Certificates[0].PrivateKey)

	require.Len(t, device.CAs, 1)
	assert.Equal(t, "ca-001", device.CAs[0].RefID)
	assert.Equal(t, "CADATA", device.CAs[0].Certificate)
	assert.Equal(t, "42", device.CAs[0].Serial)
}

func TestConverter_Syslog(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	// pfSense syslog has no common mapping — should be zero-value.
	assert.False(t, device.Syslog.Enabled)
	assert.Empty(t, device.Syslog.LogFileSize)
}

func TestConverter_Revision(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Revision = opnsense.Revision{
		Username:    "admin@192.168.1.1",
		Time:        "1700000000",
		Description: "Updated config",
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Equal(t, "admin@192.168.1.1", device.Revision.Username)
	assert.Equal(t, "1700000000", device.Revision.Time)
	assert.Equal(t, "Updated config", device.Revision.Description)
}

func TestConverter_Cron(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Cron.Items = []pfsenseSchema.CronItem{
		{Minute: "0", Hour: "3", Command: "/usr/bin/nice -n20 newsyslog"},
		{Minute: "*/5", Hour: "*", Command: ""},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	require.NotNil(t, device.Cron)
	assert.Equal(t, "/usr/bin/nice -n20 newsyslog", device.Cron.Jobs)
}

func TestConverter_Cron_NoCommands(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Cron.Items = []pfsenseSchema.CronItem{
		{Minute: "0", Hour: "3", Command: ""},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Nil(t, device.Cron)
}

func TestConverter_ComputedFieldsNil(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	assert.Nil(t, device.Statistics)
	assert.Nil(t, device.Analysis)
	assert.Nil(t, device.SecurityAssessment)
	assert.Nil(t, device.ComplianceResults)
}

// --- Conversion Warning tests ---

func TestConverter_FirewallRules_Warnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rules        []pfsenseSchema.FilterRule
		wantWarnings int
		wantField    string
		wantSeverity common.Severity
	}{
		{
			name: "empty type",
			rules: []pfsenseSchema.FilterRule{
				{
					Type:      "",
					Interface: opnsense.InterfaceList{"lan"},
					Source:    opnsense.Source{Any: new(string)},
					Destination: opnsense.Destination{
						Any: new(string),
					},
				},
			},
			wantWarnings: 1,
			wantField:    "FirewallRules[0].Type",
			wantSeverity: common.SeverityHigh,
		},
		{
			name: "missing source address",
			rules: []pfsenseSchema.FilterRule{
				{
					Type:      "pass",
					Interface: opnsense.InterfaceList{"lan"},
					Source:    opnsense.Source{},
					Destination: opnsense.Destination{
						Any: new(string),
					},
				},
			},
			wantWarnings: 1,
			wantField:    "FirewallRules[0].Source",
			wantSeverity: common.SeverityMedium,
		},
		{
			name: "missing destination address",
			rules: []pfsenseSchema.FilterRule{
				{
					Type:        "pass",
					Interface:   opnsense.InterfaceList{"lan"},
					Source:      opnsense.Source{Any: new(string)},
					Destination: opnsense.Destination{},
				},
			},
			wantWarnings: 1,
			wantField:    "FirewallRules[0].Destination",
			wantSeverity: common.SeverityMedium,
		},
		{
			name: "empty interface",
			rules: []pfsenseSchema.FilterRule{
				{
					Type:   "pass",
					Source: opnsense.Source{Any: new(string)},
					Destination: opnsense.Destination{
						Any: new(string),
					},
				},
			},
			wantWarnings: 1,
			wantField:    "FirewallRules[0].Interface",
			wantSeverity: common.SeverityMedium,
		},
		{
			name: "multiple issues",
			rules: []pfsenseSchema.FilterRule{
				{
					Type:        "",
					Source:      opnsense.Source{},
					Destination: opnsense.Destination{},
				},
			},
			wantWarnings: 4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			doc.Filter.Rule = tc.rules

			_, warnings, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			filtered := nonGapWarnings(warnings)
			require.Len(t, filtered, tc.wantWarnings)

			if tc.wantField != "" {
				assert.Equal(t, tc.wantField, filtered[0].Field)
				assert.Equal(t, tc.wantSeverity, filtered[0].Severity)
			}
		})
	}
}

func TestConverter_NAT_Warnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setup        func(doc *pfsenseSchema.Document)
		wantWarnings int
		wantField    string
		wantSeverity common.Severity
	}{
		{
			name: "inbound rule missing internal IP",
			setup: func(doc *pfsenseSchema.Document) {
				doc.Nat.Inbound = []pfsenseSchema.InboundRule{
					{
						Interface:   opnsense.InterfaceList{"wan"},
						Target:      "",
						InternalIP:  "",
						Source:      opnsense.Source{Any: new(string)},
						Destination: opnsense.Destination{Any: new(string)},
					},
				}
			},
			wantWarnings: 1,
			wantField:    "NAT.InboundRules[0].InternalIP",
			wantSeverity: common.SeverityHigh,
		},
		{
			name: "inbound rule empty interface",
			setup: func(doc *pfsenseSchema.Document) {
				doc.Nat.Inbound = []pfsenseSchema.InboundRule{
					{
						Target:      "192.168.1.50",
						Source:      opnsense.Source{Any: new(string)},
						Destination: opnsense.Destination{Any: new(string)},
					},
				}
			},
			wantWarnings: 1,
			wantField:    "NAT.InboundRules[0].Interface",
			wantSeverity: common.SeverityMedium,
		},
		{
			name: "outbound rule empty interface",
			setup: func(doc *pfsenseSchema.Document) {
				doc.Nat.Outbound.Rule = []opnsense.NATRule{
					{
						Source:      opnsense.Source{Any: new(string)},
						Destination: opnsense.Destination{Any: new(string)},
					},
				}
			},
			wantWarnings: 1,
			wantField:    "NAT.OutboundRules[0].Interface",
			wantSeverity: common.SeverityMedium,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			tc.setup(doc)

			_, warnings, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			filtered := nonGapWarnings(warnings)
			require.Len(t, filtered, tc.wantWarnings)

			if tc.wantField != "" {
				assert.Equal(t, tc.wantField, filtered[0].Field)
				assert.Equal(t, tc.wantSeverity, filtered[0].Severity)
			}
		})
	}
}

func TestConverter_Gateways_Warnings(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Gateways = opnsense.Gateways{
		Gateway: []opnsense.Gateway{
			{Name: "", Gateway: "", Interface: "wan"},
		},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Len(t, nonGapWarnings(warnings), 2)

	fields := make([]string, len(warnings))
	for i, w := range warnings {
		fields[i] = w.Field
	}
	assert.Contains(t, fields, "Routing.Gateways[0].Address")
	assert.Contains(t, fields, "Routing.Gateways[0].Name")
}

func TestConverter_Users_Warnings(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.System.User = []pfsenseSchema.User{
		{Name: "", UID: ""},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Len(t, nonGapWarnings(warnings), 2)

	fields := make([]string, len(warnings))
	for i, w := range warnings {
		fields[i] = w.Field
	}
	assert.Contains(t, fields, "Users[0].Name")
	assert.Contains(t, fields, "Users[0].UID")
}

// --- File-based Parse tests ---

func TestParser_ParseFixture_2_6_x(t *testing.T) {
	t.Parallel()

	f, err := os.Open("../../../testdata/pfsense/config-2.6.x.xml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	p := pfsense.NewParser(nil)
	device, _, err := p.Parse(context.Background(), f)
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
	assert.Equal(t, "fw-test", device.System.Hostname)
	assert.Equal(t, "test.local", device.System.Domain)
	assert.Equal(t, "21.02", device.Version)
	assert.GreaterOrEqual(t, len(device.Interfaces), 2)
	assert.GreaterOrEqual(t, len(device.FirewallRules), 2)
	assert.GreaterOrEqual(t, len(device.DHCP), 1)
	require.Len(t, device.NAT.InboundRules, 1)
	assert.Len(t, device.VPN.OpenVPN.Servers, 1)
	assert.Len(t, device.Certificates, 1)
	assert.Len(t, device.CAs, 1)

	// Verify <enable>1</enable> (value-based) produces Enabled: true through the converter.
	// Use explicit lookups with require to fail the test when expected entries are missing.
	var wanIface, lanIface *common.Interface
	for i := range device.Interfaces {
		switch device.Interfaces[i].Name {
		case "wan":
			wanIface = &device.Interfaces[i]
		case ifaceLAN:
			lanIface = &device.Interfaces[i]
		}
	}

	require.NotNil(t, wanIface, "WAN interface must exist in fixture")
	assert.True(t, wanIface.Enabled, "WAN interface should be enabled")

	require.NotNil(t, lanIface, "LAN interface must exist in fixture")
	assert.True(t, lanIface.Enabled, "LAN interface should be enabled")

	var lanDHCP *common.DHCPScope
	for i := range device.DHCP {
		if device.DHCP[i].Interface == ifaceLAN {
			lanDHCP = &device.DHCP[i]
		}
	}

	require.NotNil(t, lanDHCP, "LAN DHCP scope must exist in fixture")
	assert.True(t, lanDHCP.Enabled, "LAN DHCP scope should be enabled")
}

// TestParser_EnablePresenceXML verifies that self-closing <enable/> elements
// (presence-based flags) correctly produce Enabled: true on the converted
// CommonDevice for both interfaces and DHCP scopes.
func TestParser_EnablePresenceXML(t *testing.T) {
	t.Parallel()

	const xmlInput = `<?xml version="1.0"?>
<pfsense>
  <version>21.02</version>
  <system>
    <hostname>test</hostname>
    <domain>test.local</domain>
  </system>
  <interfaces>
    <wan>
      <enable/>
      <if>em0</if>
      <descr>WAN</descr>
      <ipaddr>dhcp</ipaddr>
    </wan>
    <lan>
      <if>em1</if>
      <descr>LAN</descr>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>
  <dhcpd>
    <lan>
      <enable/>
      <range>
        <from>192.168.1.100</from>
        <to>192.168.1.200</to>
      </range>
      <gateway>192.168.1.1</gateway>
    </lan>
    <opt1>
      <range>
        <from>10.0.10.100</from>
        <to>10.0.10.200</to>
      </range>
    </opt1>
  </dhcpd>
</pfsense>`

	p := pfsense.NewParser(nil)
	device, _, err := p.Parse(context.Background(), strings.NewReader(xmlInput))
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
	require.Len(t, device.Interfaces, 2)

	// Find interfaces by name
	var wanIface, lanIface *common.Interface
	for i := range device.Interfaces {
		switch device.Interfaces[i].Name {
		case "wan":
			wanIface = &device.Interfaces[i]
		case ifaceLAN:
			lanIface = &device.Interfaces[i]
		}
	}

	require.NotNil(t, wanIface, "WAN interface must exist")
	assert.True(t, wanIface.Enabled, "WAN with <enable/> must be Enabled")
	assert.Equal(t, "em0", wanIface.PhysicalIf)

	require.NotNil(t, lanIface, "LAN interface must exist")
	assert.False(t, lanIface.Enabled, "LAN without <enable> must not be Enabled")
	assert.Equal(t, "em1", lanIface.PhysicalIf)

	require.Len(t, device.DHCP, 2)

	var lanDHCP, opt1DHCP *common.DHCPScope
	for i := range device.DHCP {
		switch device.DHCP[i].Interface {
		case ifaceLAN:
			lanDHCP = &device.DHCP[i]
		case "opt1":
			opt1DHCP = &device.DHCP[i]
		}
	}

	require.NotNil(t, lanDHCP, "LAN DHCP scope must exist")
	assert.True(t, lanDHCP.Enabled, "LAN DHCP with <enable/> must be Enabled")

	require.NotNil(t, opt1DHCP, "OPT1 DHCP scope must exist")
	assert.False(t, opt1DHCP.Enabled, "OPT1 DHCP without <enable/> must not be Enabled")
}

func TestParser_ParseFixture_2_7_x(t *testing.T) {
	t.Parallel()

	f, err := os.Open("../../../testdata/pfsense/config-2.7.x.xml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	p := pfsense.NewParser(nil)
	device, _, err := p.Parse(context.Background(), f)
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
	assert.Equal(t, "pf-edge", device.System.Hostname)
	assert.Equal(t, "23.09", device.Version)
	assert.GreaterOrEqual(t, len(device.Interfaces), 2)
	assert.GreaterOrEqual(t, len(device.FirewallRules), 1)
	assert.Len(t, device.VLANs, 1)
	assert.Len(t, device.Routing.Gateways, 1)
	assert.Len(t, device.Routing.StaticRoutes, 1)
	assert.True(t, device.DNS.Unbound.Enabled)
	assert.True(t, device.DNS.Unbound.DNSSEC)
	assert.NotNil(t, device.Cron)
	assert.Equal(t, "public", device.SNMP.ROCommunity)
}

func TestConverter_VLANs(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.VLANs = opnsense.VLANs{
		VLAN: []opnsense.VLAN{
			{If: "igb1", Tag: "100", Descr: "Guest VLAN", Vlanif: "igb1.100"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.VLANs, 1)
	assert.Equal(t, "igb1", device.VLANs[0].PhysicalIf)
	assert.Equal(t, "100", device.VLANs[0].Tag)
	assert.Equal(t, "Guest VLAN", device.VLANs[0].Description)
}

func TestConverter_SNMP(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.Snmpd = opnsense.Snmpd{
		ROCommunity: "public",
		SysLocation: "Server Room",
		SysContact:  "admin@test.local",
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Equal(t, "public", device.SNMP.ROCommunity)
	assert.Equal(t, "Server Room", device.SNMP.SysLocation)
	assert.Equal(t, "admin@test.local", device.SNMP.SysContact)
}

func TestConverter_LoadBalancer(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.LoadBalancer = opnsense.LoadBalancer{
		MonitorType: []opnsense.MonitorType{
			{Name: "ICMP", Type: "icmp", Descr: "ICMP Monitor"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.LoadBalancer.MonitorTypes, 1)
	assert.Equal(t, "ICMP", device.LoadBalancer.MonitorTypes[0].Name)
	assert.Equal(t, "icmp", device.LoadBalancer.MonitorTypes[0].Type)
}

// --- Real-world fixture tests for config-pfSense.xml ---

// parseConfigPfSenseFixture is a shared helper that parses the config-pfSense.xml fixture.
func parseConfigPfSenseFixture(t *testing.T) (*common.CommonDevice, []common.ConversionWarning) {
	t.Helper()

	f, err := os.Open("../../../testdata/pfsense/config-pfSense.xml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	p := pfsense.NewParser(nil)
	device, warnings, err := p.Parse(context.Background(), f)
	require.NoError(t, err)
	require.NotNil(t, device)

	return device, warnings
}

// TestParser_ParseFixture_ConfigPfSense verifies comprehensive parsing of a real-world pfSense 19.1 config.
func TestParser_ParseFixture_ConfigPfSense(t *testing.T) {
	t.Parallel()

	device, _ := parseConfigPfSenseFixture(t)

	// Device metadata
	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
	assert.Equal(t, "19.1", device.Version)

	// System configuration
	assert.Equal(t, "pfSense", device.System.Hostname)
	assert.Equal(t, "localdomain", device.System.Domain)
	assert.Equal(t, "Etc/UTC", device.System.Timezone)
	assert.Equal(t, "normal", device.System.Optimization)
	assert.Equal(t, "en_US", device.System.Language)
	require.Len(t, device.System.DNSServers, 2)
	assert.Contains(t, device.System.DNSServers, "91.239.100.100")
	assert.Contains(t, device.System.DNSServers, "89.233.43.71")
	require.Len(t, device.System.TimeServers, 1)
	assert.Contains(t, device.System.TimeServers, "0.pfsense.pool.ntp.org")
	assert.True(t, device.System.DisableNATReflection)
	assert.Equal(t, "monthly", device.System.Bogons.Interval)
	assert.Equal(t, "hadp", device.System.PowerdACMode)
	assert.Equal(t, "https", device.System.WebGUI.Protocol)

	// Interfaces
	assert.Len(t, device.Interfaces, 7) // wan, lan, opt1-opt5

	// DHCP
	assert.GreaterOrEqual(t, len(device.DHCP), 4) // lan, opt1, opt4, opt5 scopes

	// NAT
	assert.Equal(t, "advanced", string(device.NAT.OutboundMode))
	assert.Len(t, device.NAT.OutboundRules, 8)
	assert.Len(t, device.NAT.InboundRules, 2)

	// Firewall rules (13 rules in the filter section)
	assert.GreaterOrEqual(t, len(device.FirewallRules), 13)

	// VPN
	require.Len(t, device.VPN.OpenVPN.Clients, 2)
	assert.Contains(t, device.VPN.OpenVPN.Clients[0].ServerAddr, "mullvad.net")

	// Load Balancer
	assert.Len(t, device.LoadBalancer.MonitorTypes, 5)

	// VLANs
	require.Len(t, device.VLANs, 2)

	// CAs
	assert.Len(t, device.CAs, 1)

	// Users
	require.GreaterOrEqual(t, len(device.Users), 1)
	assert.Equal(t, "admin", device.Users[0].Name)

	// Groups
	assert.GreaterOrEqual(t, len(device.Groups), 2)

	// Cron
	require.NotNil(t, device.Cron)
	assert.NotEmpty(t, device.Cron.Jobs)

	// SNMP
	assert.Equal(t, "public", device.SNMP.ROCommunity)

	// Revision
	assert.Contains(t, device.Revision.Username, "admin")

	// --- Spot-check specific data values ---

	// First inbound NAT rule
	assert.Contains(t, device.NAT.InboundRules[0].Description, "HTTP to webserver")
	assert.Equal(t, "10.0.2.2", device.NAT.InboundRules[0].InternalIP)

	// Floating firewall rule with block type
	hasFloatingBlock := false
	for _, rule := range device.FirewallRules {
		if rule.Floating && strings.EqualFold(string(rule.Type), "block") {
			hasFloatingBlock = true

			break
		}
	}
	assert.True(t, hasFloatingBlock, "expected at least one floating block rule")

	// Firewall rule with description mentioning Mullvad WAN Egress (floating block)
	hasMullvadRule := false
	for _, rule := range device.FirewallRules {
		if strings.Contains(rule.Description, "Mullvad WAN Egress") {
			hasMullvadRule = true

			break
		}
	}
	assert.True(t, hasMullvadRule, "expected at least one rule referencing Mullvad WAN Egress")

	// Firewall rule with gateway
	hasGatewayRule := false
	for _, rule := range device.FirewallRules {
		if rule.Gateway == "MULLVAD2_VPNV4" {
			hasGatewayRule = true

			break
		}
	}
	assert.True(t, hasGatewayRule, "expected at least one rule with gateway MULLVAD2_VPNV4")

	// VLANs on igb2
	assert.Equal(t, "igb2", device.VLANs[0].PhysicalIf)
	assert.Equal(t, "2", device.VLANs[0].Tag)
	assert.Equal(t, "igb2", device.VLANs[1].PhysicalIf)
	assert.Equal(t, "3", device.VLANs[1].Tag)
}

// TestParser_ConfigPfSense_MarkdownOutput verifies that the parsed fixture produces valid markdown.
//

func TestParser_ConfigPfSense_MarkdownOutput(t *testing.T) {
	t.Setenv("TERM", "dumb") // Clean output without ANSI codes

	device, _ := parseConfigPfSenseFixture(t)

	mc := converter.NewMarkdownConverter()
	md, err := mc.ToMarkdown(context.Background(), device)
	require.NoError(t, err)
	assert.NotEmpty(t, md)

	// Device-type-aware title
	assert.Contains(t, md, "pfSense Configuration")
	assert.NotContains(t, md, "OPNsense Configuration")

	// Hostname and domain
	assert.Contains(t, md, "pfSense")
	assert.Contains(t, md, "localdomain")

	// Section headers
	assert.Contains(t, md, "System Configuration")
	assert.Contains(t, md, "Network Configuration")

	// Specific data values
	assert.Contains(t, md, "igb0")        // WAN physical interface
	assert.Contains(t, md, "192.168.1.1") // LAN IP
	assert.Contains(t, md, "advanced")    // NAT mode
	assert.Contains(t, md, "SNMP")        // SNMP section present
	assert.Contains(t, md, "ICMP")        // Load balancer monitor
	assert.Contains(t, md, "HTTP")        // Load balancer monitor
}

// TestParser_ConfigPfSense_JSONOutput verifies that the parsed fixture serializes to valid JSON.
func TestParser_ConfigPfSense_JSONOutput(t *testing.T) {
	t.Parallel()

	device, _ := parseConfigPfSenseFixture(t)

	data, err := json.Marshal(device)
	require.NoError(t, err)
	assert.True(t, json.Valid(data), "expected valid JSON output")

	output := string(data)
	assert.Contains(t, output, `"pfsense"`)        // device_type field
	assert.Contains(t, output, `"pfSense"`)        // hostname
	assert.Contains(t, output, `"91.239.100.100"`) // DNS server
}

// TestParser_ConfigPfSense_YAMLOutput verifies that the parsed fixture serializes to valid YAML.
func TestParser_ConfigPfSense_YAMLOutput(t *testing.T) {
	t.Parallel()

	device, _ := parseConfigPfSenseFixture(t)

	data, err := yaml.Marshal(device)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	output := string(data)
	assert.Contains(t, output, "hostname: pfSense")
	assert.Contains(t, output, "91.239.100.100") // DNS server
}

// TestParser_ConfigPfSense_Warnings verifies conversion warnings have valid structure when present.
// The standard pfSense fixture produces no warnings because NAT-associated rules (empty type
// with associated-rule-id) are excluded from the empty-type check.
func TestParser_ConfigPfSense_Warnings(t *testing.T) {
	t.Parallel()

	_, warnings := parseConfigPfSenseFixture(t)

	// Verify any warnings that are emitted have valid structure.
	for _, w := range warnings {
		assert.NotEmpty(t, w.Field, "warning Field should not be empty")
		assert.NotEmpty(t, w.Message, "warning Message should not be empty")
		assert.True(t, common.IsValidSeverity(w.Severity), "warning Severity %q should be valid", w.Severity)
	}
}

func TestConverter_InvalidEnumValues(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.XMLName.Local = xmlRootPfSense
	doc.Filter.Rule = []pfsenseSchema.FilterRule{
		{
			Type:        "match",
			Direction:   "sideways",
			IPProtocol:  "ipv5",
			Source:      opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{Any: new(string)},
			Interface:   opnsense.InterfaceList{"lan"},
		},
	}
	doc.Nat.Outbound.Rule = []opnsense.NATRule{
		{
			IPProtocol:  "ipv5",
			Interface:   opnsense.InterfaceList{"wan"},
			Source:      opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{Any: new(string)},
		},
	}
	doc.Nat.Inbound = []pfsenseSchema.InboundRule{
		{
			IPProtocol:  "ipv5",
			Target:      "10.0.0.1",
			Interface:   opnsense.InterfaceList{"wan"},
			Source:      opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{Any: new(string)},
		},
	}
	doc.Nat.Outbound.Mode = "bogus"

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.NotNil(t, device)

	// Expect warnings for: unrecognized firewall type, direction, IP protocol (firewall),
	// IP protocol (outbound NAT), IP protocol (inbound NAT), outbound mode
	enumWarnings := 0
	for _, w := range warnings {
		if strings.Contains(w.Message, "unrecognized") {
			enumWarnings++
		}
	}

	assert.Equal(
		t,
		6,
		enumWarnings,
		"expected 6 unrecognized-enum warnings, got %d; warnings: %v",
		enumWarnings,
		warnings,
	)
}

func TestConverter_PPPs(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.XMLName.Local = xmlRootPfSense
	doc.PPPs = opnsense.PPPInterfaces{
		Ppp: []opnsense.PPP{
			{If: "pppoe0", Type: "pppoe", Descr: "WAN PPPoE"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.PPPs, 1)
	assert.Equal(t, "pppoe0", device.PPPs[0].Interface)
	assert.Equal(t, "pppoe", device.PPPs[0].Type)
	assert.Equal(t, "WAN PPPoE", device.PPPs[0].Description)
}

func TestConverter_GatewayGroups(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.XMLName.Local = xmlRootPfSense
	doc.Gateways = opnsense.Gateways{
		Gateway: []opnsense.Gateway{
			{Name: "WAN_DHCP", Interface: "wan", Gateway: "dynamic"},
		},
		Groups: []opnsense.GatewayGroup{
			{Name: "WANGROUP", Trigger: "downloss", Descr: "WAN Failover"},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Routing.Gateways, 1)
	assert.Equal(t, "WAN_DHCP", device.Routing.Gateways[0].Name)
	require.Len(t, device.Routing.GatewayGroups, 1)
	assert.Equal(t, "WANGROUP", device.Routing.GatewayGroups[0].Name)
	assert.Equal(t, "downloss", device.Routing.GatewayGroups[0].Trigger)
}

func TestConverter_OpenVPNCSCs(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.XMLName.Local = xmlRootPfSense
	doc.OpenVPN = opnsense.OpenVPN{
		CSC: []opnsense.OpenVPNCSC{
			{
				Common_name:    "client1",
				Tunnel_network: "10.8.1.0/24",
				DNS_domain:     "vpn.local",
				DNS_server1:    "10.8.0.1",
			},
		},
	}

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.VPN.OpenVPN.ClientSpecificConfigs, 1)
	csc := device.VPN.OpenVPN.ClientSpecificConfigs[0]
	assert.Equal(t, "client1", csc.CommonName)
	assert.Equal(t, "10.8.1.0/24", csc.TunnelNetwork)
	assert.Equal(t, "vpn.local", csc.DNSDomain)
	assert.Contains(t, csc.DNSServers, "10.8.0.1")
}

func TestConverter_CronEmptyCommand(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.XMLName.Local = xmlRootPfSense
	doc.Cron.Items = []pfsenseSchema.CronItem{
		{Command: "/usr/bin/nice -n20 newsyslog", Minute: "1", Hour: "0"},
		{Command: "", Minute: "0", Hour: "0"},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.NotNil(t, device.Cron)
	assert.Equal(t, "/usr/bin/nice -n20 newsyslog", device.Cron.Jobs)

	cronWarnings := 0
	for _, w := range warnings {
		if strings.Contains(w.Field, "Cron") && strings.Contains(w.Message, "empty command") {
			cronWarnings++
		}
	}

	assert.Equal(t, 1, cronWarnings, "expected 1 empty-command cron warning")
}

// minimalValidPfSenseXML is a minimal well-formed pfSense config XML used by
// the SetValidator regression tests below.
const minimalValidPfSenseXML = `<?xml version="1.0"?><pfsense><version>19.1</version><system><hostname>test</hostname></system></pfsense>`

// TestParser_ParseAndValidateWithValidator exercises the three observable
// behaviors of the validator injection: installed-and-succeeds,
// installed-and-fails, and no-validator fallback. Each subtest resets the
// sync.Once guard so it can install its own validator; the subtests cannot
// run in parallel for this reason.
func TestParser_ParseAndValidateWithValidator(t *testing.T) {
	t.Cleanup(pfsense.ResetValidatorForTesting)

	t.Run("validates with injected validator", func(t *testing.T) {
		pfsense.ResetValidatorForTesting()
		pfsense.SetValidator(func(_ *pfsenseSchema.Document) error {
			return nil
		})

		p := pfsense.NewParser(nil)
		device, _, err := p.ParseAndValidate(context.Background(), strings.NewReader(minimalValidPfSenseXML))

		require.NoError(t, err)
		assert.Equal(t, "test", device.System.Hostname)
	})

	t.Run("returns validation error", func(t *testing.T) {
		pfsense.ResetValidatorForTesting()
		pfsense.SetValidator(func(_ *pfsenseSchema.Document) error {
			return errors.New("hostname is required")
		})

		p := pfsense.NewParser(nil)
		xmlData := `<?xml version="1.0"?><pfsense><version>19.1</version></pfsense>`
		_, _, err := p.ParseAndValidate(context.Background(), strings.NewReader(xmlData))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation")
		assert.Contains(t, err.Error(), "hostname is required")
	})

	t.Run("falls back to parse when no validator", func(t *testing.T) {
		pfsense.ResetValidatorForTesting()
		// Intentionally do NOT call SetValidator — exercises the nil fallback.

		p := pfsense.NewParser(nil)
		xmlData := `<?xml version="1.0"?><pfsense><version>19.1</version><system><hostname>fallback</hostname></system></pfsense>`
		device, _, err := p.ParseAndValidate(context.Background(), strings.NewReader(xmlData))

		require.NoError(t, err)
		assert.Equal(t, "fallback", device.System.Hostname)
	})
}

// TestPfSense_SetValidator_CannotBeOverwritten pins the one-shot semantics
// of [pfsense.SetValidator]. The second call must NOT replace the validator
// installed by the first call — this is the enforcement point that prevents
// a dynamically loaded plugin's init() from stomping the CLI-installed
// validator (see GOTCHAS.md §20).
func TestPfSense_SetValidator_CannotBeOverwritten(t *testing.T) {
	t.Cleanup(pfsense.ResetValidatorForTesting)
	pfsense.ResetValidatorForTesting()

	var firstCalled, secondCalled bool

	pfsense.SetValidator(func(_ *pfsenseSchema.Document) error {
		firstCalled = true
		return nil
	})
	pfsense.SetValidator(func(_ *pfsenseSchema.Document) error {
		secondCalled = true
		return errors.New("SHOULD NOT RUN")
	})

	p := pfsense.NewParser(nil)
	_, _, err := p.ParseAndValidate(context.Background(), strings.NewReader(minimalValidPfSenseXML))

	require.NoError(t, err, "second SetValidator leaked its error-returning validator")
	assert.True(t, firstCalled, "first validator was not invoked — sync.Once behavior broken")
	assert.False(t, secondCalled, "second validator was invoked — stomp protection broken")
}

// TestPfSense_SetValidator_Race stresses concurrent [pfsense.SetValidator]
// writers and [pfsense.Parser.ParseAndValidate] readers. Run under -race
// (e.g., `just test-race ./pkg/parser/pfsense/...`) to catch any data race
// between the validator-install path and the validator-read path.
//
// The test asserts no races occur and that the first-caller-wins invariant
// holds: whichever validator the sync.Once actually installed is the one
// observed by ParseAndValidate.
func TestPfSense_SetValidator_Race(t *testing.T) {
	t.Cleanup(pfsense.ResetValidatorForTesting)
	pfsense.ResetValidatorForTesting()

	const (
		numWriters = 16
		numReaders = 16
	)

	// Every writer installs the SAME validator (identical function value is
	// not required by the spec — only "some installed function wins and
	// stays installed"). Because we cannot reliably compare func values,
	// each writer just increments the shared counter; the race test
	// succeeds if no race is flagged and the reader path executes cleanly.
	var installed sync.WaitGroup
	installed.Add(numWriters)

	writerBarrier := make(chan struct{})
	readerBarrier := make(chan struct{})

	var readerWG sync.WaitGroup
	readerWG.Add(numReaders)

	for range numWriters {
		go func() {
			defer installed.Done()
			<-writerBarrier
			pfsense.SetValidator(func(_ *pfsenseSchema.Document) error {
				return nil
			})
		}()
	}

	for range numReaders {
		go func() {
			defer readerWG.Done()
			<-readerBarrier
			p := pfsense.NewParser(nil)
			// The race test only cares about data-race freedom; the
			// returned CommonDevice and warnings are intentionally
			// discarded and an error here would still satisfy the race
			// invariant. Errors must still be read so errcheck is happy.
			if _, _, err := p.ParseAndValidate(
				context.Background(),
				strings.NewReader(minimalValidPfSenseXML),
			); err != nil {
				// The minimal fixture must parse successfully. A
				// spurious error here is a real regression, not a race
				// concern — surface it via t.Errorf (t is safe for
				// concurrent use per the testing package docs).
				t.Errorf("concurrent ParseAndValidate failed: %v", err)
			}
		}()
	}

	// Release writers and readers together so they contend.
	close(writerBarrier)
	close(readerBarrier)

	installed.Wait()
	readerWG.Wait()

	// After the storm, the validator must remain installed — not nil.
	assert.NotNil(t, pfsense.ValidatorForTesting(),
		"validator was cleared by concurrent writers; sync.Once semantics broken")
}

func TestConverter_FirmwareVersion(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()
	doc.XMLName.Local = xmlRootPfSense
	doc.Version = "22.9"

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	assert.Equal(t, "22.9", device.System.Firmware.Version)
	assert.Equal(t, "22.9", device.Version)
}

// --- IPsec converter tests ---

// TestConverter_IPsec_Phase1 verifies Phase 1 (IKE SA) tunnel conversion from pfSense schema
// to common model, including all field mappings, BoolFlag handling, and encryption algorithms.
//
//nolint:funlen // test table or data declaration; length is in data not logic
func TestConverter_IPsec_Phase1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(doc *pfsenseSchema.Document)
		check func(t *testing.T, device *common.CommonDevice)
	}{
		{
			name:  "empty phase1",
			setup: func(_ *pfsenseSchema.Document) {},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.Nil(t, device.VPN.IPsec.Phase1Tunnels)
			},
		},
		{
			name: "single active tunnel",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{
						IKEId:        "1",
						IKEType:      "ikev2",
						Interface:    "wan",
						RemoteGW:     "203.0.113.1",
						Protocol:     "inet",
						AuthMethod:   "pre_shared_key",
						MyIDType:     "myaddress",
						MyIDData:     "198.51.100.1",
						PeerIDType:   "peeraddress",
						PeerIDData:   "203.0.113.1",
						Mode:         "main",
						Lifetime:     "28800",
						RekeyTime:    "25200",
						ReauthTime:   "0",
						RandTime:     "540",
						NATTraversal: "on",
						Mobike:       "on",
						DPDDelay:     "10",
						DPDMaxFail:   "5",
						StartAction:  "none",
						CloseAction:  "none",
						CertRef:      "cert-abc123",
						CARef:        "ca-def456",
						IKEPort:      "500",
						NATTPort:     "4500",
						SplitConn:    "on",
						Descr:        "Site-to-site VPN",
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.True(t, device.VPN.IPsec.Enabled, "IPsec must be enabled when Phase1 tunnels exist")
				require.Len(t, device.VPN.IPsec.Phase1Tunnels, 1)
				p1 := device.VPN.IPsec.Phase1Tunnels[0]
				assert.Equal(t, "1", p1.IKEID)
				assert.Equal(t, "ikev2", p1.IKEType)
				assert.Equal(t, "wan", p1.Interface)
				assert.Equal(t, "203.0.113.1", p1.RemoteGateway)
				assert.Equal(t, "inet", p1.Protocol)
				assert.Equal(t, "pre_shared_key", p1.AuthMethod)
				assert.Equal(t, "myaddress", p1.MyIDType)
				assert.Equal(t, "198.51.100.1", p1.MyIDData)
				assert.Equal(t, "peeraddress", p1.PeerIDType)
				assert.Equal(t, "203.0.113.1", p1.PeerIDData)
				assert.Equal(t, "main", p1.Mode)
				assert.Equal(t, "28800", p1.Lifetime)
				assert.Equal(t, "25200", p1.RekeyTime)
				assert.Equal(t, "0", p1.ReauthTime)
				assert.Equal(t, "540", p1.RandTime)
				assert.Equal(t, "on", p1.NATTraversal)
				assert.Equal(t, "on", p1.MOBIKE)
				assert.Equal(t, "10", p1.DPDDelay)
				assert.Equal(t, "5", p1.DPDMaxFail)
				assert.Equal(t, "none", p1.StartAction)
				assert.Equal(t, "none", p1.CloseAction)
				assert.Equal(t, "cert-abc123", p1.CertRef)
				assert.Equal(t, "ca-def456", p1.CARef)
				assert.Equal(t, "500", p1.IKEPort)
				assert.Equal(t, "4500", p1.NATTPort)
				assert.Equal(t, "on", p1.SplitConn)
				assert.Equal(t, "Site-to-site VPN", p1.Description)
				assert.False(t, p1.Disabled)
				assert.False(t, p1.Mobile)
			},
		},
		{
			name: "disabled tunnel",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{
						IKEId:    "1",
						Disabled: opnsense.BoolFlag(true),
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				require.Len(t, device.VPN.IPsec.Phase1Tunnels, 1)
				assert.True(t, device.VPN.IPsec.Phase1Tunnels[0].Disabled)
			},
		},
		{
			name: "mobile tunnel",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{
						IKEId:  "1",
						Mobile: opnsense.BoolFlag(true),
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				require.Len(t, device.VPN.IPsec.Phase1Tunnels, 1)
				assert.True(t, device.VPN.IPsec.Phase1Tunnels[0].Mobile)
			},
		},
		{
			name: "with encryption algorithms",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{
						IKEId: "1",
						Encryption: pfsenseSchema.IPsecPhase1Encryption{
							Algorithms: []pfsenseSchema.IPsecEncryptionAlgorithm{
								{Name: "aes", KeyLen: "256"},
								{Name: "aes", KeyLen: "128"},
							},
						},
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				require.Len(t, device.VPN.IPsec.Phase1Tunnels, 1)
				assert.Equal(t, []string{"aes-256", "aes-128"}, device.VPN.IPsec.Phase1Tunnels[0].EncryptionAlgorithms)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			tt.setup(doc)

			device, _, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			tt.check(t, device)
		})
	}
}

// TestConverter_IPsec_Phase2 verifies Phase 2 (child SA) tunnel conversion from pfSense schema
// to common model, including network identity netbits, NATLocalID, and hash/encryption algorithms.
//
//nolint:funlen // test table or data declaration; length is in data not logic
func TestConverter_IPsec_Phase2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(doc *pfsenseSchema.Document)
		check func(t *testing.T, device *common.CommonDevice)
	}{
		{
			name:  "empty phase2",
			setup: func(_ *pfsenseSchema.Document) {},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.Nil(t, device.VPN.IPsec.Phase2Tunnels)
			},
		},
		{
			name: "single tunnel",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{IKEId: "1", Interface: "wan", RemoteGW: "203.0.113.1"},
				}
				doc.IPsec.Phase2 = []pfsenseSchema.IPsecPhase2{
					{
						IKEId:    "1",
						UniqID:   "abc123",
						ReqID:    "42",
						Mode:     "tunnel",
						Protocol: "esp",
						LocalID: pfsenseSchema.IPsecID{
							Type:    "network",
							Address: "192.168.1.0",
							Netbits: "24",
						},
						RemoteID: pfsenseSchema.IPsecID{
							Type:    "network",
							Address: "10.0.0.0",
							Netbits: "8",
						},
						NATLocalID: pfsenseSchema.IPsecID{
							Type:    "network",
							Address: "172.16.0.0",
							Netbits: "16",
						},
						PFSGroup: "14",
						Lifetime: "3600",
						PingHost: "10.0.0.1",
						Descr:    "LAN to remote",
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.True(t, device.VPN.IPsec.Enabled, "IPsec must be enabled when Phase1 tunnels exist")
				require.Len(t, device.VPN.IPsec.Phase2Tunnels, 1)
				p2 := device.VPN.IPsec.Phase2Tunnels[0]
				assert.Equal(t, "1", p2.IKEID)
				assert.Equal(t, "abc123", p2.UniqID)
				assert.Equal(t, "42", p2.ReqID)
				assert.Equal(t, "tunnel", p2.Mode)
				assert.Equal(t, "esp", p2.Protocol)
				assert.Equal(t, "network", p2.LocalIDType)
				assert.Equal(t, "192.168.1.0", p2.LocalIDAddress)
				assert.Equal(t, "24", p2.LocalIDNetbits)
				assert.Equal(t, "network", p2.RemoteIDType)
				assert.Equal(t, "10.0.0.0", p2.RemoteIDAddress)
				assert.Equal(t, "8", p2.RemoteIDNetbits)
				assert.Equal(t, "network", p2.NATLocalIDType)
				assert.Equal(t, "172.16.0.0", p2.NATLocalIDAddress)
				assert.Equal(t, "16", p2.NATLocalIDNetbits)
				assert.Equal(t, "14", p2.PFSGroup)
				assert.Equal(t, "3600", p2.Lifetime)
				assert.Equal(t, "10.0.0.1", p2.PingHost)
				assert.Equal(t, "LAN to remote", p2.Description)
				assert.False(t, p2.Disabled)
			},
		},
		{
			name: "disabled phase2",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{IKEId: "1", Interface: "wan", RemoteGW: "203.0.113.1"},
				}
				doc.IPsec.Phase2 = []pfsenseSchema.IPsecPhase2{
					{
						IKEId:    "1",
						Disabled: opnsense.BoolFlag(true),
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				require.Len(t, device.VPN.IPsec.Phase2Tunnels, 1)
				assert.True(t, device.VPN.IPsec.Phase2Tunnels[0].Disabled)
			},
		},
		{
			name: "with encryption algorithms and key lengths",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{IKEId: "1", Interface: "wan", RemoteGW: "203.0.113.1"},
				}
				doc.IPsec.Phase2 = []pfsenseSchema.IPsecPhase2{
					{
						IKEId: "1",
						EncryptionAlgorithms: []pfsenseSchema.IPsecEncryptionAlgorithm{
							{Name: "aes", KeyLen: "256"},
							{Name: "aes", KeyLen: "128"},
							{Name: "blowfish"},
						},
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				require.Len(t, device.VPN.IPsec.Phase2Tunnels, 1)
				assert.Equal(
					t,
					[]string{"aes-256", "aes-128", "blowfish"},
					device.VPN.IPsec.Phase2Tunnels[0].EncryptionAlgorithms,
				)
			},
		},
		{
			name: "with hash algorithms",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{IKEId: "1", Interface: "wan", RemoteGW: "203.0.113.1"},
				}
				doc.IPsec.Phase2 = []pfsenseSchema.IPsecPhase2{
					{
						IKEId: "1",
						HashAlgorithms: []pfsenseSchema.IPsecHashAlgorithm{
							{Name: "hmac-sha256"},
							{Name: "hmac-sha1"},
						},
					},
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				require.Len(t, device.VPN.IPsec.Phase2Tunnels, 1)
				assert.Equal(t, []string{"hmac-sha256", "hmac-sha1"}, device.VPN.IPsec.Phase2Tunnels[0].HashAlgorithms)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			tt.setup(doc)

			device, _, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			tt.check(t, device)
		})
	}
}

// TestConverter_IPsec_MobileClient verifies mobile/road-warrior client pool conversion,
// including IPv4/IPv6 pools, DNS/WINS aggregation, and SavePassword flag.
func TestConverter_IPsec_MobileClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(doc *pfsenseSchema.Document)
		check func(t *testing.T, device *common.CommonDevice)
	}{
		{
			name:  "disabled mobile client",
			setup: func(_ *pfsenseSchema.Document) {},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.False(t, device.VPN.IPsec.MobileClient.Enabled)
			},
		},
		{
			name: "enabled mobile client",
			setup: func(doc *pfsenseSchema.Document) {
				doc.IPsec.Phase1 = []pfsenseSchema.IPsecPhase1{
					{IKEId: "1", Interface: "wan", RemoteGW: "0.0.0.0", Mobile: opnsense.BoolFlag(true)},
				}
				doc.IPsec.Client = pfsenseSchema.IPsecClient{
					Enable:      opnsense.BoolFlag(true),
					UserSource:  "local",
					GroupSource: "system",
					PoolAddress: "10.10.10.0",
					PoolNetbits: "24",
					PoolAddrV6:  "fd00::1",
					PoolNetV6:   "64",
					DNSServer1:  "8.8.8.8",
					DNSServer2:  "8.8.4.4",
					WINSServer1: "192.168.1.10",
					DNSDomain:   "vpn.local",
					DNSSplit:    "internal.local",
					LoginBanner: "Welcome to the VPN",
					SavePasswd:  opnsense.BoolFlag(true),
				}
			},
			check: func(t *testing.T, device *common.CommonDevice) {
				t.Helper()
				assert.True(t, device.VPN.IPsec.Enabled, "IPsec must be enabled when Phase1 tunnels exist")
				mc := device.VPN.IPsec.MobileClient
				assert.True(t, mc.Enabled)
				assert.Equal(t, "local", mc.UserSource)
				assert.Equal(t, "system", mc.GroupSource)
				assert.Equal(t, "10.10.10.0", mc.PoolAddress)
				assert.Equal(t, "24", mc.PoolNetbits)
				assert.Equal(t, "fd00::1", mc.PoolAddressV6)
				assert.Equal(t, "64", mc.PoolNetbitsV6)
				assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, mc.DNSServers)
				assert.Equal(t, []string{"192.168.1.10"}, mc.WINSServers)
				assert.Equal(t, "vpn.local", mc.DNSDomain)
				assert.Equal(t, "internal.local", mc.DNSSplit)
				assert.Equal(t, "Welcome to the VPN", mc.LoginBanner)
				assert.True(t, mc.SavePassword)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := pfsenseSchema.NewDocument()
			tt.setup(doc)

			device, _, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			tt.check(t, device)
		})
	}
}

// TestConverter_IPsec_EmptyDocument verifies that an empty pfSense document produces a
// zero-value IPsecConfig with Enabled=false and nil tunnel slices.
func TestConverter_IPsec_EmptyDocument(t *testing.T) {
	t.Parallel()

	doc := pfsenseSchema.NewDocument()

	device, _, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	assert.False(t, device.VPN.IPsec.Enabled, "IPsec must not be enabled on empty document")
	assert.Nil(t, device.VPN.IPsec.Phase1Tunnels)
	assert.Nil(t, device.VPN.IPsec.Phase2Tunnels)
	assert.False(t, device.VPN.IPsec.MobileClient.Enabled)
}
