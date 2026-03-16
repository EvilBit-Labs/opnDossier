package opnsense_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_Certificates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		certs   []schema.Cert
		wantLen int
	}{
		{
			name:    "empty certs returns nil",
			certs:   nil,
			wantLen: 0,
		},
		{
			name: "single certificate",
			certs: []schema.Cert{
				{Refid: "cert-001", Descr: "Web Server", Crt: "MIIB...", Prv: "MIIE..."},
			},
			wantLen: 1,
		},
		{
			name: "multiple certificates",
			certs: []schema.Cert{
				{Refid: "cert-001", Descr: "Web Server", Crt: "MIIB1", Prv: "MIIE1"},
				{Refid: "cert-002", Descr: "VPN User", Crt: "MIIB2", Prv: "MIIE2"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.Certs = tt.certs

			device, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.Certificates)
				return
			}
			require.Len(t, device.Certificates, tt.wantLen)
		})
	}
}

func TestConverter_Certificates_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Certs = []schema.Cert{
		{
			Refid: "5aa10f2a5b569",
			Descr: "WebUI TLS Certificate",
			Crt:   "LS0tLS1CRUdJTi...",
			Prv:   "LS0tLS1CRUdJTk...",
		},
	}

	device, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.Certificates, 1)

	cert := device.Certificates[0]
	assert.Equal(t, "5aa10f2a5b569", cert.RefID)
	assert.Equal(t, "WebUI TLS Certificate", cert.Description)
	assert.Equal(t, "LS0tLS1CRUdJTi...", cert.Certificate)
	assert.Equal(t, "LS0tLS1CRUdJTk...", cert.PrivateKey)
}

func TestConverter_CAs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cas     []schema.CertificateAuthority
		wantLen int
	}{
		{
			name:    "empty CAs returns nil",
			cas:     nil,
			wantLen: 0,
		},
		{
			name: "single CA",
			cas: []schema.CertificateAuthority{
				{Refid: "ca-001", Descr: "Internal CA", Crt: "MIID..."},
			},
			wantLen: 1,
		},
		{
			name: "multiple CAs with chain",
			cas: []schema.CertificateAuthority{
				{Refid: "ca-root", Descr: "Root CA", Crt: "ROOT..."},
				{Refid: "ca-inter", Descr: "Intermediate CA", Crt: "INTER..."},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.CAs = tt.cas

			device, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.CAs)
				return
			}
			require.Len(t, device.CAs, tt.wantLen)
		})
	}
}

func TestConverter_CAs_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.CAs = []schema.CertificateAuthority{
		{
			Refid:  "4dad3002120e0",
			Descr:  "Internal Root CA",
			Crt:    "MIIDxTCCAq2gAw...",
			Prv:    "MIIEvgIBADANBg...",
			Serial: "3",
		},
	}

	device, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.CAs, 1)

	ca := device.CAs[0]
	assert.Equal(t, "4dad3002120e0", ca.RefID)
	assert.Equal(t, "Internal Root CA", ca.Description)
	assert.Equal(t, "MIIDxTCCAq2gAw...", ca.Certificate)
	assert.Equal(t, "MIIEvgIBADANBg...", ca.PrivateKey)
	assert.Equal(t, "3", ca.Serial)
}

func TestConverter_Packages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		plugins string
		wantLen int
	}{
		{
			name:    "empty plugins returns nil",
			plugins: "",
			wantLen: 0,
		},
		{
			name:    "single plugin",
			plugins: "os-haproxy",
			wantLen: 1,
		},
		{
			name:    "multiple plugins",
			plugins: "os-haproxy,os-wireguard,os-theme-cicada",
			wantLen: 3,
		},
		{
			name:    "plugins with whitespace",
			plugins: "os-haproxy, os-wireguard , os-theme-cicada",
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.System.Firmware.Plugins = tt.plugins

			device, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)
			assert.Empty(t, warnings)

			if tt.wantLen == 0 {
				assert.Nil(t, device.Packages)
				return
			}
			require.Len(t, device.Packages, tt.wantLen)
		})
	}
}

func TestConverter_Packages_FieldMapping(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.System.Firmware.Plugins = "os-haproxy,os-wireguard"

	device, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, device.Packages, 2)

	pkg := device.Packages[0]
	assert.Equal(t, "os-haproxy", pkg.Name)
	assert.Equal(t, "plugin", pkg.Type)
	assert.True(t, pkg.Installed)

	pkg2 := device.Packages[1]
	assert.Equal(t, "os-wireguard", pkg2.Name)
	assert.Equal(t, "plugin", pkg2.Type)
	assert.True(t, pkg2.Installed)
}

func TestConverter_Certificates_Warnings(t *testing.T) {
	t.Parallel()

	doc := schema.NewOpnSenseDocument()
	doc.Certs = []schema.Cert{
		{Refid: "cert-001", Descr: "Empty cert", Crt: "", Prv: "MIIE..."},
	}

	_, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	assert.Equal(t, "Certificates[0].Certificate", warnings[0].Field)
	assert.Equal(t, common.SeverityHigh, warnings[0].Severity)
	assert.Equal(t, "certificate has empty PEM data", warnings[0].Message)
}

func TestConverter_HA_Warnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		syncIP       string
		username     string
		password     string
		wantWarnings int
	}{
		{
			name:         "sync target without credentials",
			syncIP:       "10.0.0.2",
			username:     "",
			password:     "",
			wantWarnings: 1,
		},
		{
			name:         "sync target with credentials",
			syncIP:       "10.0.0.2",
			username:     "admin",
			password:     "secret",
			wantWarnings: 0,
		},
		{
			name:         "no sync target",
			syncIP:       "",
			username:     "",
			password:     "",
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := schema.NewOpnSenseDocument()
			doc.HighAvailabilitySync.Synchronizetoip = tt.syncIP
			doc.HighAvailabilitySync.Username = tt.username
			doc.HighAvailabilitySync.Password = tt.password

			_, warnings, err := opnsense.NewConverter().ToCommonDevice(doc)
			require.NoError(t, err)

			if tt.wantWarnings == 0 {
				assert.Empty(t, warnings)
				return
			}

			require.Len(t, warnings, tt.wantWarnings)
			assert.Equal(t, "HighAvailability.SynchronizeToIP", warnings[0].Field)
			assert.Equal(t, tt.syncIP, warnings[0].Value)
			assert.Equal(t, common.SeverityHigh, warnings[0].Severity)
		})
	}
}
