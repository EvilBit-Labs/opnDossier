package converter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestCase represents a test case for converter tests.
type TestCase struct {
	Name        string
	Data        *common.CommonDevice
	WantErr     bool
	ErrType     error
	ValidateOut func(t *testing.T, result string) // Function to validate the output format
}

// GetCommonTestCases returns common test cases for both JSON and YAML converters.
func GetCommonTestCases() []TestCase {
	return []TestCase{
		{
			Name:    "nil device",
			Data:    nil,
			WantErr: true,
			ErrType: ErrNilDevice,
		},
		{
			Name: "valid device",
			Data: &common.CommonDevice{
				System: common.System{
					Hostname: "test-host",
					Domain:   "test.local",
				},
			},
			WantErr: false,
		},
	}
}

// RunConverterTests runs the standard converter test suite.
func RunConverterTests(
	t *testing.T,
	tests []TestCase,
	convertFunc func(context.Context, *common.CommonDevice) (string, error),
) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			result, err := convertFunc(context.Background(), tt.Data)

			if tt.WantErr {
				require.Error(t, err)

				if tt.ErrType != nil {
					require.ErrorIs(t, err, tt.ErrType)
				}

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, result)

			if tt.ValidateOut != nil {
				tt.ValidateOut(t, result)
			}
		})
	}
}

// newFieldsTestDevice returns a CommonDevice populated with all new fields
// (VLANs, Bridges, PPPs, GIFs, GREs, LAGGs, VirtualIPs, InterfaceGroups,
// Certificates, CAs, Packages) for serialization tests.
func newFieldsTestDevice() *common.CommonDevice {
	return &common.CommonDevice{
		DeviceType: common.DeviceTypeOPNsense,
		System:     common.System{Hostname: "test-fields"},
		VLANs:      []common.VLAN{{VLANIf: "igb0_vlan100", Tag: "100"}},
		Bridges:    []common.Bridge{{BridgeIf: "bridge0", Members: []string{"igb2"}}},
		PPPs:       []common.PPP{{Interface: "pppoe0", Type: "pppoe"}},
		GIFs:       []common.GIF{{Interface: "gif0", Remote: "198.51.100.1"}},
		GREs:       []common.GRE{{Interface: "gre0", Remote: "198.51.100.2"}},
		LAGGs:      []common.LAGG{{Members: []string{"igb4"}, Protocol: "lacp"}},
		VirtualIPs: []common.VirtualIP{{Mode: "carp", Interface: "lan"}},
		InterfaceGroups: []common.InterfaceGroup{
			{Name: "internal", Members: []string{"lan"}},
		},
		Certificates: []common.Certificate{
			{RefID: "cert-001", Description: "Test Cert", PrivateKey: "dGVzdC1rZXktbm90LXJlYWw="},
		},
		CAs: []common.CertificateAuthority{
			{RefID: "ca-001", Description: "Test CA", PrivateKey: "dGVzdC1jYS1rZXktbm90LXJlYWw="},
		},
		Packages: []common.Package{{Name: "os-acme-client", Installed: true}},
	}
}

// newFieldsExpectedKeys returns the JSON/YAML keys expected for the new CommonDevice fields.
var newFieldsExpectedKeys = []string{
	"vlans", "bridges", "ppps", "gifs", "gres", "laggs",
	"virtualIps", "interfaceGroups", "certificates", "cas", "packages",
}

// assertNewFieldsPresent validates that all new-field keys are present and non-empty
// in parsed, and that the certificate privateKey is redacted.
func assertNewFieldsPresent(t *testing.T, parsed map[string]any) {
	t.Helper()

	for _, key := range newFieldsExpectedKeys {
		val, ok := parsed[key]
		assert.True(t, ok, "expected key %q in output", key)
		arr, isArr := val.([]any)
		if isArr {
			assert.NotEmpty(t, arr, "expected key %q to be non-empty", key)
		}
	}

	// Verify certificate private key is redacted
	certs, ok := parsed["certificates"].([]any)
	require.True(t, ok, "certificates should be an array")
	require.Len(t, certs, 1)
	cert, ok := certs[0].(map[string]any)
	require.True(t, ok, "certificate entry should be an object")
	assert.Equal(t, "[REDACTED]", cert["privateKey"], "privateKey should be redacted")
}

// RunNewFieldsSerializationTests verifies that all new CommonDevice fields appear
// in both JSON and YAML serialization output and that sensitive data is redacted.
func RunNewFieldsSerializationTests(t *testing.T) {
	t.Helper()
	t.Parallel()

	device := newFieldsTestDevice()

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		c := NewJSONConverter()
		result, err := c.ToJSON(context.Background(), device, true)
		require.NoError(t, err)

		var parsed map[string]any
		err = json.Unmarshal([]byte(result), &parsed)
		require.NoError(t, err)

		assertNewFieldsPresent(t, parsed)
	})

	t.Run("yaml", func(t *testing.T) {
		t.Parallel()

		c := NewYAMLConverter()
		result, err := c.ToYAML(context.Background(), device, true)
		require.NoError(t, err)

		var parsed map[string]any
		err = yaml.Unmarshal([]byte(result), &parsed)
		require.NoError(t, err)

		assertNewFieldsPresent(t, parsed)
	})
}

// loadTestDataFromFile reads and unmarshals a CommonDevice from a JSON file in testdata/.
func loadTestDataFromFile(t *testing.T, filename string) *common.CommonDevice {
	t.Helper()

	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read test data file: %s", filename)

	var doc common.CommonDevice
	err = json.Unmarshal(data, &doc)
	require.NoError(t, err, "Failed to unmarshal test data: %s", filename)

	return &doc
}
