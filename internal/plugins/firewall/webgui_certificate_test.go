package firewall_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // registers the OPNsense parser
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const webGUICertControl = "FIREWALL-036"

// storedCertificate encodes a DER certificate the way both firewalls keep it
// in config.xml: the PEM text, base64-encoded once more.
func storedCertificate(der []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newCertificate creates a certificate for subject, signed by parent's key,
// or self-signed when parent is nil.
func newCertificate(
	t *testing.T,
	subject string,
	isCA bool,
	parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}

	if parent == nil {
		parent, parentKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

// caIssuedCertificate returns certificate data for a web GUI certificate an
// internal CA issued.
func caIssuedCertificate(t *testing.T) string {
	t.Helper()

	ca, caKey := newCertificate(t, "Internal Root CA", true, nil, nil)
	leaf, _ := newCertificate(t, "fw.example.internal", false, ca, caKey)

	return storedCertificate(leaf.Raw)
}

// selfSignedCertificate returns certificate data shaped like the one OPNsense
// and pfSense generate for the web GUI: issued by itself, with no CA.
func selfSignedCertificate(t *testing.T, isCA bool) string {
	t.Helper()

	cert, _ := newCertificate(t, "OPNsense.localdomain", isCA, nil, nil)

	return storedCertificate(cert.Raw)
}

// certVerdict is what the firewall plugin reported for FIREWALL-036.
type certVerdict struct {
	evaluated bool
	failed    bool
}

// webGUICertVerdict runs the firewall plugin and reports whether FIREWALL-036
// was evaluated and whether it failed.
func webGUICertVerdict(t *testing.T, device *common.CommonDevice) certVerdict {
	t.Helper()

	findings, evaluated, err := firewall.NewPlugin().RunChecks(device)
	require.NoError(t, err)

	failed := slices.ContainsFunc(findings, func(f compliance.Finding) bool {
		return slices.Contains(f.References, webGUICertControl)
	})

	return certVerdict{evaluated: slices.Contains(evaluated, webGUICertControl), failed: failed}
}

// TestFirewallPlugin_ValidWebGUICertificate pins FIREWALL-036 on the shapes a
// config can hold. A reference alone used to pass it, so the self-signed
// certificate every firewall generates for its own GUI passed as valid.
func TestFirewallPlugin_ValidWebGUICertificate(t *testing.T) {
	t.Parallel()

	caIssued := caIssuedCertificate(t)
	selfSigned := selfSignedCertificate(t, false)
	selfSignedCA := selfSignedCertificate(t, true)

	// Wrapped over lines with indentation, as OPNsense writes it.
	var wrapped strings.Builder
	for chunk := range slices.Chunk([]byte(caIssued), 76) {
		wrapped.WriteString("\n      " + string(chunk))
	}

	tests := []struct {
		name      string
		protocol  string
		ref       string
		data      string // certificate data stored under refid "web"
		evaluated bool
		failed    bool
	}{
		{name: "CA-issued", protocol: "https", ref: "web", data: caIssued, evaluated: true},
		{name: "CA-issued, wrapped", protocol: "https", ref: "web", data: wrapped.String(), evaluated: true},
		{name: "CA-issued, raw PEM", protocol: "https", ref: "web", data: decoded(t, caIssued), evaluated: true},
		{name: "self-signed", protocol: "https", ref: "web", data: selfSigned, evaluated: true, failed: true},
		{name: "self-signed CA", protocol: "https", ref: "web", data: selfSignedCA, evaluated: true, failed: true},
		{name: "plain HTTP", protocol: "http", ref: "web", data: caIssued, evaluated: true, failed: true},
		{name: "no protocol", protocol: "", ref: "web", data: caIssued, evaluated: true, failed: true},
		{name: "no reference", protocol: "https", ref: "", data: caIssued, evaluated: true, failed: true},
		{name: "dangling reference", protocol: "https", ref: "gone", data: caIssued, evaluated: true, failed: true},
		{name: "no certificate data", protocol: "https", ref: "web", data: "", evaluated: true, failed: true},
		{name: "truncated data", protocol: "https", ref: "web", data: "LS0tLS1CRUdJTi..."},
		{name: "redacted data", protocol: "https", ref: "web", data: "[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				System: common.System{WebGUI: common.WebGUI{Protocol: tt.protocol, SSLCertRef: tt.ref}},
				Certificates: []common.Certificate{
					{RefID: "other", Certificate: selfSigned},
					{RefID: "web", Certificate: tt.data},
				},
			}

			assert.Equal(t, certVerdict{evaluated: tt.evaluated, failed: tt.failed}, webGUICertVerdict(t, device))
		})
	}
}

// TestFirewallPlugin_ValidWebGUICertificate_FromConfig drives a config
// OPNsense wrote through parse and the check. testdata/sample.config.5.xml
// references the "Web GUI TLS certificate" OPNsense generated for itself,
// which is self-signed; replacing its data with a CA-issued certificate is
// the only change in the passing case.
func TestFirewallPlugin_ValidWebGUICertificate_FromConfig(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sample.config.5.xml"))
	require.NoError(t, err)

	crt := regexp.MustCompile(`(?s)(<descr>Web GUI TLS certificate</descr>\s*<crt>).*?(</crt>)`)
	require.Len(t, crt.FindAllIndex(raw, -1), 1, "fixture no longer carries the generated web GUI certificate")

	tests := []struct {
		name   string
		cfg    []byte
		failed bool
	}{
		{name: "generated self-signed", cfg: raw, failed: true},
		{
			name: "CA-issued",
			cfg:  crt.ReplaceAll(raw, []byte("${1}"+caIssuedCertificate(t)+"${2}")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(), bytes.NewReader(tt.cfg), common.DeviceTypeUnknown, false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Equal(t, certVerdict{evaluated: true, failed: tt.failed}, webGUICertVerdict(t, device))
		})
	}
}

// decoded returns the PEM text inside stored certificate data.
func decoded(t *testing.T, data string) string {
	t.Helper()

	pemText, err := base64.StdEncoding.DecodeString(data)
	require.NoError(t, err)

	return string(pemText)
}

// TestFirewallPlugin_ValidWebGUICertificate_SHA1SelfSigned pins a self-signed
// SHA-1 certificate, the kind older boxes still carry for their web GUI.
func TestFirewallPlugin_ValidWebGUICertificate_SHA1SelfSigned(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "OPNsense.localdomain"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		SignatureAlgorithm: x509.SHA1WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	device := &common.CommonDevice{
		System:       common.System{WebGUI: common.WebGUI{Protocol: "https", SSLCertRef: "web"}},
		Certificates: []common.Certificate{{RefID: "web", Certificate: storedCertificate(der)}},
	}

	assert.Equal(t, certVerdict{evaluated: true, failed: true}, webGUICertVerdict(t, device))
}

// md5SelfSignedCertificate is stored certificate data for a self-signed
// certificate signed with MD5 (openssl req -x509 -md5), which Go refuses to
// verify. It holds no key.
const md5SelfSignedCertificate = "" +
	"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlDSERDQ0FZV2dBd0lCQWdJ" +
	"VUFqdmR1bEJ3TXJnNkpRRWl2YTFrL1pGWFVxTXdEUVlKS29aSWh2Y05BUUVFDQpC" +
	"UUF3SHpFZE1Cc0dBMVVFQXd3VVQxQk9jMlZ1YzJVdWJHOWpZV3hrYjIxaGFXNHdJ" +
	"QmNOTWpZeE1URXpNVGt3DQpOREE1V2hnUE1qRXlOakV3TWpBeE9UQTBNRGxhTUI4" +
	"eEhUQWJCZ05WQkFNTUZFOVFUbk5sYm5ObExteHZZMkZzDQpaRzl0WVdsdU1JR2ZN" +
	"QTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRRG1HUFNDNzkrdmhiLytJ" +
	"WEhHDQp6SnpnNHdPUXpzNlExcGJVNlBkVytvWjRRVThhK0ZhZzdSL2lVMXNFcEFO" +
	"cHk3N3BJUWI5NG01YmRnUERhQ2xWDQp3MW1lclV6cGR1d0EwclRhRDdxcGtpbmhv" +
	"VkVsdnMwdjJqaVJ4dXBoaEx1YTZ5eVorcjliemhkdFl0SWtFSGVpDQpiR3NIbGdP" +
	"NVZuWlJ3STVqclpKMHJFZWtBUUlEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVSWYv" +
	"UVg0M3hlbXNqDQpxRFBaRVNjSExpaHRybEl3SHdZRFZSMGpCQmd3Rm9BVUlmL1FY" +
	"NDN4ZW1zanFEUFpFU2NITGlodHJsSXdEd1lEDQpWUjBUQVFIL0JBVXdBd0VCL3pB" +
	"TkJna3Foa2lHOXcwQkFRUUZBQU9CZ1FDM1lOeVNRbWMzd284bzR5MVJBbEdRDQpZ" +
	"R2tlSjBRVlRRUHBSVWZmbFVVTlpXODBFYXZycUZCNXZUeXB4QTJESzM4TFRPeDRq" +
	"aHBXWU9NWFNqTldJbkNBDQoxc2tmZzVnMWNxRkUxNGdOTDAxcmZYSmxBUm1LeFFD" +
	"ZmFra0VRbzR2bS9JTEtGc1UwQ09EUHZzNE1OY0VneHYxDQpOZUVXRENSdzJkbUpG" +
	"UklTNkQ3d0h3PT0NCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg=="

// TestFirewallPlugin_ValidWebGUICertificate_MD5SelfSigned pins a self-signed
// certificate whose signature Go refuses to verify. Reading the refusal as
// "signed by another key" would pass the control on it.
func TestFirewallPlugin_ValidWebGUICertificate_MD5SelfSigned(t *testing.T) {
	t.Parallel()

	device := &common.CommonDevice{
		System:       common.System{WebGUI: common.WebGUI{Protocol: "https", SSLCertRef: "web"}},
		Certificates: []common.Certificate{{RefID: "web", Certificate: md5SelfSignedCertificate}},
	}

	assert.Equal(t, certVerdict{evaluated: true, failed: true}, webGUICertVerdict(t, device))
}
