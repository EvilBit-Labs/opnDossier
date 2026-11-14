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
	"encoding/asn1"
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

// storedKey stands in for a certificate's private key. The check only asks
// whether one is stored.
const storedKey = "stored-key"

// sha1CAIssuedCertificate returns certificate data for a leaf an internal CA
// signed with SHA-1, which Go refuses to verify.
func sha1CAIssuedCertificate(t *testing.T) string {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Internal Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "fw.example.internal"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		SignatureAlgorithm: x509.SHA1WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	return storedCertificate(der)
}

// keyFirstBundle returns certificate data whose PEM text holds a private key
// before the CA-issued certificate, as a pasted bundle can.
func keyFirstBundle(t *testing.T, caIssued string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	bundle := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	bundle = append(bundle, decoded(t, caIssued)...)

	return base64.StdEncoding.EncodeToString(bundle)
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
		noKey     bool   // stores no private key with it
		evaluated bool
		failed    bool
	}{
		{name: "CA-issued", protocol: "https", ref: "web", data: caIssued, evaluated: true},
		{name: "CA-issued, wrapped", protocol: "https", ref: "web", data: wrapped.String(), evaluated: true},
		{name: "CA-issued, raw PEM", protocol: "https", ref: "web", data: decoded(t, caIssued), evaluated: true},
		{
			name: "CA-issued, key before certificate", protocol: "https", ref: "web",
			data: keyFirstBundle(t, caIssued), evaluated: true,
		},
		// Issuer and subject differ, so the signature Go refuses does not matter.
		{
			name: "CA-issued, SHA-1 signature", protocol: "https", ref: "web",
			data: sha1CAIssuedCertificate(t), evaluated: true,
		},
		{
			name: "CA-issued, no private key", protocol: "https", ref: "web",
			data: caIssued, noKey: true, evaluated: true, failed: true,
		},
		{name: "self-signed", protocol: "https", ref: "web", data: selfSigned, evaluated: true, failed: true},
		{name: "self-signed CA", protocol: "https", ref: "web", data: selfSignedCA, evaluated: true, failed: true},
		{name: "plain HTTP", protocol: "http", ref: "web", data: caIssued, evaluated: true, failed: true},
		{name: "no protocol", protocol: "", ref: "web", data: caIssued, evaluated: true, failed: true},
		{name: "no reference", protocol: "https", ref: "", data: caIssued, evaluated: true, failed: true},
		{name: "dangling reference", protocol: "https", ref: "gone", data: caIssued, evaluated: true, failed: true},
		{name: "no certificate data", protocol: "https", ref: "web", data: "", evaluated: true, failed: true},
		{name: "truncated data", protocol: "https", ref: "web", data: "LS0tLS1CRUdJTi..."},
		{name: "placeholder data", protocol: "https", ref: "web", data: "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := storedKey
			if tt.noKey {
				key = ""
			}

			device := &common.CommonDevice{
				System: common.System{WebGUI: common.WebGUI{Protocol: tt.protocol, SSLCertRef: tt.ref}},
				Certificates: []common.Certificate{
					{RefID: "other", Certificate: selfSigned, PrivateKey: storedKey},
					{RefID: "web", Certificate: tt.data, PrivateKey: key},
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

// TestFirewallPlugin_ValidWebGUICertificate_UnverifiableSelfSigned pins
// self-signed certificates whose signature Go cannot or will not verify. The
// OPNsense Trust model still offers RSA-512 keys, and older boxes carry SHA-1
// and MD5 certificates. Reading a refused signature as "signed by another key"
// would pass the control on them.
func TestFirewallPlugin_ValidWebGUICertificate_UnverifiableSelfSigned(t *testing.T) {
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

	sha1, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	for name, data := range map[string]string{
		"SHA-1":   storedCertificate(sha1),
		"MD5":     md5SelfSignedCertificate,
		"RSA-512": rsa512SelfSignedCertificate,
		"DSA":     dsaSelfSignedCertificate,
		"Ed448":   ed448SelfSignedCertificate,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				System:       common.System{WebGUI: common.WebGUI{Protocol: "https", SSLCertRef: "web"}},
				Certificates: []common.Certificate{{RefID: "web", Certificate: data, PrivateKey: storedKey}},
			}

			assert.Equal(t, certVerdict{evaluated: true, failed: true}, webGUICertVerdict(t, device))
		})
	}
}

// The constants below are stored certificate data for self-signed
// certificates Go cannot create, made with openssl req -x509. They hold no
// key.

// md5SelfSignedCertificate is signed with MD5.
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

// rsa512SelfSignedCertificate has a 512-bit RSA key, a size the OPNsense
// Trust model offers and Go refuses to verify.
const rsa512SelfSignedCertificate = "" +
	"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlCbHpDQ0FVR2dBd0lCQWdJ" +
	"VUd4dm9MaVZya3IvTkNqaE0zMHZnV1lSUkRZZ3dEUVlKS29aSWh2Y05BUUVMDQpC" +
	"UUF3SHpFZE1Cc0dBMVVFQXd3VVQxQk9jMlZ1YzJVdWJHOWpZV3hrYjIxaGFXNHdJ" +
	"QmNOTWpZeE1URXpNVGsxDQpNVFF4V2hnUE1qRXlOakV3TWpBeE9UVXhOREZhTUI4" +
	"eEhUQWJCZ05WQkFNTUZFOVFUbk5sYm5ObExteHZZMkZzDQpaRzl0WVdsdU1Gd3dE" +
	"UVlKS29aSWh2Y05BUUVCQlFBRFN3QXdTQUpCQUs5RThZRDFSRHNlRFprcm1sOXRL" +
	"aWNGDQpNY1FLbHl5blcyUnhmeFN5VUJ1NHRqa2pIRGxzUzZockNXZm83K0t2RVo2" +
	"bjl1WFcwZVd4YzN4YW00cTNBdE1DDQpBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVG" +
	"S0lPTXZJTFZsRjhkZUV1eXZGOTFjQUJ4c2MyTUI4R0ExVWRJd1FZDQpNQmFBRktJ" +
	"T012SUxWbEY4ZGVFdXl2RjkxY0FCeHNjMk1BOEdBMVVkRXdFQi93UUZNQU1CQWY4" +
	"d0RRWUpLb1pJDQpodmNOQVFFTEJRQURRUUJOQ2VLNUdKZ0x2K211M2kyTVIrYm5X" +
	"dFEvalZBL3c0blZmRUVreWdqdmV0V05yaEkyDQpXVHYwZ2laa1BZSEdVa1VDa2lX" +
	"emd5SmJTMGVEOHNodUVpblkNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg=="

// dsaSelfSignedCertificate has a DSA key.
const dsaSelfSignedCertificate = "" +
	"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlDOVRDQ0FxT2dBd0lCQWdJ" +
	"VWNNbXRmbE5BaS9HZDZ3ZjBnemZDT2ZmZFcxWXdDd1lKWUlaSUFXVURCQU1DDQpN" +
	"Qjh4SFRBYkJnTlZCQU1NRkU5UVRuTmxibk5sTG14dlkyRnNaRzl0WVdsdU1DQVhE" +
	"VEkyTVRFeE16RTVOVEUwDQpNVm9ZRHpJeE1qWXhNREl3TVRrMU1UUXhXakFmTVIw" +
	"d0d3WURWUVFEREJSUFVFNXpaVzV6WlM1c2IyTmhiR1J2DQpiV0ZwYmpDQ0FiNHdn" +
	"Z0V6QmdjcWhrak9PQVFCTUlJQkpnS0JnUURBcjZWZ0lJU1ZGeVF3K1VXMlljcFk3" +
	"NlUzDQp2L0dMZmxQTjhreHQ4aUR2eS8xK3l1ajcwemtRTXVrbTY4Tlg0eU51blVO" +
	"ZmFhL0RIaG9jQndLbzlEeTRMazRQDQoyejJhTklQTUEyZnRMQkxhM3BsR0xvYk9y" +
	"Q0F3Q3FXVlkyTGRZbmlQSFNrb3dpUXlXTzFjcmtCdEFBOEdIODVhDQpIUDRvVmZN" +
	"N2RIdDFwYTlwY1FJZEFJWEEyOG4xMXQ0ZmdMRERaZXRSNzFIcWdabVFzVlZXN1or" +
	"NE5yOENnWUJNDQpyMTNocFZXdGhxdlhXR0lCMnFFUSt0bExmNjFYaGVGNXF5SVlt" +
	"TytUZFRoV0JYZFo0VEp0UU41ZHVlU1dNMllwDQpudmtvaDUyVUxVOC9iRlJmRm5U" +
	"d3l2V0R4eXRkT0gwTmlUYUxWTng4dWZyVXlXR3FLemlzOE80N3Nvd1dIT1RqDQo3" +
	"NXZ1d24wY25la3JVTmNKQW9JZlZ4QjBTNG1tUTkydk5zUzVqUXNKaEFPQmhBQUNn" +
	"WUF1Y2l2S1J4ejNhWFYrDQpod3lGN3k1aUpYY2Z5ejRTUnJjNGhEWWdFTjF4YUVP" +
	"REs1SHkwRzI4aDZ2UXNibVEzeEhKQVByN1FpT3ZwOG02DQp5MmVkNWhOTXpHZFE4" +
	"Rk1TeVo5N1NaMmV1c3loZkFxT3hHdG9jU2N1SWVDNldUWG5rNXlOc0wySEhBL3Mx" +
	"RWRrDQpZSXlMT3VrMGRNdy81azdycnNhcW81a3lmS2NZNTZOVE1GRXdIUVlEVlIw" +
	"T0JCWUVGSnV4UTlGSERJZ0NScXM2DQpIdlFsZjd1VmZuL1JNQjhHQTFVZEl3UVlN" +
	"QmFBRkp1eFE5RkhESWdDUnFzNkh2UWxmN3VWZm4vUk1BOEdBMVVkDQpFd0VCL3dR" +
	"Rk1BTUJBZjh3Q3dZSllJWklBV1VEQkFNQ0F6OEFNRHdDSENBRlNxUDdaYmRJU3Nx" +
	"RXBsZDNPM0gzDQpZbGVVTGFQZDRFakhsSDhDSEVQbFlCaXJ1eFRQSVYyY28xZnpD" +
	"ZHo3QjhSRjhNOFRJVnFtcno4PQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ0K"

// ed448SelfSignedCertificate has an Ed448 key.
const ed448SelfSignedCertificate = "" +
	"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlCb0RDQ0FTQ2dBd0lCQWdJ" +
	"VUs1VkVGY1VTcEdXd1dKUUZxamUxMFZYMTVEb3dCUVlESzJWeE1COHhIVEFiDQpC" +
	"Z05WQkFNTUZFOVFUbk5sYm5ObExteHZZMkZzWkc5dFlXbHVNQ0FYRFRJMk1URXhN" +
	"ekU1TlRFME1Wb1lEekl4DQpNall4TURJd01UazFNVFF4V2pBZk1SMHdHd1lEVlFR" +
	"RERCUlBVRTV6Wlc1elpTNXNiMk5oYkdSdmJXRnBiakJEDQpNQVVHQXl0bGNRTTZB" +
	"RUR3Mk5WZkxaV0ZQcEVKMTZ5OERPdkxYRFI5Y2pZRnRxSGdXeDRTQzVNUmF6T3pY" +
	"eUxnDQpVR0NXaVlDWXZRNDBQWWpWeGVUYno3cVlBS05UTUZFd0hRWURWUjBPQkJZ" +
	"RUZQZzVtb3VQelhsdlZIQWRrMUFUDQpYTWxXRmo1ck1COEdBMVVkSXdRWU1CYUFG" +
	"UGc1bW91UHpYbHZWSEFkazFBVFhNbFdGajVyTUE4R0ExVWRFd0VCDQovd1FGTUFN" +
	"QkFmOHdCUVlESzJWeEEzTUFJNXZIZzZNZXVzNmYwcitFRDl2OFNQUXVqWTkvMVJl" +
	"THFFSE9rcFUxDQpLZm5vQkRvMFNtbmkxQXRDQ0Z2ZUdXb2NGeldtUVF6SFFqbUF4" +
	"ZGEwV2xLY1JZQno4NXhKUzk3S3VzdzRqY044DQpHd0lPZkRxQVM2dFdPNzVTL2hB" +
	"ZXdqenRqMnA3SWhWTGZaSVZrVmVoR3pTRWFnWUENCi0tLS0tRU5EIENFUlRJRklD" +
	"QVRFLS0tLS0NCg=="

// nameAttr is one attribute of a distinguished name, with the ASN.1 string
// type its value is encoded in.
type nameAttr struct {
	oid   asn1.ObjectIdentifier
	tag   int
	value string
}

var (
	oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrg        = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrgUnit    = asn1.ObjectIdentifier{2, 5, 4, 11}
)

// rawName encodes attrs as a distinguished name, one attribute per RDN, with
// each value in the string type given.
func rawName(t *testing.T, attrs ...nameAttr) []byte {
	t.Helper()

	seq := make(pkix.RDNSequence, 0, len(attrs))
	for _, a := range attrs {
		seq = append(seq, pkix.RelativeDistinguishedNameSET{{
			Type:  a.oid,
			Value: asn1.RawValue{Tag: a.tag, Bytes: []byte(a.value)},
		}})
	}

	der, err := asn1.Marshal(seq)
	require.NoError(t, err)

	return der
}

// certificateWithNames returns stored certificate data for a certificate
// whose issuer and subject are written exactly as given, signed by its own
// key.
func certificateWithNames(t *testing.T, issuer, subject []byte) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		RawSubject:   subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	parent := *tmpl
	parent.RawSubject = issuer

	der, err := x509.CreateCertificate(rand.Reader, tmpl, &parent, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, issuer, cert.RawIssuer)
	require.Equal(t, subject, cert.RawSubject)

	return storedCertificate(der)
}

// TestFirewallPlugin_ValidWebGUICertificate_NameEncodings pins how issuer and
// subject are compared. OPNsense compares the strings certs_build_name builds
// from openssl_x509_parse: decoded values, attribute types sorted, repeated
// values of one type in order. A certificate whose issuer and subject hold the
// same values in different string types, or in a different attribute order, is
// self-signed there although its DER bytes differ.
func TestFirewallPlugin_ValidWebGUICertificate_NameEncodings(t *testing.T) {
	t.Parallel()

	printable := func(oid asn1.ObjectIdentifier, v string) nameAttr {
		return nameAttr{oid: oid, tag: asn1.TagPrintableString, value: v}
	}
	utf8 := func(oid asn1.ObjectIdentifier, v string) nameAttr {
		return nameAttr{oid: oid, tag: asn1.TagUTF8String, value: v}
	}

	tests := []struct {
		name    string
		issuer  []byte
		subject []byte
		failed  bool
	}{
		{
			name:    "same values, different string types",
			issuer:  rawName(t, printable(oidCommonName, "fw.example.internal"), printable(oidOrg, "Example")),
			subject: rawName(t, utf8(oidCommonName, "fw.example.internal"), utf8(oidOrg, "Example")),
			failed:  true,
		},
		{
			name:    "same values, attributes in a different order",
			issuer:  rawName(t, utf8(oidCommonName, "fw.example.internal"), utf8(oidOrg, "Example")),
			subject: rawName(t, utf8(oidOrg, "Example"), utf8(oidCommonName, "fw.example.internal")),
			failed:  true,
		},
		// Repeated values of one type keep their order in certs_build_name.
		{
			name:    "repeated attribute values in a different order",
			issuer:  rawName(t, utf8(oidOrgUnit, "a"), utf8(oidOrgUnit, "b")),
			subject: rawName(t, utf8(oidOrgUnit, "b"), utf8(oidOrgUnit, "a")),
		},
		{
			name:    "different values, different string types",
			issuer:  rawName(t, printable(oidCommonName, "Internal Root CA")),
			subject: rawName(t, utf8(oidCommonName, "fw.example.internal")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := &common.CommonDevice{
				System: common.System{WebGUI: common.WebGUI{Protocol: "https", SSLCertRef: "web"}},
				Certificates: []common.Certificate{{
					RefID:       "web",
					Certificate: certificateWithNames(t, tt.issuer, tt.subject),
					PrivateKey:  storedKey,
				}},
			}

			assert.Equal(t, certVerdict{evaluated: true, failed: tt.failed}, webGUICertVerdict(t, device))
		})
	}
}
