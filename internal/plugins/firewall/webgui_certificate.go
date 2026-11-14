package firewall

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/constants"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// webGUICertificate returns the certificate the web GUI serves, and false
// when the config shows it serves none of its own choosing. Both firewalls
// compare the protocol with "https" exactly (OPNsense webgui.inc
// webgui_configure_do, pfSense system.inc system_webgui_start), so anything
// else is plain HTTP and a reference left behind is unused. Over https, a
// reference that is empty or names no certificate in the store is replaced
// when the GUI starts by a freshly generated self-signed certificate, so it
// never stands for a CA-issued one. pfSense does the same for a certificate
// with no certificate data or no private key, which the caller checks; with
// either missing, OPNsense has nothing it can serve either.
func webGUICertificate(device *common.CommonDevice) (common.Certificate, bool) {
	gui := device.System.WebGUI
	if gui.Protocol != constants.ProtocolHTTPS || gui.SSLCertRef == "" {
		return common.Certificate{}, false
	}

	for _, cert := range device.Certificates {
		if cert.RefID == gui.SSLCertRef {
			return cert, true
		}
	}

	return common.Certificate{}, false
}

// errNoCertificatePEM reports certificate data that holds no PEM certificate
// block, such as truncated or placeholder data.
var errNoCertificatePEM = errors.New("no PEM certificate block")

// parseStoredCertificate decodes certificate data as both firewalls store it:
// the PEM text base64-encoded once more, possibly wrapped over several lines.
// Data that is not base64 is tried as PEM directly.
func parseStoredCertificate(data string) (*x509.Certificate, error) {
	compact := strings.Join(strings.Fields(data), "")

	raw, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		raw = []byte(data)
	}

	for {
		var block *pem.Block

		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, errNoCertificatePEM
		}

		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// isSelfSigned reports whether cert names itself as its issuer, the rule
// OPNsense applies when it imports a certificate (cert_import in certs.inc
// links a CA only when issuer and subject differ). A certificate an internal
// CA issued has the CA as issuer, so it is not self-signed. The signature is
// not checked: Go refuses to verify many keys and algorithms the firewall can
// still hold, such as RSA-512, which the OPNsense Trust pages still offer, and
// DSA, Ed448 and MD5 certificates imported from elsewhere. A refusal must not
// read as "signed by another key".
func isSelfSigned(cert *x509.Certificate) bool {
	return maps.EqualFunc(nameAttributes(cert.Issuer), nameAttributes(cert.Subject), slices.Equal[[]string])
}

// nameAttributes groups the decoded values of a distinguished name by
// attribute type, each type's values in the order they appear. OPNsense
// compares issuer and subject as the strings certs_build_name builds from
// openssl_x509_parse: decoded values, so a PrintableString and a UTF8String
// holding the same text match, and attribute types sorted (ksort), so their
// order does not matter, while repeated values of one type keep their order.
// Comparing the DER bytes instead would read such a self-signed certificate
// as issued by someone else.
func nameAttributes(name pkix.Name) map[string][]string {
	attrs := make(map[string][]string, len(name.Names))

	for _, atv := range name.Names {
		key := atv.Type.String()
		attrs[key] = append(attrs[key], fmt.Sprint(atv.Value))
	}

	return attrs
}
