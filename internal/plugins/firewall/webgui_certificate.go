package firewall

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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
// with no certificate data, which the caller checks.
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
// block, such as a truncated or redacted value.
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

// isSelfSigned reports whether cert names itself as its issuer and is signed
// by its own key. A certificate an internal CA issued has the CA as issuer,
// so it is not self-signed. A self-issued certificate whose signature uses an
// algorithm Go refuses to verify, such as MD5, counts as self-signed: the key
// cannot be checked, and reading it the other way would pass the control on
// an old self-signed certificate.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}

	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		return true
	}

	var insecure x509.InsecureAlgorithmError

	return errors.As(err, &insecure)
}
