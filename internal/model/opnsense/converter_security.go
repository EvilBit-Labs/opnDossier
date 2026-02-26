package opnsense

import (
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// convertCertificates maps doc.Certs to []common.Certificate.
// Certificate data includes the PEM-encoded certificate and private key, which
// are stored as base64-encoded strings in the OPNsense XML configuration.
func (c *Converter) convertCertificates(doc *schema.OpnSenseDocument) []common.Certificate {
	if len(doc.Certs) == 0 {
		return nil
	}

	result := make([]common.Certificate, 0, len(doc.Certs))
	for _, cert := range doc.Certs {
		result = append(result, common.Certificate{
			RefID:       cert.Refid,
			Description: cert.Descr,
			Certificate: cert.Crt,
			PrivateKey:  cert.Prv,
		})
	}

	return result
}

// convertCAs maps doc.CAs to []common.CertificateAuthority.
// CA entries store the authority's certificate for chain validation. Unlike
// identity certificates, CA entries do not carry a private key field in the
// current OPNsense schema (locally-created CAs may have one in practice).
func (c *Converter) convertCAs(doc *schema.OpnSenseDocument) []common.CertificateAuthority {
	if len(doc.CAs) == 0 {
		return nil
	}

	result := make([]common.CertificateAuthority, 0, len(doc.CAs))
	for _, ca := range doc.CAs {
		result = append(result, common.CertificateAuthority{
			RefID:       ca.Refid,
			Description: ca.Descr,
			Certificate: ca.Crt,
		})
	}

	return result
}

// convertPackages extracts installed firmware plugin names from
// doc.System.Firmware.Plugins. OPNsense stores plugin names as a
// comma-separated string in the XML configuration. Full package metadata
// (versions, descriptions) requires the OPNsense API and is not available
// from config.xml alone.
func (c *Converter) convertPackages(doc *schema.OpnSenseDocument) []common.Package {
	names := splitNonEmpty(doc.System.Firmware.Plugins, ",")
	if len(names) == 0 {
		return nil
	}

	result := make([]common.Package, 0, len(names))
	for _, name := range names {
		result = append(result, common.Package{
			Name:      name,
			Type:      "plugin",
			Installed: true,
		})
	}

	return result
}
