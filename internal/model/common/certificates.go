package common

// Certificate represents a TLS/SSL certificate.
type Certificate struct {
	// RefID is the unique reference identifier for the certificate.
	RefID string `json:"refId,omitempty" yaml:"refId,omitempty"`
	// Description is a human-readable description of the certificate.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Certificate is the PEM-encoded certificate data.
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	// PrivateKey is the PEM-encoded private key data.
	PrivateKey string `json:"privateKey,omitempty" yaml:"privateKey,omitempty"`
}

// CertificateAuthority represents a certificate authority.
type CertificateAuthority struct {
	// RefID is the unique reference identifier for the CA.
	RefID string `json:"refId,omitempty" yaml:"refId,omitempty"`
	// Description is a human-readable description of the CA.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Certificate is the PEM-encoded CA certificate data.
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
}
