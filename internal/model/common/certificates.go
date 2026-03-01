package common

// Certificate represents a TLS/SSL certificate.
type Certificate struct {
	// RefID is the unique reference identifier for the certificate.
	RefID string `json:"refId,omitempty" yaml:"refId,omitempty"`
	// Description is a human-readable description of the certificate.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Type is the certificate type (e.g., "server", "user").
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// CARef is the reference ID of the issuing certificate authority.
	CARef string `json:"caRef,omitempty" yaml:"caRef,omitempty"`
	// Certificate is the PEM-encoded certificate data.
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	// PrivateKey is the PEM-encoded private key data.
	//nolint:gosec // Domain model field intentionally represents parsed configuration data, not embedded credentials.
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
	// PrivateKey is the PEM-encoded CA private key data. Present for
	// locally-created CAs; absent for imported external CAs.
	//nolint:gosec // Domain model field intentionally represents parsed configuration data, not embedded credentials.
	PrivateKey string `json:"privateKey,omitempty" yaml:"privateKey,omitempty"`
	// Serial is the next serial number to use when issuing certificates.
	Serial string `json:"serial,omitempty" yaml:"serial,omitempty"`
}
