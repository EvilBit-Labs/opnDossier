// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// CertificateAuthority represents certificate authority configuration.
type CertificateAuthority = schema.CertificateAuthority

// DHCPv6Server represents DHCPv6 server configuration.
type DHCPv6Server = schema.DHCPv6Server
