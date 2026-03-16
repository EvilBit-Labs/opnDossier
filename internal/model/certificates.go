// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// CertificateAuthority represents certificate authority configuration.
type CertificateAuthority = schema.CertificateAuthority

// DHCPv6Server represents DHCPv6 server configuration.
type DHCPv6Server = schema.DHCPv6Server
