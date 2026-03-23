// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// IPsec represents the top-level IPsec VPN configuration container.
type IPsec struct {
	Phase1  []IPsecPhase1 `xml:"phase1,omitempty"  json:"phase1,omitempty" yaml:"phase1,omitempty"`
	Phase2  []IPsecPhase2 `xml:"phase2,omitempty"  json:"phase2,omitempty" yaml:"phase2,omitempty"`
	Client  IPsecClient   `xml:"client,omitempty"  json:"client"           yaml:"client,omitempty"`
	Logging IPsecLogging  `xml:"logging,omitempty" json:"logging"          yaml:"logging,omitempty"`
}

// NewIPsec returns a new IPsec configuration with Phase1 and Phase2 slices initialized for safe use.
func NewIPsec() IPsec {
	return IPsec{
		Phase1: make([]IPsecPhase1, 0),
		Phase2: make([]IPsecPhase2, 0),
	}
}

// IPsecPhase1 represents a single IKE Phase 1 (SA) entry.
// Phase 1 entries are listtags in pfSense config.xml.
type IPsecPhase1 struct {
	IKEId      string `xml:"ikeid,omitempty"                 json:"ikeId,omitempty"                yaml:"ikeId,omitempty"`
	IKEType    string `xml:"iketype,omitempty"               json:"ikeType,omitempty"              yaml:"ikeType,omitempty"`
	Interface  string `xml:"interface,omitempty"             json:"interface,omitempty"            yaml:"interface,omitempty"`
	RemoteGW   string `xml:"remote-gateway,omitempty"        json:"remoteGateway,omitempty"        yaml:"remoteGateway,omitempty"`
	Protocol   string `xml:"protocol,omitempty"              json:"protocol,omitempty"             yaml:"protocol,omitempty"`
	MyIDType   string `xml:"myid_type,omitempty"             json:"myIdType,omitempty"             yaml:"myIdType,omitempty"`
	MyIDData   string `xml:"myid_data,omitempty"             json:"myIdData,omitempty"             yaml:"myIdData,omitempty"`
	PeerIDType string `xml:"peerid_type,omitempty"           json:"peerIdType,omitempty"           yaml:"peerIdType,omitempty"`
	PeerIDData string `xml:"peerid_data,omitempty"           json:"peerIdData,omitempty"           yaml:"peerIdData,omitempty"`
	AuthMethod string `xml:"authentication_method,omitempty" json:"authenticationMethod,omitempty" yaml:"authenticationMethod,omitempty"`
	// PreSharedKey is the IPsec pre-shared key. Intentionally excluded from the common model
	// (secrets must not reach the export pipeline). The sanitizer handles this at the XML level.
	// If this field is ever mapped to common.IPsecPhase1Tunnel, redactedCopyUnsafe() in
	// internal/processor/report.go MUST be updated to redact it.
	PreSharedKey string                `xml:"pre-shared-key,omitempty" json:"-"                      yaml:"-"`
	CertRef      string                `xml:"certref,omitempty"        json:"certRef,omitempty"      yaml:"certRef,omitempty"`
	CARef        string                `xml:"caref,omitempty"          json:"caRef,omitempty"        yaml:"caRef,omitempty"`
	Lifetime     string                `xml:"lifetime,omitempty"       json:"lifetime,omitempty"     yaml:"lifetime,omitempty"`
	RekeyTime    string                `xml:"rekey_time,omitempty"     json:"rekeyTime,omitempty"    yaml:"rekeyTime,omitempty"`
	ReauthTime   string                `xml:"reauth_time,omitempty"    json:"reauthTime,omitempty"   yaml:"reauthTime,omitempty"`
	RandTime     string                `xml:"rand_time,omitempty"      json:"randTime,omitempty"     yaml:"randTime,omitempty"`
	Mode         string                `xml:"mode,omitempty"           json:"mode,omitempty"         yaml:"mode,omitempty"`
	NATTraversal string                `xml:"nat_traversal,omitempty"  json:"natTraversal,omitempty" yaml:"natTraversal,omitempty"`
	Mobike       string                `xml:"mobike,omitempty"         json:"mobike,omitempty"       yaml:"mobike,omitempty"`
	DPDDelay     string                `xml:"dpd_delay,omitempty"      json:"dpdDelay,omitempty"     yaml:"dpdDelay,omitempty"`
	DPDMaxFail   string                `xml:"dpd_maxfail,omitempty"    json:"dpdMaxFail,omitempty"   yaml:"dpdMaxFail,omitempty"`
	StartAction  string                `xml:"startaction,omitempty"    json:"startAction,omitempty"  yaml:"startAction,omitempty"`
	CloseAction  string                `xml:"closeaction,omitempty"    json:"closeAction,omitempty"  yaml:"closeAction,omitempty"`
	Disabled     opnsense.BoolFlag     `xml:"disabled,omitempty"       json:"disabled"               yaml:"disabled,omitempty"`
	Descr        string                `xml:"descr,omitempty"          json:"descr,omitempty"        yaml:"descr,omitempty"`
	Mobile       opnsense.BoolFlag     `xml:"mobile,omitempty"         json:"mobile"                 yaml:"mobile,omitempty"`
	IKEPort      string                `xml:"ikeport,omitempty"        json:"ikePort,omitempty"      yaml:"ikePort,omitempty"`
	NATTPort     string                `xml:"nattport,omitempty"       json:"nattPort,omitempty"     yaml:"nattPort,omitempty"`
	SplitConn    string                `xml:"splitconn,omitempty"      json:"splitConn,omitempty"    yaml:"splitConn,omitempty"`
	Encryption   IPsecPhase1Encryption `xml:"encryption,omitempty"     json:"encryption"             yaml:"encryption,omitempty"`
}

// ipsecPhase1Alias is a type alias used to break the recursion in IPsecPhase1.MarshalXML.
// encoding/xml would infinitely recurse if MarshalXML called EncodeElement on the same type.
type ipsecPhase1Alias IPsecPhase1

// MarshalXML implements custom XML marshaling for IPsecPhase1, ensuring that the
// Disabled and Mobile BoolFlag fields are addressable so (*BoolFlag).MarshalXML is invoked.
// Without this, direct xml.Marshal calls on IPsecPhase1 values would fall back to
// default bool serialization instead of producing pfSense-compatible presence elements.
// Uses a value receiver so both value and pointer marshaling work correctly.
func (p IPsecPhase1) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement((*ipsecPhase1Alias)(&p), start)
}

// IPsecPhase1Encryption wraps the encryption sub-element containing algorithm options for Phase 1.
type IPsecPhase1Encryption struct {
	Algorithms []IPsecEncryptionAlgorithm `xml:"encryption-algorithm-option,omitempty" json:"algorithms,omitempty" yaml:"algorithms,omitempty"`
}

// IPsecPhase2 represents a single IPsec Phase 2 (child SA) entry.
// Phase 2 entries are listtags in pfSense config.xml.
type IPsecPhase2 struct {
	IKEId                string                     `xml:"ikeid,omitempty"                       json:"ikeId,omitempty"                yaml:"ikeId,omitempty"`
	UniqID               string                     `xml:"uniqid,omitempty"                      json:"uniqId,omitempty"               yaml:"uniqId,omitempty"`
	Mode                 string                     `xml:"mode,omitempty"                        json:"mode,omitempty"                 yaml:"mode,omitempty"`
	Disabled             opnsense.BoolFlag          `xml:"disabled,omitempty"                    json:"disabled"                       yaml:"disabled,omitempty"`
	ReqID                string                     `xml:"reqid,omitempty"                       json:"reqId,omitempty"                yaml:"reqId,omitempty"`
	LocalID              IPsecID                    `xml:"localid,omitempty"                     json:"localId"                        yaml:"localId,omitempty"`
	RemoteID             IPsecID                    `xml:"remoteid,omitempty"                    json:"remoteId"                       yaml:"remoteId,omitempty"`
	NATLocalID           IPsecID                    `xml:"natlocalid,omitempty"                  json:"natLocalId"                     yaml:"natLocalId,omitempty"`
	Protocol             string                     `xml:"protocol,omitempty"                    json:"protocol,omitempty"             yaml:"protocol,omitempty"`
	EncryptionAlgorithms []IPsecEncryptionAlgorithm `xml:"encryption-algorithm-option,omitempty" json:"encryptionAlgorithms,omitempty" yaml:"encryptionAlgorithms,omitempty"`
	HashAlgorithms       []IPsecHashAlgorithm       `xml:"hash-algorithm-option,omitempty"       json:"hashAlgorithms,omitempty"       yaml:"hashAlgorithms,omitempty"`
	PFSGroup             string                     `xml:"pfsgroup,omitempty"                    json:"pfsGroup,omitempty"             yaml:"pfsGroup,omitempty"`
	Lifetime             string                     `xml:"lifetime,omitempty"                    json:"lifetime,omitempty"             yaml:"lifetime,omitempty"`
	PingHost             string                     `xml:"pinghost,omitempty"                    json:"pingHost,omitempty"             yaml:"pingHost,omitempty"`
	Descr                string                     `xml:"descr,omitempty"                       json:"descr,omitempty"                yaml:"descr,omitempty"`
}

// ipsecPhase2Alias is a type alias used to break the recursion in IPsecPhase2.MarshalXML.
// encoding/xml would infinitely recurse if MarshalXML called EncodeElement on the same type.
type ipsecPhase2Alias IPsecPhase2

// MarshalXML implements custom XML marshaling for IPsecPhase2, ensuring that the
// Disabled BoolFlag field is addressable so (*BoolFlag).MarshalXML is invoked.
// Without this, direct xml.Marshal calls on IPsecPhase2 values would fall back to
// default bool serialization instead of producing pfSense-compatible presence elements.
// Uses a value receiver so both value and pointer marshaling work correctly.
func (p IPsecPhase2) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement((*ipsecPhase2Alias)(&p), start)
}

// IPsecEncryptionAlgorithm represents a single encryption algorithm option used in Phase 1 and Phase 2.
type IPsecEncryptionAlgorithm struct {
	Name   string `xml:"name,omitempty"   json:"name,omitempty"   yaml:"name,omitempty"`
	KeyLen string `xml:"keylen,omitempty" json:"keyLen,omitempty" yaml:"keyLen,omitempty"`
}

// IPsecHashAlgorithm represents a single hash algorithm option used in Phase 2.
type IPsecHashAlgorithm struct {
	Name string `xml:"name,omitempty" json:"name,omitempty" yaml:"name,omitempty"`
}

// IPsecID represents a network identity element, used for localid, remoteid,
// and natlocalid in IPsec configurations.
type IPsecID struct {
	Type    string `xml:"type,omitempty"    json:"type,omitempty"    yaml:"type,omitempty"`
	Address string `xml:"address,omitempty" json:"address,omitempty" yaml:"address,omitempty"`
	Netbits string `xml:"netbits,omitempty" json:"netbits,omitempty" yaml:"netbits,omitempty"`
}

// IPsecClient represents the mobile IPsec client pool configuration
// (the <client> element within <ipsec>).
type IPsecClient struct {
	Enable      opnsense.BoolFlag `xml:"enable,omitempty"          json:"enable"                  yaml:"enable,omitempty"`
	UserSource  string            `xml:"user_source,omitempty"     json:"userSource,omitempty"    yaml:"userSource,omitempty"`
	GroupSource string            `xml:"group_source,omitempty"    json:"groupSource,omitempty"   yaml:"groupSource,omitempty"`
	PoolAddress string            `xml:"pool_address,omitempty"    json:"poolAddress,omitempty"   yaml:"poolAddress,omitempty"`
	PoolNetbits string            `xml:"pool_netbits,omitempty"    json:"poolNetbits,omitempty"   yaml:"poolNetbits,omitempty"`
	PoolAddrV6  string            `xml:"pool_address_v6,omitempty" json:"poolAddressV6,omitempty" yaml:"poolAddressV6,omitempty"`
	PoolNetV6   string            `xml:"pool_netbits_v6,omitempty" json:"poolNetbitsV6,omitempty" yaml:"poolNetbitsV6,omitempty"`
	DNSServer1  string            `xml:"dns_server1,omitempty"     json:"dnsServer1,omitempty"    yaml:"dnsServer1,omitempty"`
	DNSServer2  string            `xml:"dns_server2,omitempty"     json:"dnsServer2,omitempty"    yaml:"dnsServer2,omitempty"`
	DNSServer3  string            `xml:"dns_server3,omitempty"     json:"dnsServer3,omitempty"    yaml:"dnsServer3,omitempty"`
	DNSServer4  string            `xml:"dns_server4,omitempty"     json:"dnsServer4,omitempty"    yaml:"dnsServer4,omitempty"`
	WINSServer1 string            `xml:"wins_server1,omitempty"    json:"winsServer1,omitempty"   yaml:"winsServer1,omitempty"`
	WINSServer2 string            `xml:"wins_server2,omitempty"    json:"winsServer2,omitempty"   yaml:"winsServer2,omitempty"`
	DNSDomain   string            `xml:"dns_domain,omitempty"      json:"dnsDomain,omitempty"     yaml:"dnsDomain,omitempty"`
	DNSSplit    string            `xml:"dns_split,omitempty"       json:"dnsSplit,omitempty"      yaml:"dnsSplit,omitempty"`
	LoginBanner string            `xml:"login_banner,omitempty"    json:"loginBanner,omitempty"   yaml:"loginBanner,omitempty"`
	SavePasswd  opnsense.BoolFlag `xml:"save_passwd,omitempty"     json:"savePasswd"              yaml:"savePasswd,omitempty"`
}

// ipsecClientAlias is a type alias used to break the recursion in IPsecClient.MarshalXML.
// encoding/xml would infinitely recurse if MarshalXML called EncodeElement on the same type.
type ipsecClientAlias IPsecClient

// MarshalXML implements custom XML marshaling for IPsecClient, ensuring that the
// Enable and SavePasswd BoolFlag fields are addressable so (*BoolFlag).MarshalXML is invoked.
// Without this, direct xml.Marshal calls on IPsecClient values would fall back to
// default bool serialization instead of producing pfSense-compatible presence elements.
// Uses a value receiver so both value and pointer marshaling work correctly.
func (c IPsecClient) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement((*ipsecClientAlias)(&c), start)
}

// IPsecLogging represents per-subsystem strongSwan log level configuration.
// Parsed from config.xml but intentionally not mapped to the common model — log
// levels are daemon tuning, not security-relevant configuration for audit/export.
type IPsecLogging struct {
	// Dmn is the strongSwan daemon (main process) log level.
	Dmn string `xml:"dmn,omitempty" json:"dmn,omitempty" yaml:"dmn,omitempty"`
	// Mgr is the IKE SA manager log level.
	Mgr string `xml:"mgr,omitempty" json:"mgr,omitempty" yaml:"mgr,omitempty"`
	// Ike is the IKE protocol log level.
	Ike string `xml:"ike,omitempty" json:"ike,omitempty" yaml:"ike,omitempty"`
	// Chd is the child SA (IPsec SA) log level.
	Chd string `xml:"chd,omitempty" json:"chd,omitempty" yaml:"chd,omitempty"`
	// Job is the job processing log level.
	Job string `xml:"job,omitempty" json:"job,omitempty" yaml:"job,omitempty"`
	// Cfg is the configuration backend log level.
	Cfg string `xml:"cfg,omitempty" json:"cfg,omitempty" yaml:"cfg,omitempty"`
	// Knl is the kernel interface log level.
	Knl string `xml:"knl,omitempty" json:"knl,omitempty" yaml:"knl,omitempty"`
	// Net is the networking log level.
	Net string `xml:"net,omitempty" json:"net,omitempty" yaml:"net,omitempty"`
	// Asn is the ASN.1 encoding/decoding log level.
	Asn string `xml:"asn,omitempty" json:"asn,omitempty" yaml:"asn,omitempty"`
	// Enc is the cryptographic operations log level.
	Enc string `xml:"enc,omitempty" json:"enc,omitempty" yaml:"enc,omitempty"`
	// Lib is the strongSwan library log level.
	Lib string `xml:"lib,omitempty" json:"lib,omitempty" yaml:"lib,omitempty"`
}
