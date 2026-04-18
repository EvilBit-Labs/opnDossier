// Package opnsense defines the data structures for OPNsense configurations.
package opnsense

// UnboundPlus contains the full Unbound DNS resolver MVC configuration as stored
// under <OPNsense><unboundplus> in config.xml. Element names are pinned to the
// OPNsense Unbound MVC model (validated against v1.0.x as of 2026-04). If a future
// OPNsense release renames any of these elements (for example, <privateaddress>),
// the Go XML decoder will silently produce empty values — no error, no warning.
// See GOTCHAS 18.1 for the analogous Kea MVC version-pinning concern.
//
// Fields are intentionally typed as `string` to preserve XML round-trip fidelity.
// Truthy parsing (e.g., "0"/"1") is performed by the converter, not the schema.
// JSON tags are intentionally omitted on leaf fields so that JSON marshaling
// uses Go field names (PascalCase), matching the pre-refactor inline-struct
// serialization shape. Changing this would be a breaking JSON-export change
// for downstream consumers of the OpnSenseDocument model.
type UnboundPlus struct {
	Text       string                `xml:",chardata"    json:"text,omitempty"`
	Version    string                `xml:"version,attr" json:"version,omitempty"`
	General    UnboundPlusGeneral    `xml:"general"      json:"general"`
	Advanced   UnboundPlusAdvanced   `xml:"advanced"     json:"advanced"`
	Acls       UnboundPlusAcls       `xml:"acls"         json:"acls"`
	Dnsbl      UnboundPlusDnsbl      `xml:"dnsbl"        json:"dnsbl"`
	Forwarding UnboundPlusForwarding `xml:"forwarding"   json:"forwarding"`
	Dots       string                `xml:"dots"`
	Hosts      string                `xml:"hosts"`
	Aliases    string                `xml:"aliases"`
	Domains    string                `xml:"domains"`
}

// UnboundPlusGeneral mirrors the <general> block under <unboundplus>.
type UnboundPlusGeneral struct {
	Text               string `xml:",chardata"          json:"text,omitempty"`
	Enabled            string `xml:"enabled"`
	Port               string `xml:"port"`
	Stats              string `xml:"stats"`
	ActiveInterface    string `xml:"active_interface"`
	Dnssec             string `xml:"dnssec"`
	DNS64              string `xml:"dns64"`
	DNS64prefix        string `xml:"dns64prefix"`
	Noarecords         string `xml:"noarecords"`
	RegisterDHCP       string `xml:"regdhcp"`
	RegisterDHCPDomain string `xml:"regdhcpdomain"`
	RegisterDHCPStatic string `xml:"regdhcpstatic"`
	NoRegisterLLAddr6  string `xml:"noreglladdr6"`
	NoRegisterRecords  string `xml:"noregrecords"`
	Txtsupport         string `xml:"txtsupport"`
	Cacheflush         string `xml:"cacheflush"`
	LocalZoneType      string `xml:"local_zone_type"`
	OutgoingInterface  string `xml:"outgoing_interface"`
	EnableWpad         string `xml:"enable_wpad"`
}

// UnboundPlusAdvanced mirrors the <advanced> block under <unboundplus>.
// Privateaddress holds the DNS rebind protection list (Unbound `private-address`
// directive): a separator-delimited list of CIDR ranges whose presence in a DNS
// response causes Unbound to treat the response as a rebinding attempt.
type UnboundPlusAdvanced struct {
	Text                      string `xml:",chardata"                 json:"text,omitempty"`
	Hideidentity              string `xml:"hideidentity"`
	Hideversion               string `xml:"hideversion"`
	Prefetch                  string `xml:"prefetch"`
	Prefetchkey               string `xml:"prefetchkey"`
	Dnssecstripped            string `xml:"dnssecstripped"`
	Aggressivensec            string `xml:"aggressivensec"`
	Serveexpired              string `xml:"serveexpired"`
	Serveexpiredreplyttl      string `xml:"serveexpiredreplyttl"`
	Serveexpiredttl           string `xml:"serveexpiredttl"`
	Serveexpiredttlreset      string `xml:"serveexpiredttlreset"`
	Serveexpiredclienttimeout string `xml:"serveexpiredclienttimeout"`
	Qnameminstrict            string `xml:"qnameminstrict"`
	Extendedstatistics        string `xml:"extendedstatistics"`
	Logqueries                string `xml:"logqueries"`
	Logreplies                string `xml:"logreplies"`
	Logtagqueryreply          string `xml:"logtagqueryreply"`
	Logservfail               string `xml:"logservfail"`
	Loglocalactions           string `xml:"loglocalactions"`
	Logverbosity              string `xml:"logverbosity"`
	Valloglevel               string `xml:"valloglevel"`
	Privatedomain             string `xml:"privatedomain"`
	Privateaddress            string `xml:"privateaddress"`
	Insecuredomain            string `xml:"insecuredomain"`
	Msgcachesize              string `xml:"msgcachesize"`
	Rrsetcachesize            string `xml:"rrsetcachesize"`
	Outgoingnumtcp            string `xml:"outgoingnumtcp"`
	Incomingnumtcp            string `xml:"incomingnumtcp"`
	Numqueriesperthread       string `xml:"numqueriesperthread"`
	Outgoingrange             string `xml:"outgoingrange"`
	Jostletimeout             string `xml:"jostletimeout"`
	Discardtimeout            string `xml:"discardtimeout"`
	Cachemaxttl               string `xml:"cachemaxttl"`
	Cachemaxnegativettl       string `xml:"cachemaxnegativettl"`
	Cacheminttl               string `xml:"cacheminttl"`
	Infrahostttl              string `xml:"infrahostttl"`
	Infrakeepprobing          string `xml:"infrakeepprobing"`
	Infracachenumhosts        string `xml:"infracachenumhosts"`
	Unwantedreplythreshold    string `xml:"unwantedreplythreshold"`
}

// UnboundPlusAcls mirrors the <acls> block under <unboundplus>.
type UnboundPlusAcls struct {
	Text          string `xml:",chardata" json:"text,omitempty"`
	DefaultAction string `xml:"default_action"`
}

// UnboundPlusDnsbl mirrors the <dnsbl> block under <unboundplus>.
type UnboundPlusDnsbl struct {
	Text       string `xml:",chardata" json:"text,omitempty"`
	Enabled    string `xml:"enabled"`
	Safesearch string `xml:"safesearch"`
	Type       string `xml:"type"`
	Lists      string `xml:"lists"`
	Whitelists string `xml:"whitelists"`
	Blocklists string `xml:"blocklists"`
	Wildcards  string `xml:"wildcards"`
	Address    string `xml:"address"`
	Nxdomain   string `xml:"nxdomain"`
}

// UnboundPlusForwarding mirrors the <forwarding> block under <unboundplus>.
type UnboundPlusForwarding struct {
	Text    string `xml:",chardata" json:"text,omitempty"`
	Enabled string `xml:"enabled"`
}
