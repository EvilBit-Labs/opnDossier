// Package opnsense defines the data structures for OPNsense configurations.
package opnsense

import "encoding/xml"

// UnboundPlus contains the full Unbound DNS resolver MVC configuration as stored
// under <OPNsense><unboundplus> in config.xml. Element names are pinned to the
// OPNsense Unbound MVC model (validated against version attributes listed in
// `knownUnboundPlusVersions` in the OPNsense converter). If a future OPNsense
// release renames any of these elements (for example, <privateaddress>), the
// Go XML decoder will silently produce empty values — no error, no warning.
// The converter emits a drift warning when the <unboundplus version="..."> attr
// falls outside the known-good set. See GOTCHAS 18.1 for the analogous Kea MVC
// version-pinning concern.
//
// Fields are intentionally typed as `string` to preserve XML round-trip fidelity.
// Truthy parsing (strict exact-match against "1") is performed by the converter,
// not the schema. The top-level container fields (Dots, Hosts, Aliases, Domains)
// use `*string` so "element absent" (nil) and "element present but empty" ("")
// are distinguishable across a marshal/unmarshal round-trip (GOTCHAS 3.2).
//
// JSON tags are omitted on the leaf *config* fields (Enabled, Port, Hideidentity,
// Privateaddress, etc.) so JSON marshaling uses Go field names (PascalCase),
// matching the pre-refactor inline-struct serialization shape. Fields that map
// to XML text/attributes (Text, Version) retain their json tags. The *string
// container fields (Dots/Hosts/Aliases/Domains) carry explicit PascalCase json
// tags with `omitempty` — without the tag a nil pointer would emit `null`
// (a shape change from the previous empty-string behavior), and without the
// PascalCase name JSON would downcase the Go field name. `omitempty` omits
// nil pointers entirely; populated pointers emit as strings. Changing any of
// these conventions is a breaking JSON-export change for downstream consumers
// of the OpnSenseDocument model.
type UnboundPlus struct {
	XMLName    xml.Name              `xml:"unboundplus"  json:"-"`
	Text       string                `xml:",chardata"    json:"text,omitempty"`
	Version    string                `xml:"version,attr" json:"version,omitempty"` // OPNsense MVC model version, e.g., "1.0.0"
	General    UnboundPlusGeneral    `xml:"general"      json:"general"`
	Advanced   UnboundPlusAdvanced   `xml:"advanced"     json:"advanced"`
	Acls       UnboundPlusAcls       `xml:"acls"         json:"acls"`
	Dnsbl      UnboundPlusDnsbl      `xml:"dnsbl"        json:"dnsbl"`
	Forwarding UnboundPlusForwarding `xml:"forwarding"   json:"forwarding"`
	// Dots, Hosts, Aliases, Domains are container references typed as *string
	// so absent vs. present-but-empty elements survive XML round-trip.
	// Explicit PascalCase `json` tags with `omitempty` preserve the pre-refactor
	// Go-field-name casing and keep zero-value JSON output compact (nil pointers
	// are omitted instead of emitting `null`).
	Dots    *string `xml:"dots"    json:"Dots,omitempty"`    // DNS-over-TLS config reference
	Hosts   *string `xml:"hosts"   json:"Hosts,omitempty"`   // host override references
	Aliases *string `xml:"aliases" json:"Aliases,omitempty"` // host alias references
	Domains *string `xml:"domains" json:"Domains,omitempty"` // domain override references
}

// UnboundPlusGeneral mirrors the <general> block under <unboundplus>.
// All fields are stored verbatim from config.xml; truthy values are "0" / "1"
// unless otherwise noted.
type UnboundPlusGeneral struct {
	Text               string `xml:",chardata"          json:"text,omitempty"`
	Enabled            string `xml:"enabled"`          // "0" or "1"
	Port               string `xml:"port"`             // numeric port string, e.g., "53"
	Stats              string `xml:"stats"`            // "0" or "1"
	ActiveInterface    string `xml:"active_interface"` // interface name, e.g., "lan"
	Dnssec             string `xml:"dnssec"`           // "0" or "1"
	DNS64              string `xml:"dns64"`            // "0" or "1"
	DNS64prefix        string `xml:"dns64prefix"`      // IPv6 prefix, e.g., "64:ff9b::/96"
	Noarecords         string `xml:"noarecords"`       // "0" or "1"
	RegisterDHCP       string `xml:"regdhcp"`          // "0" or "1"
	RegisterDHCPDomain string `xml:"regdhcpdomain"`    // "0" or "1"
	RegisterDHCPStatic string `xml:"regdhcpstatic"`    // "0" or "1"
	NoRegisterLLAddr6  string `xml:"noreglladdr6"`     // "0" or "1"
	NoRegisterRecords  string `xml:"noregrecords"`     // "0" or "1"
	Txtsupport         string `xml:"txtsupport"`       // "0" or "1"
	Cacheflush         string `xml:"cacheflush"`       // "0" or "1"
	LocalZoneType      string `xml:"local_zone_type"`  // e.g., "transparent", "static"
	OutgoingInterface  string `xml:"outgoing_interface"`
	EnableWpad         string `xml:"enable_wpad"` // "0" or "1"
}

// UnboundPlusAdvanced mirrors the <advanced> block under <unboundplus>. All
// fields are stored verbatim from config.xml; boolean fields use "0" / "1"
// and cache/TTL fields are decimal strings unless otherwise noted.
// Privateaddress holds the DNS rebind protection list (Unbound `private-address`
// directive): a separator-delimited list of CIDR ranges whose presence in a DNS
// response causes Unbound to treat the response as a rebinding attempt.
type UnboundPlusAdvanced struct {
	Text                      string `xml:",chardata"                 json:"text,omitempty"`
	Hideidentity              string `xml:"hideidentity"`              // "0" or "1"; hides Unbound identity in responses
	Hideversion               string `xml:"hideversion"`               // "0" or "1"; hides Unbound version string
	Prefetch                  string `xml:"prefetch"`                  // "0" or "1"; cache-warm near-expiry messages
	Prefetchkey               string `xml:"prefetchkey"`               // "0" or "1"
	Dnssecstripped            string `xml:"dnssecstripped"`            // "0" or "1"
	Aggressivensec            string `xml:"aggressivensec"`            // "0" or "1"
	Serveexpired              string `xml:"serveexpired"`              // "0" or "1"
	Serveexpiredreplyttl      string `xml:"serveexpiredreplyttl"`      // seconds, decimal
	Serveexpiredttl           string `xml:"serveexpiredttl"`           // seconds, decimal
	Serveexpiredttlreset      string `xml:"serveexpiredttlreset"`      // "0" or "1"
	Serveexpiredclienttimeout string `xml:"serveexpiredclienttimeout"` // milliseconds, decimal
	Qnameminstrict            string `xml:"qnameminstrict"`            // "0" or "1"
	Extendedstatistics        string `xml:"extendedstatistics"`        // "0" or "1"
	Logqueries                string `xml:"logqueries"`                // "0" or "1"
	Logreplies                string `xml:"logreplies"`                // "0" or "1"
	Logtagqueryreply          string `xml:"logtagqueryreply"`          // "0" or "1"
	Logservfail               string `xml:"logservfail"`               // "0" or "1"
	Loglocalactions           string `xml:"loglocalactions"`           // "0" or "1"
	Logverbosity              string `xml:"logverbosity"`              // decimal, typically "0".."5"
	Valloglevel               string `xml:"valloglevel"`               // decimal, typically "0".."2"
	Privatedomain             string `xml:"privatedomain"`             // separator-delimited domain list
	// Privateaddress is a separator-delimited CIDR/IP list powering Unbound's
	// DNS rebind protection. *string so an absent element ("MVC advanced
	// section never configured") is distinguishable from an element present
	// but empty ("configured, cleared out") — see GOTCHAS 3.2. The converter
	// carries this distinction through to common.UnboundConfig so the firewall
	// plugin can treat unknown and configured-empty differently.
	Privateaddress         *string `xml:"privateaddress"         json:",omitempty"`
	Insecuredomain         string  `xml:"insecuredomain"`         // separator-delimited domain list
	Msgcachesize           string  `xml:"msgcachesize"`           // bytes, decimal
	Rrsetcachesize         string  `xml:"rrsetcachesize"`         // bytes, decimal
	Outgoingnumtcp         string  `xml:"outgoingnumtcp"`         // decimal
	Incomingnumtcp         string  `xml:"incomingnumtcp"`         // decimal
	Numqueriesperthread    string  `xml:"numqueriesperthread"`    // decimal
	Outgoingrange          string  `xml:"outgoingrange"`          // decimal
	Jostletimeout          string  `xml:"jostletimeout"`          // milliseconds, decimal
	Discardtimeout         string  `xml:"discardtimeout"`         // milliseconds, decimal
	Cachemaxttl            string  `xml:"cachemaxttl"`            // seconds, decimal
	Cachemaxnegativettl    string  `xml:"cachemaxnegativettl"`    // seconds, decimal
	Cacheminttl            string  `xml:"cacheminttl"`            // seconds, decimal
	Infrahostttl           string  `xml:"infrahostttl"`           // seconds, decimal
	Infrakeepprobing       string  `xml:"infrakeepprobing"`       // "0" or "1"
	Infracachenumhosts     string  `xml:"infracachenumhosts"`     // decimal
	Unwantedreplythreshold string  `xml:"unwantedreplythreshold"` // decimal
}

// UnboundPlusAcls mirrors the <acls> block under <unboundplus>.
type UnboundPlusAcls struct {
	Text          string `xml:",chardata"      json:"text,omitempty"`
	DefaultAction string `xml:"default_action"` // e.g., "allow", "deny"
}

// UnboundPlusDnsbl mirrors the <dnsbl> block under <unboundplus>.
// All boolean fields use "0" / "1".
type UnboundPlusDnsbl struct {
	Text       string `xml:",chardata"  json:"text,omitempty"`
	Enabled    string `xml:"enabled"`    // "0" or "1"
	Safesearch string `xml:"safesearch"` // "0" or "1"
	Type       string `xml:"type"`       // blocklist category keyword, e.g., "ads"
	Lists      string `xml:"lists"`      // separator-delimited DNSBL feed names
	Whitelists string `xml:"whitelists"` // separator-delimited allow patterns
	Blocklists string `xml:"blocklists"` // separator-delimited block patterns
	Wildcards  string `xml:"wildcards"`  // separator-delimited wildcard patterns
	Address    string `xml:"address"`    // override IP for blocked lookups
	Nxdomain   string `xml:"nxdomain"`   // "0" or "1"; return NXDOMAIN for blocked names
}

// UnboundPlusForwarding mirrors the <forwarding> block under <unboundplus>.
type UnboundPlusForwarding struct {
	Text    string `xml:",chardata" json:"text,omitempty"`
	Enabled string `xml:"enabled"` // "0" or "1"
}
