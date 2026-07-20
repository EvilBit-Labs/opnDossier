// Package pfsense defines the XML schema types for pfSense configuration files.
package pfsense

// Alias represents a single pfSense firewall alias definition (a "named
// object" in ADR-0002 terms), as it appears under the top-level <aliases>
// element in pfSense's config.xml:
//
//	<aliases>
//	  <alias>
//	    <name>WEB_SERVERS</name>
//	    <type>host</type>
//	    <address>10.0.0.1 10.0.0.2</address>
//	    <descr>Web servers</descr>
//	    <detail>comment1||comment2</detail>
//	  </alias>
//	</aliases>
//
// Unlike OPNsense's MVC-model alias (pkg/schema/opnsense.Alias), pfSense has
// no uuid attribute and stores members SPACE-separated in <address> rather
// than newline-separated in <content>.
//
// Type is one of host|network|port per common.NamedObjectType. pfSense also
// supports dynamic alias types (url, urltable, urltable_ports) that have no
// direct common.NamedObjectType equivalent — the converter casts Type as-is
// and emits an "unrecognized named-object type" warning for these per
// GOTCHAS §5.2, the same fail-open pattern used for OPNsense's own dynamic
// variants (e.g. urltable, networkgroup).
type Alias struct {
	Name    string `xml:"name"              json:"name,omitempty"        yaml:"name,omitempty"`
	Type    string `xml:"type"              json:"type,omitempty"        yaml:"type,omitempty"`
	Address string `xml:"address,omitempty" json:"address,omitempty"     yaml:"address,omitempty"`
	Descr   string `xml:"descr,omitempty"   json:"description,omitempty" yaml:"description,omitempty"`
	Detail  string `xml:"detail,omitempty"  json:"detail,omitempty"      yaml:"detail,omitempty"`
}

// AliasList is the container for a set of pfSense firewall alias
// definitions, mapping to the top-level <aliases> XML element.
type AliasList struct {
	Alias []Alias `xml:"alias,omitempty" json:"alias,omitempty" yaml:"alias,omitempty"`
}
