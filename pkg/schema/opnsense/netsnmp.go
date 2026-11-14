package opnsense

// Netsnmp is the os-net-snmp plugin's configuration, stored under
// <OPNsense><netsnmp>. The plugin's two MVC models mount at
// //OPNsense/netsnmp/general and //OPNsense/netsnmp/user, so each carries its
// own version attribute. From 19.1 this plugin is the only SNMP agent
// OPNsense ships: core dropped its own agent at 17.1, and the os-snmp plugin
// that took over the legacy <snmpd> element was removed in 19.1.
//
// Every leaf is a string: the agent's templates compare the raw values with
// "1", and the converter does the same.
type Netsnmp struct {
	General NetsnmpGeneral `xml:"general" json:"general" yaml:"general"`
	User    NetsnmpUsers   `xml:"user"    json:"user"    yaml:"user"`
}

// NetsnmpGeneral is the general model of the os-net-snmp plugin
// (Netsnmp/General.xml). Its element names are unchanged from model version
// 1.0.0 to 1.0.7; the converter warns on a version it has not been checked
// against.
type NetsnmpGeneral struct {
	Version string `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Enabled string `xml:"enabled"                json:"enabled"           yaml:"enabled"`
	// Community is the agent's read-only community, a credential, so it is
	// kept out of JSON and YAML.
	Community       string `xml:"community"       json:"-"               yaml:"-"`
	SysLocation     string `xml:"syslocation"     json:"syslocation"     yaml:"syslocation"`
	SysContact      string `xml:"syscontact"      json:"syscontact"      yaml:"syscontact"`
	L3Visibility    string `xml:"l3visibility"    json:"l3visibility"    yaml:"l3visibility"`
	VersionOID      string `xml:"versionoid"      json:"versionoid"      yaml:"versionoid"`
	EnableAgentX    string `xml:"enableagentx"    json:"enableagentx"    yaml:"enableagentx"`
	EnableObservium string `xml:"enableobservium" json:"enableobservium" yaml:"enableobservium"`
	// Listen is a comma-separated list of addresses; empty means every IPv4
	// address and IPv6 loopback.
	Listen string `xml:"listen" json:"listen" yaml:"listen"`
}

// NetsnmpUsers is the user model of the os-net-snmp plugin
// (Netsnmp/User.xml), which holds the SNMPv3 users.
type NetsnmpUsers struct {
	Version string        `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Users   []NetsnmpUser `xml:"users>user"             json:"users,omitempty"   yaml:"users,omitempty"`
}

// NetsnmpUser is one SNMPv3 user. The model also stores the user's
// authentication password and privacy key in cleartext; they are deliberately
// not bound, so nothing that reads this type can carry them into a report or
// an export.
type NetsnmpUser struct {
	UUID      string `xml:"uuid,attr,omitempty" json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Enabled   string `xml:"enabled"             json:"enabled"        yaml:"enabled"`
	Username  string `xml:"username"            json:"username"       yaml:"username"`
	ReadWrite string `xml:"readwrite"           json:"readwrite"      yaml:"readwrite"`
}
