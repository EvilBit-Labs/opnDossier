package opnsense

// SyslogModel is the Syslog model, <OPNsense><Syslog>: general logging
// settings and, from 20.1, the only remote log targets OPNsense reads.
type SyslogModel struct {
	Text    string `xml:",chardata"    json:"text,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	General struct {
		Text        string `xml:",chardata"   json:"text,omitempty"`
		Enabled     string `xml:"enabled"`
		Loglocal    string `xml:"loglocal"`
		Maxpreserve string `xml:"maxpreserve"`
		Maxfilesize string `xml:"maxfilesize"`
	} `xml:"general"      json:"general"`
	Destinations SyslogDestinations `xml:"destinations" json:"destinations"`
}

// SyslogDestinations is the <destinations> container of the Syslog model
// (<OPNsense><Syslog>). From 20.1 it is the only place OPNsense reads remote
// log targets from.
type SyslogDestinations struct {
	Destination []SyslogDestination `xml:"destination" json:"destination,omitempty"`
}

// SyslogDestination is one remote log target of the Syslog model. Every field
// is kept as the text OPNsense writes: enabled and the flags are 0 or 1, and
// program, level and facility are comma-separated lists, where an empty list
// applies no filter.
type SyslogDestination struct {
	UUID        string `xml:"uuid,attr,omitempty" json:"uuid,omitempty"`
	Enabled     string `xml:"enabled"             json:"enabled,omitempty"`
	Transport   string `xml:"transport"           json:"transport,omitempty"`
	Program     string `xml:"program"             json:"program,omitempty"`
	Level       string `xml:"level"               json:"level,omitempty"`
	Facility    string `xml:"facility"            json:"facility,omitempty"`
	Hostname    string `xml:"hostname"            json:"hostname,omitempty"`
	Certificate string `xml:"certificate"         json:"certificate,omitempty"`
	Port        string `xml:"port"                json:"port,omitempty"`
	RFC5424     string `xml:"rfc5424"             json:"rfc5424,omitempty"`
	Suppress    string `xml:"suppress"            json:"suppress,omitempty"`
	Description string `xml:"description"         json:"description,omitempty"`
}

// IsPlaceholder reports whether the destination has no content. OPNsense
// does not forward to one: its template requires enabled to be 1.
func (d SyslogDestination) IsPlaceholder() bool {
	d.UUID = ""

	return d == SyslogDestination{}
}
