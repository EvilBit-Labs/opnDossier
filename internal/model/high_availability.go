// Package model defines the data structures for OPNsense configurations.
package model

import (
	"encoding/xml"
)

// HighAvailabilitySync represents high availability synchronization configuration.
type HighAvailabilitySync struct {
	XMLName         xml.Name `xml:"hasync" json:"-" yaml:"-"`
	Version         string   `xml:"version,attr,omitempty" json:"version,omitempty" yaml:"version,omitempty"`
	Disablepreempt  string   `xml:"disablepreempt,omitempty" json:"disablepreempt,omitempty" yaml:"disablepreempt,omitempty"`
	Disconnectppps  string   `xml:"disconnectppps,omitempty" json:"disconnectppps,omitempty" yaml:"disconnectppps,omitempty"`
	Pfsyncinterface string   `xml:"pfsyncinterface,omitempty" json:"pfsyncinterface,omitempty" yaml:"pfsyncinterface,omitempty"`
	Pfsyncpeerip    string   `xml:"pfsyncpeerip,omitempty" json:"pfsyncpeerip,omitempty" yaml:"pfsyncpeerip,omitempty"`
	Pfsyncversion   string   `xml:"pfsyncversion,omitempty" json:"pfsyncversion,omitempty" yaml:"pfsyncversion,omitempty"`
	Synchronizetoip string   `xml:"synchronizetoip,omitempty" json:"synchronizetoip,omitempty" yaml:"synchronizetoip,omitempty"`
	Username        string   `xml:"username,omitempty" json:"username,omitempty" yaml:"username,omitempty"`
	Password        string   `xml:"password,omitempty" json:"password,omitempty" yaml:"password,omitempty"`
	Syncitems       string   `xml:"syncitems,omitempty" json:"syncitems,omitempty" yaml:"syncitems,omitempty"`
}
