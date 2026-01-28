// Package model re-exports types from internal/schema for backward compatibility.
package model

import (
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// ServiceConfig groups service-related configuration.
type ServiceConfig = schema.ServiceConfig

// Unbound represents the Unbound DNS resolver configuration.
type Unbound = schema.Unbound

// Snmpd contains the SNMP daemon configuration.
type Snmpd = schema.Snmpd

// Rrd contains the RRDtool configuration.
type Rrd = schema.Rrd

// LoadBalancer contains the load balancer configuration.
type LoadBalancer = schema.LoadBalancer

// MonitorType represents a load balancer monitor type.
type MonitorType = schema.MonitorType

// Options contains the options for a load balancer monitor type.
type Options = schema.Options

// Ntpd contains the NTP daemon configuration.
type Ntpd = schema.Ntpd

// DNSMasq represents DNS masquerading configuration.
type DNSMasq = schema.DNSMasq

// DNSMasqHost represents a DNSMasq host entry.
type DNSMasqHost = schema.DNSMasqHost

// DomainOverride represents a domain override entry.
type DomainOverride = schema.DomainOverride

// ForwarderGroup represents a DNS forwarder group configuration.
type ForwarderGroup = schema.ForwarderGroup

// Syslog represents system logging configuration.
type Syslog = schema.Syslog

// Monit represents system monitoring configuration.
type Monit = schema.Monit

// MonitService represents a monitored service.
type MonitService = schema.MonitService

// MonitTest represents a monitoring test.
type MonitTest = schema.MonitTest

// Constructor functions that delegate to schema package.

// NewDNSMasq returns a new DNSMasq configuration.
func NewDNSMasq() *DNSMasq {
	return schema.NewDNSMasq()
}

// NewDNSMasqHost returns a DNSMasqHost instance.
func NewDNSMasqHost() DNSMasqHost {
	return schema.NewDNSMasqHost()
}

// NewSyslog returns a pointer to a new Syslog configuration.
func NewSyslog() *Syslog {
	return schema.NewSyslog()
}

// NewMonit returns a pointer to a new Monit configuration.
func NewMonit() *Monit {
	return schema.NewMonit()
}
