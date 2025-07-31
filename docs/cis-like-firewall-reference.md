# CIS-Inspired Firewall Security Controls Reference

## Overview

This document provides a reference guide for implementing firewall security controls inspired by industry-standard benchmarks for opnFocus. The controls outlined here are based on general security best practices for network firewalls and are designed to be compatible with OPNsense configurations. This document is not affiliated with, endorsed by, or derived from any specific benchmark organization.

## Control Categories

### 1. General Setting Policy

#### 1.1 SSH Warning Banner Configuration

- **Control**: Configure SSH warning banner before authentication
- **Rationale**: Inform users of connection rules and aid in prosecution of intruders
- **Implementation**: Set Banner parameter in SSH configuration
- **Default**: No banner shown by default

#### 1.2 Auto Configuration Backup

- **Control**: Enable automatic configuration backup
- **Rationale**: Ensure configuration changes are backed up automatically
- **Implementation**: Enable AutoConfigBackup service
- **Default**: Disabled

#### 1.3 Message of the Day (MOTD)

- **Control**: Set appropriate MOTD message
- **Rationale**: Provide legal notice and consent for monitoring
- **Implementation**: Configure /etc/motd with appropriate message
- **Default**: FreeBSD default MOTD

#### 1.4 Hostname Configuration

- **Control**: Set device hostname
- **Rationale**: Asset identification and security requirements
- **Implementation**: Configure hostname in System > General Setup
- **Default**: pfSense

#### 1.5 DNS Server Configuration

- **Control**: Configure DNS servers
- **Rationale**: Enable hostname resolution to IP addresses
- **Implementation**: Set DNS servers in System > General Setup
- **Default**: Blank unless DHCP assigns

#### 1.6 IPv6 Disablement

- **Control**: Disable IPv6 if not used
- **Rationale**: Reduce attack surface if IPv6 not needed
- **Implementation**: Disable IPv6 in System > Advanced > Networking
- **Default**: IPv6 enabled

#### 1.7 DNS Rebind Check

- **Control**: Disable DNS rebind check
- **Rationale**: Protect against DNS rebinding attacks
- **Implementation**: Uncheck DNS Rebind Check in System > Advanced
- **Default**: Unchecked

#### 1.8 HTTPS Web Management

- **Control**: Use HTTPS for web management
- **Rationale**: Encrypt management traffic and ensure identity
- **Implementation**: Configure HTTPS in System > Advanced > Admin Access
- **Default**: HTTPS enabled

#### 1.9 High Availability Configuration

- **Control**: Configure synchronized HA peer
- **Rationale**: Ensure availability and automatic failover
- **Implementation**: Configure HA sync in System > High Avail. Sync
- **Default**: All fields blank

### 2. User Management

#### 2.1 Session Timeout

- **Control**: Set session timeout to ≤10 minutes
- **Rationale**: Prevent abuse of abandoned sessions
- **Implementation**: Configure in System > User Manager > Settings
- **Default**: No timeout set

#### 2.2 LDAP/RADIUS Authentication

- **Control**: Configure central authentication
- **Rationale**: Centralized AAA for access management
- **Implementation**: Configure in System > User Manager > Authentication Servers
- **Default**: Local Database

#### 2.3 Console Menu Protection

- **Control**: Password protect console menu
- **Rationale**: Prevent unauthorized console access
- **Implementation**: Enable in System > Advanced > Admin Access
- **Default**: Unchecked

#### 2.4 Default Account Management

- **Control**: Disable or secure default accounts
- **Rationale**: Prevent unauthorized access via known accounts
- **Implementation**: Review and secure default accounts
- **Default**: admin account only

### 3. Password Policy

#### 3.1 Local Account Status

- **Control**: Disable local accounts except admin
- **Rationale**: Centralize account management
- **Implementation**: Disable unnecessary local accounts
- **Default**: Local accounts enabled

#### 3.2 Login Protection Threshold

- **Control**: Set threshold to ≤30
- **Rationale**: Prevent brute force attacks
- **Implementation**: Configure in System > Advanced
- **Default**: 30

#### 3.3 Access Block Time

- **Control**: Set block time to ≥300 seconds
- **Rationale**: Prevent rapid retry attacks
- **Implementation**: Configure in System > Advanced > Admin Access
- **Default**: No block time

#### 3.4 Default Password Change

- **Control**: Change default admin password
- **Rationale**: Prevent compromise via known credentials
- **Implementation**: Change password in System > User Manager
- **Default**: admin/pfsense

### 4. Firewall Policy

#### 4.1.1 Destination Field Restrictions

- **Control**: No "Any" in destination field
- **Rationale**: Explicit destination control
- **Implementation**: Review and restrict firewall rules
- **Default**: Allow Any rules present

#### 4.1.2 Source Field Restrictions

- **Control**: No "Any" in source field
- **Rationale**: Explicit source control
- **Implementation**: Review and restrict firewall rules
- **Default**: Allow Any rules present

#### 4.1.3 Service Field Restrictions

- **Control**: No "Any" in service field
- **Rationale**: Explicit service control
- **Implementation**: Review and restrict firewall rules
- **Default**: Allow Any rules present

#### 4.1.4 Unused Policy Removal

- **Control**: Remove unused firewall policies
- **Rationale**: Prevent unintended access
- **Implementation**: Review and remove unused policies
- **Default**: Varies by configuration

#### 4.1.5 Firewall Rule Logging

- **Control**: Enable logging for all firewall rules
- **Rationale**: Audit trail and troubleshooting
- **Implementation**: Enable logging in firewall rules
- **Default**: Some logging enabled

#### 4.1.6 ICMP Configuration

- **Control**: Secure ICMP request configuration
- **Rationale**: Prevent ICMP-based attacks
- **Implementation**: Restrict ICMP types in firewall rules
- **Default**: Varies by configuration

### 5. Service Configuration

#### 5.1.1 SNMP Trap Receivers

- **Control**: Configure SNMP trap receivers
- **Rationale**: Enable monitoring and alerting
- **Implementation**: Configure in Services > SNMP
- **Default**: Not configured

#### 5.1.2 SNMP Trap Enablement

- **Control**: Enable SNMP traps
- **Rationale**: Enable monitoring notifications
- **Implementation**: Enable in Services > SNMP
- **Default**: Disabled

#### 5.1.3 NET-SNMP Package

- **Control**: Install and secure NET-SNMP
- **Rationale**: Enhanced SNMP functionality
- **Implementation**: Install and configure NET-SNMP package
- **Default**: Not installed

#### 5.2.1 NTP Configuration

- **Control**: Configure time zone properly
- **Rationale**: Accurate timestamps and certificate validation
- **Implementation**: Configure in Services > NTP
- **Default**: NTP server enabled

#### 5.3.1 DNSSEC Enablement

- **Control**: Enable DNSSEC on DNS service
- **Rationale**: Protect against DNS attacks
- **Implementation**: Enable in Services > DNS Resolver
- **Default**: DNS resolver enabled

#### 5.4.1 VPN Authentication

- **Control**: Use RADIUS/LDAP for VPN authentication
- **Rationale**: Centralized authentication
- **Implementation**: Configure in System > User Manager
- **Default**: Local Database

#### 5.4.2 VPN Certificate

- **Control**: Use trusted certificate for VPN portal
- **Rationale**: Prevent man-in-the-middle attacks
- **Implementation**: Import trusted CA in System > Cert. Manager
- **Default**: No certificates

#### 5.4.3 OpenVPN TLS

- **Control**: Configure OpenVPN with TLS encryption
- **Rationale**: Secure VPN communications
- **Implementation**: Configure in VPN > OpenVPN
- **Default**: Varies by configuration

#### 5.5.1 OpenVPN Ciphers

- **Control**: Use strong ciphers and hashing algorithms
- **Rationale**: Prevent cryptographic attacks
- **Implementation**: Configure strong algorithms in OpenVPN
- **Default**: Varies by configuration

### 6. Logging

#### 6.1 Syslog Configuration

- **Control**: Configure syslog for remote logging
- **Rationale**: Protected log storage and archiving
- **Implementation**: Configure in Status > System Logs > Settings
- **Default**: No external logging

## Implementation Notes

### Control Mapping

Each control should be mapped to our audit engine with:

- Control ID (e.g., FIREWALL-001)
- Category and title
- Severity level
- Description and rationale
- Audit procedure
- Remediation steps

### Severity Levels

- **High**: Critical security controls that must be implemented
- **Medium**: Important security controls that should be implemented
- **Low**: Recommended security controls for enhanced security

### Profile Levels

- **Level 1**: Basic security controls for most environments
- **Level 2**: Enhanced security controls for high-security environments

### Industry Standards Alignment

These controls align with general industry security standards and best practices for network infrastructure security, providing guidance for different organizational maturity levels.

## References

- General network security best practices
- Industry-standard firewall security guidelines
- OPNsense documentation and security recommendations
- Network infrastructure security frameworks

## Usage in opnFocus

This reference document guides the implementation of firewall security controls in our audit engine. Each control should be:

1. **Implemented** as a check in the audit engine
2. **Mapped** to appropriate OPNsense configuration elements
3. **Reported** with clear findings and recommendations
4. **Tracked** for compliance status

The controls provide a comprehensive security assessment framework for OPNsense firewalls, complementing our existing STIG and SANS compliance capabilities.
