# JSON Export Examples

This guide demonstrates common jq queries for working with opnDossier JSON exports.

The JSON export uses the **CommonDevice** model -- a platform-agnostic representation with normalized field names. If you are looking for the internal XML schema (`OpnSenseDocument`), see the [Model Reference](../model-reference.md).

## Exporting to JSON

```bash
# Basic export
opndossier convert config.xml --format json -o config.json

# Pretty-print to stdout
opndossier convert config.xml --format json | jq .

# Export with sensitive fields redacted
opndossier convert config.xml --format json --redact -o config.json
```

## System Information

### Basic System Details

```bash
# Get hostname and domain
jq '{hostname: .system.hostname, domain: .system.domain}' config.json

# Get device type
jq '.device_type' config.json

# Get timezone
jq '.system.timezone' config.json
```

### Users and Groups

```bash
# List all users
jq '.users[] | {name: .name, scope: .scope}' config.json

# Find admin users (UID 0 or in admins group)
jq '.users[] | select(.uid == "0" or .groupName == "admins")' config.json

# List all groups
jq '.groups[] | {name: .name, gid: .gid}' config.json
```

### SSH Configuration

```bash
# Check SSH settings
jq '.system.ssh' config.json

# Get SSH group
jq '.system.ssh.group' config.json
```

## Network Interfaces

### Interface Listing

```bash
# List all interface names
jq '[.interfaces[].name]' config.json

# Get interface details
jq '.interfaces[] | {
  name,
  ip: .ipAddress,
  subnet,
  enabled
}' config.json

# Find WAN interface
jq '.interfaces[] | select(.description == "WAN" or .name == "wan")' config.json
```

### VLANs

```bash
# List all VLANs
jq '.vlans[] | {tag, vlanIf, description}' config.json

# Find VLANs on specific parent interface
jq '.vlans[] | select(.parentInterface == "igb0")' config.json
```

### Gateways

```bash
# List all gateways
jq '.routing.gateways[] | {
  name,
  interface,
  address,
  description
}' config.json

# Find default gateway
jq '.routing.gateways[] | select(.defaultGw == "1")' config.json
```

## Firewall Rules

### Rule Analysis

```bash
# Count total rules
jq '.firewallRules | length' config.json

# List enabled rules only (disabled is a boolean)
jq '.firewallRules[] | select(.disabled | not)' config.json

# Rules by interface
jq '[.firewallRules[] | .interfaces[]] | group_by(.) | map({
  interface: .[0],
  count: length
})' config.json
```

### Security Queries

```bash
# Find rules with "any" source
jq '.firewallRules[] | select(.source.address == "any") | {
  interfaces,
  description,
  destination
}' config.json

# Find rules allowing specific ports
jq '.firewallRules[] | select(.destination.port == "22")' config.json

# Find block rules
jq '.firewallRules[] | select(.type == "block")' config.json
```

### Rule Export

```bash
# Export rules as CSV-like format
jq -r '.firewallRules[] | [
  (.interfaces // ["*"] | join(",")),
  .type,
  .protocol,
  (.source.address // "any"),
  (.destination.address // "any"),
  (.destination.port // "*"),
  .description
] | @csv' config.json
```

## NAT Configuration

### Outbound NAT

```bash
# List outbound NAT rules
jq '.nat.outboundRules[]' config.json

# Check NAT mode
jq '.nat.outboundMode' config.json
```

### Port Forwards

```bash
# List all inbound NAT rules (port forwards)
jq '.nat.inboundRules[] | {
  interface,
  protocol,
  destination,
  target,
  localPort
}' config.json
```

## Services

### DHCP

```bash
# List DHCP scopes
jq '.dhcp[] | {
  interface,
  enabled,
  range
}' config.json

# Get static DHCP mappings
jq '.dhcp[] | .staticMappings[]? | {
  mac,
  ipAddress,
  hostname
}' config.json
```

### DNS (Unbound)

```bash
# Check Unbound settings
jq '.dns.unbound' config.json

# Get DNS host overrides
jq '.dns.unbound.hostOverrides[]' config.json
```

## VPN Configuration

### OpenVPN

```bash
# List OpenVPN servers
jq '.vpn.openVpn.servers[] | {
  description,
  mode,
  protocol,
  port: .localPort,
  tunnel: .tunnelNetwork
}' config.json

# List OpenVPN clients
jq '.vpn.openVpn.clients[] | {
  description,
  serverAddress,
  serverPort,
  protocol
}' config.json
```

### WireGuard

```bash
# List WireGuard servers
jq '.vpn.wireGuard.servers[] | {
  name,
  publicKey,
  listenPort,
  tunnelAddress
}' config.json

# List WireGuard clients (peers)
jq '.vpn.wireGuard.clients[] | {
  name,
  publicKey,
  serverAddress,
  serverPort
}' config.json
```

## Certificates

```bash
# List all certificates
jq '.certificates[] | {
  description,
  type: .certType,
  caRef
}' config.json

# List certificate authorities
jq '.cas[] | {description, serial}' config.json
```

## Enrichment Data

When exported with `--format json`, the output includes computed enrichment fields:

```bash
# Get configuration statistics
jq '.statistics' config.json

# Get security assessment
jq '.securityAssessment' config.json

# Get analysis summary
jq '.analysis' config.json

# Get performance metrics
jq '.performanceMetrics' config.json
```

## Advanced Queries

### Configuration Comparison

For comparing two OPNsense configurations, use the built-in `diff` command instead of manual JSON comparison:

```bash
# Compare two configs with security impact scoring
opndossier diff old-config.xml new-config.xml

# Generate JSON diff for automation
opndossier diff old-config.xml new-config.xml -f json
```

### Statistics

```bash
# Configuration summary
jq '{
  device_type,
  hostname: .system.hostname,
  interfaces: (.interfaces | length),
  firewall_rules: (.firewallRules | length),
  dhcp_scopes: (.dhcp | length),
  users: (.users | length)
}' config.json
```

### Export for Spreadsheet

```bash
# Export firewall rules to TSV
jq -r '["Interface","Type","Protocol","Source","Destination","Port","Description"],
(.firewallRules[] | [
  (.interfaces // ["*"] | join(",")),
  .type,
  .protocol,
  (.source.address // "any"),
  (.destination.address // "any"),
  (.destination.port // "*"),
  .description
]) | @tsv' config.json
```
