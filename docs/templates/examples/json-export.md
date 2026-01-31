# JSON Export Examples

This guide demonstrates common jq queries for working with opnDossier JSON exports.

## Exporting to JSON

```bash
# Basic export
opndossier convert config.xml --format json -o config.json

# Pretty-print to stdout
opndossier convert config.xml --format json | jq .
```

## System Information

### Basic System Details

```bash
# Get hostname and domain
jq '{hostname: .system.hostname, domain: .system.domain}' config.json

# Get OPNsense version
jq '.version' config.json

# Get timezone
jq '.system.timezone' config.json
```

### Users and Groups

```bash
# List all users
jq '.system.user[] | {name: .name, scope: .scope}' config.json

# Find admin users (UID 0 or in admins group)
jq '.system.user[] | select(.uid == "0" or .groupname == "admins")' config.json

# List all groups
jq '.system.group[] | {name: .name, gid: .gid}' config.json
```

### SSH Configuration

```bash
# Check if SSH is enabled
jq '.system.ssh.enabled' config.json

# Get SSH port
jq '.system.ssh.port // "22"' config.json

# Check password authentication
jq '.system.ssh.passwordauth' config.json
```

## Network Interfaces

### Interface Listing

```bash
# List all interface names
jq '.interfaces | keys' config.json

# Get interface details
jq '.interfaces | to_entries[] | {
  name: .key,
  ip: .value.ipaddr,
  subnet: .value.subnet,
  enabled: .value.enable
}' config.json

# Find WAN interface
jq '.interfaces | to_entries[] | select(.value.descr == "WAN" or .key == "wan")' config.json
```

### VLANs

```bash
# List all VLANs
jq '.vlans.vlan[] | {tag: .tag, if: .if, descr: .descr}' config.json

# Find VLANs on specific parent interface
jq '.vlans.vlan[] | select(.if == "igb0")' config.json
```

### Gateways

```bash
# List all gateways
jq '.gateways.gateway_item[] | {
  name: .name,
  interface: .interface,
  gateway: .gateway,
  monitor: .monitor
}' config.json

# Find default gateway
jq '.gateways.gateway_item[] | select(.defaultgw == "1")' config.json
```

## Firewall Rules

### Rule Analysis

```bash
# Count total rules
jq '.filter.rule | length' config.json

# List enabled rules only
jq '.filter.rule[] | select(.disabled != "1")' config.json

# Rules by interface
jq '.filter.rule | group_by(.interface) | map({
  interface: .[0].interface,
  count: length
})' config.json
```

### Security Queries

```bash
# Find rules with "any" source
jq '.filter.rule[] | select(.source.any == "1") | {
  interface: .interface,
  descr: .descr,
  destination: .destination
}' config.json

# Find rules allowing specific ports
jq '.filter.rule[] | select(.destination.port == "22")' config.json

# Find block rules
jq '.filter.rule[] | select(.type == "block")' config.json
```

### Rule Export

```bash
# Export rules as CSV-like format
jq -r '.filter.rule[] | [.interface, .type, .protocol, .source.address // "any", .destination.address // "any", .destination.port // "*", .descr] | @csv' config.json
```

## NAT Configuration

### Outbound NAT

```bash
# List outbound NAT rules
jq '.nat.outbound.rule[]' config.json

# Check NAT mode
jq '.nat.outbound.mode' config.json
```

### Port Forwards

```bash
# List all port forwards
jq '.nat.rule[] | {
  interface: .interface,
  protocol: .protocol,
  destination: .destination,
  target: .target,
  local_port: .local_port
}' config.json
```

## Services

### DHCP

```bash
# List DHCP scopes
jq '.dhcpd | to_entries[] | {
  interface: .key,
  enabled: .value.enable,
  range_from: .value.range.from,
  range_to: .value.range.to
}' config.json

# Get static DHCP mappings
jq '.dhcpd | to_entries[] | .value.staticmap[]? | {
  mac: .mac,
  ip: .ipaddr,
  hostname: .hostname
}' config.json
```

### DNS (Unbound)

```bash
# Check if Unbound is enabled
jq '.unbound.enable' config.json

# Get DNS overrides
jq '.unbound.hosts[]' config.json
```

## Advanced Queries

### Configuration Comparison

```bash
# Generate sorted JSON for diff
jq -S . config.json > sorted.json

# Compare two configurations
diff <(jq -S '.filter.rule' old.json) <(jq -S '.filter.rule' new.json)
```

### Statistics

```bash
# Configuration summary
jq '{
  version: .version,
  hostname: .system.hostname,
  interfaces: (.interfaces | keys | length),
  firewall_rules: (.filter.rule | length),
  nat_rules: (.nat.rule | length),
  dhcp_scopes: (.dhcpd | keys | length),
  users: (.system.user | length),
  vlans: (.vlans.vlan | length)
}' config.json
```

### Export for Spreadsheet

```bash
# Export firewall rules to TSV
jq -r '["Interface","Type","Protocol","Source","Destination","Port","Description"],
(.filter.rule[] | [
  .interface,
  .type,
  .protocol,
  (.source.address // .source.any // "any"),
  (.destination.address // .destination.any // "any"),
  (.destination.port // "*"),
  .descr
]) | @tsv' config.json
```
