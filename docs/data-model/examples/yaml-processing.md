# YAML Processing Examples

This guide demonstrates common yq queries for working with opnDossier YAML exports.

The YAML export uses the **CommonDevice** model -- a platform-agnostic representation with normalized field names. If you are looking for the internal XML schema (`OpnSenseDocument`), see the [Model Reference](../model-reference.md).

## Exporting to YAML

```bash
# Basic export
opndossier convert config.xml --format yaml -o config.yaml

# Output to stdout
opndossier convert config.xml --format yaml

# Export with sensitive fields redacted
opndossier convert config.xml --format yaml --redact -o config.yaml
```

## Prerequisites

Install yq (YAML processor):

```bash
# macOS
brew install yq

# Linux (snap)
snap install yq

# Go install
go install github.com/mikefarah/yq/v4@latest
```

## System Information

### Basic Queries

```bash
# Get hostname
yq '.system.hostname' config.yaml

# Get domain
yq '.system.domain' config.yaml

# Get system timezone
yq '.system.timezone' config.yaml
```

### Users

```bash
# List all usernames
yq '.users[].name' config.yaml

# Get user details as YAML
yq '.users[] | {"name": .name, "scope": .scope}' config.yaml
```

### SSH Configuration

```bash
# Check SSH settings
yq '.system.ssh' config.yaml

# Get SSH group
yq '.system.ssh.group' config.yaml
```

## Network Configuration

### Interfaces

```bash
# List interface names
yq '[.interfaces[].name]' config.yaml

# Get specific interface by name
yq '.interfaces[] | select(.name == "wan")' config.yaml

# List all interface IPs
yq '.interfaces[] | select(.ipAddress) | {"name": .name, "ip": .ipAddress}' config.yaml
```

### VLANs

```bash
# List all VLANs
yq '.vlans[]' config.yaml

# Get VLAN tags only
yq '.vlans[].tag' config.yaml
```

### Gateways

```bash
# List gateways
yq '.routing.gateways[]' config.yaml

# Find default gateway
yq '.routing.gateways[] | select(.defaultGw == "1")' config.yaml
```

## Firewall Rules

### Rule Queries

```bash
# Count rules
yq '.firewallRules | length' config.yaml

# List rule descriptions
yq '.firewallRules[].description' config.yaml

# Get enabled rules only
yq '.firewallRules[] | select(.disabled | not)' config.yaml
```

### Security Analysis

```bash
# Find rules with any source
yq '.firewallRules[] | select(.source.address == "any")' config.yaml

# Find SSH rules
yq '.firewallRules[] | select(.destination.port == "22")' config.yaml
```

## Services

### DHCP

```bash
# List DHCP interfaces
yq '[.dhcp[].interface]' config.yaml

# Get DHCP range for a specific interface
yq '.dhcp[] | select(.interface == "lan") | .range' config.yaml

# List static mappings
yq '.dhcp[].staticMappings[]' config.yaml
```

### DNS

```bash
# Check Unbound status
yq '.dns.unbound' config.yaml

# List DNS host overrides
yq '.dns.unbound.hostOverrides[]' config.yaml
```

## VPN Configuration

### OpenVPN

```bash
# List OpenVPN servers
yq '.vpn.openVpn.servers[] | {"description": .description, "port": .localPort}' config.yaml

# List OpenVPN clients
yq '.vpn.openVpn.clients[] | {"description": .description, "server": .serverAddress}' config.yaml
```

### WireGuard

```bash
# List WireGuard servers
yq '.vpn.wireGuard.servers[]' config.yaml

# List WireGuard clients
yq '.vpn.wireGuard.clients[] | {"name": .name, "server": .serverAddress}' config.yaml
```

## Certificates

```bash
# List certificates
yq '.certificates[] | {"description": .description, "type": .certType}' config.yaml

# List certificate authorities
yq '.cas[].description' config.yaml
```

## Data Transformation

### Convert to JSON

```bash
# YAML to JSON
yq -o=json '.' config.yaml

# Pretty JSON output
yq -o=json -P '.' config.yaml
```

### Extract Subset

```bash
# Extract just firewall config
yq '.firewallRules' config.yaml > firewall.yaml

# Extract network config
yq '{"interfaces": .interfaces, "routing": .routing, "vlans": .vlans}' config.yaml > network.yaml
```

### Modify Values

```bash
# Note: These examples show the query, not modifying the original file

# Change hostname (display only)
yq '.system.hostname = "new-hostname"' config.yaml

# Add a comment
yq '. head_comment="OPNsense Configuration Export"' config.yaml
```

## Integration Examples

### Ansible Playbook

```yaml
  - name: Process OPNsense Configuration
    hosts: localhost
    tasks:
      - name: Export configuration to YAML
        command: opndossier convert config.xml --format yaml
        register: config_output

      - name: Parse configuration
        set_fact:
          opnsense_config: '{{ config_output.stdout | from_yaml }}'

      - name: Display hostname
        debug:
          msg: 'Firewall hostname: {{ opnsense_config.system.hostname }}'

      - name: List interfaces
        debug:
          msg: 'Interfaces: {{ opnsense_config.interfaces | map(attribute="name")
            | list }}'
```

### Shell Script

```bash
#!/bin/bash

CONFIG_FILE="config.yaml"

# Export if needed
if [ ! -f "$CONFIG_FILE" ]; then
    opndossier convert config.xml --format yaml -o "$CONFIG_FILE"
fi

# Extract information
HOSTNAME=$(yq '.system.hostname' "$CONFIG_FILE")
DOMAIN=$(yq '.system.domain' "$CONFIG_FILE")
RULE_COUNT=$(yq '.firewallRules | length' "$CONFIG_FILE")

echo "Firewall: $HOSTNAME.$DOMAIN"
echo "Total firewall rules: $RULE_COUNT"

# Check for risky rules
echo "Rules with 'any' source:"
yq '.firewallRules[] | select(.source.address == "any") | .description' "$CONFIG_FILE"
```

### Python

```python
import yaml
import subprocess

# Export configuration
result = subprocess.run(
    ["opndossier", "convert", "config.xml", "--format", "yaml"],
    capture_output=True,
    text=True,
)

# Parse YAML
config = yaml.safe_load(result.stdout)

# Access data
print(f"Hostname: {config['system']['hostname']}")
print(f"Interfaces: {[iface['name'] for iface in config['interfaces']]}")
print(f"Rule count: {len(config['firewallRules'])}")
```

## Comparison and Diff

For comparing two OPNsense configurations, use the built-in `diff` command instead of manual YAML comparison:

```bash
# Compare two configs with security impact scoring
opndossier diff old-config.xml new-config.xml

# Generate markdown diff report
opndossier diff old-config.xml new-config.xml -f markdown -o changes.md

# Compare only firewall rules
opndossier diff old-config.xml new-config.xml --section firewall
```
