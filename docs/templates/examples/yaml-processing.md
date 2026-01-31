# YAML Processing Examples

This guide demonstrates common yq queries for working with opnDossier YAML exports.

## Exporting to YAML

```bash
# Basic export
opndossier convert config.xml --format yaml -o config.yaml

# Output to stdout
opndossier convert config.xml --format yaml
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
yq '.system.user[].name' config.yaml

# Get user details as YAML
yq '.system.user[] | {"name": .name, "scope": .scope}' config.yaml
```

### SSH Configuration

```bash
# Check SSH settings
yq '.system.ssh' config.yaml

# Get specific SSH setting
yq '.system.ssh.enabled' config.yaml
```

## Network Configuration

### Interfaces

```bash
# List interface names
yq '.interfaces | keys' config.yaml

# Get WAN interface details
yq '.interfaces.wan' config.yaml

# List all interface IPs
yq '.interfaces.* | select(.ipaddr) | {"interface": key, "ip": .ipaddr}' config.yaml
```

### VLANs

```bash
# List all VLANs
yq '.vlans.vlan[]' config.yaml

# Get VLAN tags only
yq '.vlans.vlan[].tag' config.yaml
```

### Gateways

```bash
# List gateways
yq '.gateways.gateway_item[]' config.yaml

# Find default gateway
yq '.gateways.gateway_item[] | select(.defaultgw == "1")' config.yaml
```

## Firewall Rules

### Rule Queries

```bash
# Count rules
yq '.filter.rule | length' config.yaml

# List rule descriptions
yq '.filter.rule[].descr' config.yaml

# Get enabled rules only
yq '.filter.rule[] | select(.disabled != "1")' config.yaml
```

### Security Analysis

```bash
# Find rules with any source
yq '.filter.rule[] | select(.source.any == "1")' config.yaml

# Find SSH rules
yq '.filter.rule[] | select(.destination.port == "22")' config.yaml
```

## Services

### DHCP

```bash
# List DHCP interfaces
yq '.dhcpd | keys' config.yaml

# Get DHCP range for LAN
yq '.dhcpd.lan.range' config.yaml

# List static mappings
yq '.dhcpd.*.staticmap[]' config.yaml
```

### DNS

```bash
# Check Unbound status
yq '.unbound.enable' config.yaml

# List DNS host overrides
yq '.unbound.hosts[]' config.yaml
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
yq '.filter' config.yaml > firewall.yaml

# Extract network config
yq '{"interfaces": .interfaces, "gateways": .gateways, "vlans": .vlans}' config.yaml > network.yaml
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
          msg: 'Interfaces: {{ opnsense_config.interfaces.keys() | list }}'
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
RULE_COUNT=$(yq '.filter.rule | length' "$CONFIG_FILE")

echo "Firewall: $HOSTNAME.$DOMAIN"
echo "Total firewall rules: $RULE_COUNT"

# Check for risky rules
echo "Rules with 'any' source:"
yq '.filter.rule[] | select(.source.any == "1") | .descr' "$CONFIG_FILE"
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
print(f"Interfaces: {list(config['interfaces'].keys())}")
print(f"Rule count: {len(config['filter']['rule'])}")
```

## Comparison and Diff

### Compare Configurations

```bash
# Sort and compare
diff <(yq -P 'sort_keys(..)' old.yaml) <(yq -P 'sort_keys(..)' new.yaml)

# Compare specific sections
diff <(yq '.filter.rule' old.yaml) <(yq '.filter.rule' new.yaml)
```

### Generate Change Report

```bash
#!/bin/bash
OLD="old-config.yaml"
NEW="new-config.yaml"

echo "=== Firewall Rule Changes ==="
OLD_RULES=$(yq '.filter.rule | length' "$OLD")
NEW_RULES=$(yq '.filter.rule | length' "$NEW")
echo "Rules: $OLD_RULES -> $NEW_RULES"

echo ""
echo "=== Interface Changes ==="
diff <(yq '.interfaces | keys' "$OLD") <(yq '.interfaces | keys' "$NEW")
```
