# Template Documentation

This guide explains how to work with opnDossier's data model for custom integrations, scripting, and automation.

## Overview

opnDossier parses OPNsense configuration files (config.xml) and converts them to structured data formats:

- **Markdown** - Human-readable documentation
- **JSON** - Machine-readable, ideal for scripting with `jq`
- **YAML** - Configuration-friendly, works with `yq`

## Quick Start

### Export Configuration

```bash
# Export to JSON for scripting
opndossier convert config.xml --format json -o config.json

# Export to YAML for configuration management
opndossier convert config.xml --format yaml -o config.yaml

# Export to Markdown for documentation
opndossier convert config.xml --format markdown -o config.md
```

### Query Data with jq

```bash
# Get hostname
jq '.system.hostname' config.json

# List all interface names
jq '.interfaces | keys' config.json

# Get all enabled firewall rules
jq '.filter.rule[] | select(.disabled != "1")' config.json

# Count rules by interface
jq '.filter.rule | group_by(.interface) | map({interface: .[0].interface, count: length})' config.json
```

### Query Data with yq

```bash
# Get system domain
yq '.system.domain' config.yaml

# List DHCP scopes
yq '.dhcpd | keys' config.yaml
```

## Data Model Structure

The opnDossier data model mirrors the OPNsense configuration structure:

```text
OpnSenseDocument (root)
├── system           # Hostname, domain, users, groups, SSH
├── interfaces       # Network interface configurations
├── filter           # Firewall rules
├── nat              # NAT rules (outbound, inbound)
├── dhcpd            # DHCP server configuration
├── unbound          # DNS resolver
├── openvpn          # OpenVPN servers and clients
├── gateways         # Gateway definitions
└── ...              # Additional services
```

## Documentation

- **[Model Reference](model-reference.md)** - Complete field reference (auto-generated)
- **[JSON Export Examples](examples/json-export.md)** - Common jq queries
- **[YAML Processing Examples](examples/yaml-processing.md)** - Working with yq

## Common Use Cases

### Security Auditing

```bash
# Find rules allowing any source
jq '.filter.rule[] | select(.source.any == "1")' config.json

# List NAT port forwards
jq '.nat.rule[]' config.json

# Check SSH configuration
jq '.system.ssh' config.json
```

### Network Documentation

```bash
# Get all VLANs
jq '.vlans.vlan[]' config.json

# List gateways
jq '.gateways.gateway_item[]' config.json

# Get interface IP addresses
jq '.interfaces | to_entries[] | {name: .key, ip: .value.ipaddr}' config.json
```

### Configuration Comparison

```bash
# Compare two configs
diff <(jq -S . config1.json) <(jq -S . config2.json)

# Check for changes in firewall rules
diff <(jq '.filter.rule' config1.json) <(jq '.filter.rule' config2.json)
```

## Integration Examples

### Ansible

```yaml
  - name: Extract OPNsense configuration
    command: opndossier convert {{ config_file }} --format json
    register: opnsense_config

  - name: Parse configuration
    set_fact:
      firewall_rules: '{{ (opnsense_config.stdout | from_json).filter.rule }}'
```

### Python

```python
import json
import subprocess

result = subprocess.run(
    ["opndossier", "convert", "config.xml", "--format", "json"],
    capture_output=True,
    text=True,
)
config = json.loads(result.stdout)
print(f"Hostname: {config['system']['hostname']}")
```

### Shell Scripting

```bash
#!/bin/bash
CONFIG=$(opndossier convert config.xml --format json)

HOSTNAME=$(echo "$CONFIG" | jq -r '.system.hostname')
RULE_COUNT=$(echo "$CONFIG" | jq '.filter.rule | length')

echo "Firewall: $HOSTNAME"
echo "Rules: $RULE_COUNT"
```

## Programmatic Generation

opnDossier uses programmatic markdown generation rather than text templates. If you need custom report formats, you can:

1. **Use JSON/YAML exports** - Process with your preferred tools
2. **Extend the generator** - Add custom report types in Go
3. **Post-process output** - Transform markdown with pandoc or similar

See the [Architecture Documentation](../development/architecture.md) for details on the generator system.

## Regenerating Documentation

The model reference is auto-generated from Go types:

```bash
just generate-docs
```

This ensures documentation stays in sync with the codebase.
