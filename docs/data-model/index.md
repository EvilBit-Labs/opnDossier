# Data Model & Integration

This guide explains how to work with opnDossier's data model for custom integrations, scripting, and automation.

## Overview

opnDossier parses OPNsense and pfSense configuration files (config.xml) and converts them to structured data formats:

- **Markdown** - Human-readable documentation
- **JSON** - Machine-readable, ideal for scripting with `jq`
- **YAML** - Configuration-friendly, works with `yq`

The JSON/YAML export uses the **CommonDevice** model -- a platform-agnostic representation that normalizes XML quirks (presence-based booleans, pointer types, map-keyed collections) into clean types suitable for scripting and integration. Both OPNsense and pfSense configs are normalized to identical CommonDevice structures, enabling unified scripting regardless of device type. opnDossier auto-detects the device type from the XML root element (`<opnsense>` or `<pfsense>`).

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
jq '[.interfaces[].name]' config.json

# Get all enabled firewall rules
jq '.firewallRules[] | select(.disabled | not)' config.json

# Count rules by interface
jq '[.firewallRules[] | .interfaces[]] | group_by(.) | map({interface: .[0], count: length})' config.json
```

### Query Data with yq

```bash
# Get system domain
yq '.system.domain' config.yaml

# List DHCP scopes
yq '[.dhcp[].interface]' config.yaml
```

## Data Model Structure

The CommonDevice model organizes configuration into logical sections:

```text
CommonDevice (root)
├── system           # Hostname, domain, SSH, WebGUI, firmware
├── interfaces[]     # Network interface configurations (flat array)
├── vlans[]          # VLAN configurations
├── firewallRules[]  # Normalized firewall filter rules
├── nat              # NAT rules (outboundRules, inboundRules)
├── dhcp[]           # DHCP server scopes
├── dns              # DNS resolver (unbound, dnsMasq)
├── vpn              # VPN (openVpn, wireGuard, ipsec)
├── routing          # Gateways, gateway groups, static routes
├── users[]          # System user accounts
├── groups[]         # System groups
├── certificates[]   # TLS/SSL certificates
├── cas[]            # Certificate authorities
└── ...              # Additional services (syslog, ids, snmp, etc.)
```

## Documentation

- **[Model Reference](model-reference.md)** - Complete field reference for the CommonDevice export model and internal XML schemas
- **[JSON Export Examples](examples/json-export.md)** - Common jq queries
- **[YAML Processing Examples](examples/yaml-processing.md)** - Working with yq

## Common Use Cases

### Security Auditing

```bash
# Find rules allowing any source
jq '.firewallRules[] | select(.source.address == "any") | {
  interfaces, description, destination
}' config.json

# List NAT port forwards
jq '.nat.inboundRules[]' config.json

# Check SSH configuration
jq '.system.ssh' config.json
```

### Network Documentation

```bash
# Get all VLANs
jq '.vlans[] | {tag, vlanIf, description}' config.json

# List gateways
jq '.routing.gateways[] | {name, interface, address}' config.json

# Get interface IP addresses
jq '.interfaces[] | {name, ipAddress, subnet}' config.json
```

### Configuration Comparison

Use the built-in `diff` command for content-aware, security-scored comparison:

```bash
# Compare two configs with security impact scoring
opndossier diff old-config.xml new-config.xml

# Generate JSON diff for automation
opndossier diff old-config.xml new-config.xml -f json

# Compare only firewall rules
opndossier diff old-config.xml new-config.xml --section firewall
```

## Integration Examples

### Ansible

```yaml
  - name: Extract OPNsense configuration
    command: opndossier convert {{ config_file }} --format json
    register: opnsense_config

  - name: Parse configuration
    set_fact:
      firewall_rules: '{{ (opnsense_config.stdout | from_json).firewallRules }}'
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
print(f"Interfaces: {[iface['name'] for iface in config['interfaces']]}")
```

### Shell Scripting

```bash
#!/bin/bash
CONFIG=$(opndossier convert config.xml --format json)

HOSTNAME=$(echo "$CONFIG" | jq -r '.system.hostname')
RULE_COUNT=$(echo "$CONFIG" | jq '.firewallRules | length')

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
