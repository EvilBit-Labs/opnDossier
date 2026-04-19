# convert

The `convert` command is the primary way to extract useful documentation from an OPNsense configuration backup. It parses the raw XML and produces structured output in your choice of format -- Markdown for human-readable reports, JSON or YAML for programmatic consumption, or HTML for self-contained sharing.

**When to use it:**

- Generating network documentation from a firewall config backup
- Exporting structured data for integration with other tools or dashboards
- Creating redacted reports safe for sharing with vendors or consultants
- Batch-processing multiple configs for fleet-wide documentation

## Usage

```text
opndossier convert [flags] <config.xml> [config2.xml ...]
```

## Flags

| Flag                 | Short | Default        | Description                                                                                          |
| -------------------- | ----- | -------------- | ---------------------------------------------------------------------------------------------------- |
| `--output`           | `-o`  | stdout         | Output file path                                                                                     |
| `--format`           | `-f`  | `markdown`     | Output format: `markdown` (`md`), `json`, `yaml` (`yml`), `text` (`txt`), `html` (`htm`)             |
| `--force`            |       | `false`        | Overwrite existing output file without prompt                                                        |
| `--section`          |       | all            | Comma-separated list of sections to include: `system`, `network`, `firewall`, `services`, `security` |
| `--wrap`             |       | terminal width | Set text wrap width in columns                                                                       |
| `--no-wrap`          |       | `false`        | Disable text wrapping                                                                                |
| `--comprehensive`    |       | `false`        | Generate detailed comprehensive report                                                               |
| `--include-tunables` |       | `false`        | Include system tunables (sysctl) in output                                                           |
| `--redact`           |       | `false`        | Redact sensitive fields (passwords, keys, community strings)                                         |
| `--device-type`      |       | auto-detect    | Force device type instead of auto-detecting from XML root element                                    |

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).

## Device Types

By default, opnDossier auto-detects the device type from the XML root element of the configuration file. The built-in device types are OPNsense (`<opnsense>`) and pfSense (`<pfsense>`).

The `--device-type` flag overrides auto-detection, which is useful if a config file has an unexpected root element or if you want to explicitly specify the parser.

```bash
opndossier convert config.xml --device-type opnsense
```

opnDossier includes built-in parsers for OPNsense and pfSense. The device type system is extensible -- additional device types (e.g., Fortinet) can be added via parser plugins. Use `opndossier convert --device-type <TAB>` to see all available device types via shell completion. See the [Plugin Development Guide](../../development/plugin-development.md#device-parser-development) for details on creating device parsers.

## Sections

By default, all sections are included in the output. Use `--section` to limit output to specific areas of the configuration. This is useful when you only need to document or audit a particular domain -- for example, generating a firewall-only report for a security review.

```bash
opndossier convert config.xml --section firewall,network -o network-security.md
```

| Section    | What it covers                                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------------- |
| `system`   | Hostname, domain, timezone, language, WebGUI settings, DNS configuration, users, groups, and system tunables        |
| `network`  | Interfaces (LAN, WAN, OPT), VLANs, bridges, GIFs, GREs, LAGGs, and per-interface details (IP, subnet, media, speed) |
| `firewall` | Firewall rules and policies                                                                                         |
| `services` | DHCP server (scopes, static leases, DHCPv6), DNS resolver (Unbound), SNMP, NTP, load balancer monitors              |
| `security` | NAT configuration (inbound/outbound), IDS/Suricata, certificates                                                    |

![Screenshot of opnDossier convert command showing JSON export of firewall rules](../../images/json-output.png)

## System Tunables

OPNsense allows administrators to set kernel-level parameters (sysctl values) that control low-level system behavior -- things like TCP buffer sizes, IP forwarding, and connection tracking limits. These are configured under **System > Settings > Tunables** in the OPNsense web interface.

By default, only security-related tunables (IP forwarding, TCP/UDP blackhole) are included in output. The `--include-tunables` flag adds all tunables -- including performance tuning, buffer sizes, and other kernel parameters:

```bash
opndossier convert config.xml --include-tunables -o full-report.md
```

When included, tunables appear as a table with three columns: the sysctl parameter name, its value, and its description.

## Comprehensive Mode

By default, `convert` produces a baseline report covering the core sections: system settings, interfaces, firewall rules, NAT, and services. The `--comprehensive` flag generates a more detailed report that adds:

- VLAN configuration
- Static routes
- IPsec VPN configuration
- OpenVPN configuration
- High Availability / CARP
- All system tunables (comprehensive mode implies `--include-tunables`)

Use comprehensive mode when you need a complete picture of the device -- for example, when onboarding a new firewall, performing a full audit, or creating handover documentation.

```bash
opndossier convert config.xml --comprehensive -o full-documentation.md
```

## Redacting Sensitive Data

The `--redact` flag replaces sensitive field values with `[REDACTED]` in the output. This lets you generate reports that are safe to share without exposing credentials or secrets.

Fields that are redacted:

- Passwords (HA sync password, user passwords)
- Private keys (certificates, certificate authorities)
- API key secrets
- SNMP community strings
- WireGuard pre-shared keys
- DHCPv6 key info secrets

```bash
# Generate a redacted report for sharing with a vendor
opndossier convert config.xml --redact -o report-for-vendor.md

# Combine with comprehensive for a full but safe report
opndossier convert config.xml --comprehensive --redact -o full-redacted.md
```

For full XML-level sanitization (replacing IPs, hostnames, and all identifying data), see the [sanitize](sanitize.md) command instead.

## Output Formats

| Format     | Aliases | Description                              |
| ---------- | ------- | ---------------------------------------- |
| `markdown` | `md`    | Markdown documentation (default)         |
| `json`     |         | Structured JSON data                     |
| `yaml`     | `yml`   | Structured YAML data                     |
| `text`     | `txt`   | Plain text (markdown without formatting) |
| `html`     | `htm`   | Self-contained HTML report               |

## Security Audits

Security auditing and compliance checks are handled by the dedicated [`audit`](audit.md) command, not `convert`.

Supported audit modes:

| Mode   | Audience  | Focus                                  |
| ------ | --------- | -------------------------------------- |
| `blue` | Blue Team | Defensive audit with security findings |
| `red`  | Red Team  | Attack surface and pivot points        |

Available compliance plugins in blue mode: `stig`, `sans`, `firewall`.

## Multiple Files

When processing multiple files, the `--output` flag is ignored. Each output file is named based on its input file with the appropriate extension.

## Examples

```bash
# Convert to markdown and save to file
opndossier convert config.xml -o documentation.md

# Convert to JSON with forced overwrite
opndossier convert config.xml -f json -o output.json --force

# Convert multiple files to JSON (auto-named outputs)
opndossier convert -f json config1.xml config2.xml
```

## Related

- [audit](audit.md) -- run security audits with compliance checks
- [display](display.md) -- render in terminal instead of writing to file
- [validate](validate.md) -- check config correctness before converting
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
