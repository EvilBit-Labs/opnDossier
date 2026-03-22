# audit

The `audit` command runs security audit and compliance checks on one or more OPNsense config.xml files. It produces a report with compliance findings, security recommendations, and risk assessments based on the selected audit mode and compliance plugins.

**When to use it:**

- Running a security posture assessment against a firewall configuration
- Generating STIG/SANS/firewall compliance reports for auditors
- Red team reconnaissance to identify attack surfaces and pivot points
- Producing redacted audit reports safe for sharing with external parties
- Batch-auditing multiple configs for fleet-wide compliance visibility

## Usage

```text
opndossier audit [flags] <config.xml> [config2.xml ...]
```

## Flags

| Flag                 | Short | Default        | Description                                                                                                     |
| -------------------- | ----- | -------------- | --------------------------------------------------------------------------------------------------------------- |
| `--mode`             |       | `standard`     | Audit mode: `standard`, `blue`, `red`                                                                           |
| `--plugins`          |       |                | Comma-separated compliance plugins to run: `stig`, `sans`, `firewall` (blue mode only)                          |
| `--blackhat`         |       | `false`        | Enable blackhat commentary for red team reports                                                                 |
| `--plugin-dir`       |       |                | Directory containing dynamic `.so` compliance plugins                                                           |
| `--output`           | `-o`  | stdout         | Output file path                                                                                                |
| `--format`           | `-f`  | `markdown`     | Output format: `markdown` (`md`), `json`, `yaml` (`yml`), `text` (`txt`), `html` (`htm`)                        |
| `--force`            |       | `false`        | Overwrite existing output file without prompt                                                                   |
| `--comprehensive`    |       | `false`        | Generate detailed comprehensive report                                                                          |
| `--redact`           |       | `false`        | Redact sensitive fields (passwords, keys, community strings)                                                    |
| `--wrap`             |       | terminal width | Set text wrap width in columns                                                                                  |
| `--no-wrap`          |       | `false`        | Disable text wrapping                                                                                           |
| `--include-tunables` |       | `false`        | Include all system tunables in report output (markdown, text, HTML only; JSON/YAML always include all tunables) |
| `--section`          |       | all            | Comma-separated list of sections to include: `system`, `network`, `firewall`, `services`, `security`            |

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).

## Audit Modes

| Mode       | Audience   | Focus                                  |
| ---------- | ---------- | -------------------------------------- |
| `standard` | Operations | Neutral, comprehensive documentation   |
| `blue`     | Blue Team  | Defensive audit with security findings |
| `red`      | Red Team   | Attack surface and pivot points        |

### Standard

The default mode. Produces a neutral documentation report covering the full configuration -- system settings, interfaces, firewall rules, NAT, and services. No compliance plugins are run.

### Blue

Defensive audit mode targeting blue team operators. Runs compliance plugins and produces a report with security findings, control pass/fail results, and remediation recommendations.

When no `--plugins` flag is specified, all available plugins are run by default. The `--plugins` flag is only accepted in blue mode and is rejected for standard or red modes.

### Red

Attacker-focused recon mode highlighting attack surfaces, pivot points, and exposed services. The `--blackhat` flag adds adversary commentary to the report.

## Compliance Plugins

| Plugin     | Control Pattern | Description                             |
| ---------- | --------------- | --------------------------------------- |
| `stig`     | `V-XXXXXX`      | Security Technical Implementation Guide |
| `sans`     | `SANS-FW-XXX`   | SANS Firewall Baseline                  |
| `firewall` | `FIREWALL-XXX`  | Firewall Configuration Analysis         |

The `--plugins` flag requires `--mode blue`. It is rejected for standard and red modes.

## Dynamic Plugins

The `--plugin-dir` flag specifies a directory containing dynamic `.so` files that implement the `compliance.Plugin` interface (exporting `var Plugin compliance.Plugin`).

- Failed dynamic plugin loads are non-fatal -- the audit continues with available plugins and logs warnings for any failures
- When `--plugin-dir` is explicitly provided and the directory is missing, an error is returned

```bash
opndossier audit config.xml --mode blue --plugin-dir /opt/plugins
```

See the [Plugin Development Guide](../../dev-guide/plugin-development.md) for details on creating compliance plugins.

## Output Formats

| Format     | Aliases | Description                              |
| ---------- | ------- | ---------------------------------------- |
| `markdown` | `md`    | Markdown documentation (default)         |
| `json`     |         | Structured JSON data                     |
| `yaml`     | `yml`   | Structured YAML data                     |
| `text`     | `txt`   | Plain text (markdown without formatting) |
| `html`     | `htm`   | Self-contained HTML report               |

## Multiple Files

When auditing multiple files, the `--output` flag cannot be used. Each report is auto-named based on the input filename with an `-audit` suffix and the appropriate format extension. For example, `config1.xml` produces `config1-audit.md`.

```bash
opndossier audit config1.xml config2.xml --mode blue
```

## Redacting Sensitive Data

The `--redact` flag replaces sensitive field values with `[REDACTED]` in the output. This lets you generate reports that are safe to share without exposing credentials or secrets.

For the full list of redacted fields, see [convert -- Redacting Sensitive Data](convert.md#redacting-sensitive-data).

```bash
opndossier audit config.xml --redact -o audit-for-vendor.md
```

## Examples

```bash
# Run a standard audit (documentation report, no compliance plugins)
opndossier audit config.xml

# Blue team defensive audit with STIG and SANS compliance
opndossier audit config.xml --mode blue --plugins stig,sans

# Blue team audit with all compliance plugins (default when no --plugins)
opndossier audit config.xml --mode blue

# Red team attack surface analysis with blackhat commentary
opndossier audit config.xml --mode red --blackhat

# Export audit report as JSON
opndossier audit config.xml --format json -o audit-report.json

# Run audit on multiple files (each report is auto-named)
opndossier audit config1.xml config2.xml --mode blue

# Comprehensive blue team audit with all compliance checks
opndossier audit config.xml --mode blue --comprehensive --plugins stig,sans,firewall

# Redact sensitive fields from audit output
opndossier audit config.xml --redact

# Quiet mode (errors only)
opndossier --quiet audit config.xml --mode blue

# Verbose audit diagnostics
opndossier --verbose audit config.xml --mode blue --plugins stig,sans
```

## Related

- [convert](convert.md) -- convert configs to documentation (includes audit modes via `--audit-mode`)
- [display](display.md) -- render in terminal instead of writing to file
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
- [Audit and Compliance Examples](../../examples/audit-compliance.md) -- common audit workflows
