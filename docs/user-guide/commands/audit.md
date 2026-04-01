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
| `--mode`             |       | `blue`         | Audit mode: `blue`, `red`                                                                                       |
| `--plugins`          |       |                | Comma-separated compliance plugins to run: `stig`, `sans`, `firewall` (blue mode only)                          |
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

![Screenshot of opnDossier audit command showing STIG compliance findings with severity levels and control status](../../images/audit.png)

## Audit Modes

| Mode   | Audience  | Focus                                  |
| ------ | --------- | -------------------------------------- |
| `blue` | Blue Team | Defensive audit with security findings |
| `red`  | Red Team  | Attack surface and pivot points        |

### Blue

The default mode. Defensive audit mode targeting blue team operators. Runs compliance plugins and produces a report with security findings, control pass/fail results, and remediation recommendations.

When no `--plugins` flag is specified, all available plugins are run by default. The `--plugins` flag is only accepted in blue mode and is rejected for red mode.

### Red

Attacker-focused recon mode highlighting attack surfaces, pivot points, and exposed services.

## Compliance Plugins

| Plugin     | Control Pattern | Description                             |
| ---------- | --------------- | --------------------------------------- |
| `stig`     | `V-XXXXXX`      | Security Technical Implementation Guide |
| `sans`     | `SANS-FW-XXX`   | SANS Firewall Baseline                  |
| `firewall` | `FIREWALL-XXX`  | Firewall Configuration Analysis         |

The `--plugins` flag requires `--mode blue`. It is rejected for red mode.

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

When auditing multiple files, the `--output` flag cannot be used. Each report is auto-named based on the input path with an `-audit` suffix and the appropriate format extension. Bare filenames produce simple names (e.g., `config1.xml` produces `config1-audit.md`). When inputs include directory components, the full path is encoded into the filename to prevent collisions between files that share the same basename:

```text
config.xml                  -> config-audit.md
prod/site-a/config.xml      -> prod_site-a_config-audit.md
dr/site-a/config.xml        -> dr_site-a_config-audit.md
```

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
# Run a blue team audit with all compliance plugins (default)
opndossier audit config.xml

# Blue team defensive audit with STIG and SANS compliance
opndossier audit config.xml --mode blue --plugins stig,sans

# Red team attack surface analysis
opndossier audit config.xml --mode red

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

- [convert](convert.md) -- convert configs to documentation
- [display](display.md) -- render in terminal instead of writing to file
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
- [Audit and Compliance Examples](../../examples/audit-compliance.md) -- common audit workflows
