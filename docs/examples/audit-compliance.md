# Audit and Compliance Examples

This guide covers common audit and compliance workflows using the `opndossier audit` command. For the full flag reference, see the [audit command guide](../user-guide/commands/audit.md).

## Standard Audit

The default mode produces a neutral documentation report without compliance checks.

```bash
# Basic audit — outputs to console
opndossier audit config.xml

# Save audit report to file
opndossier audit config.xml -o report.md
```

## Blue Team — Defensive Audit

Blue mode runs compliance plugins and produces a defensive audit report with security findings and recommendations.

```bash
# Blue team audit with all available plugins (default when no --plugins specified)
opndossier audit config.xml --mode blue

# Select specific compliance plugins
opndossier audit config.xml --mode blue --plugins stig,sans

# Full compliance suite with comprehensive report
opndossier audit config.xml --mode blue --plugins stig,sans,firewall --comprehensive
```

## Red Team — Attack Surface Analysis

Red mode produces an attacker-focused recon report highlighting attack surfaces, pivot points, and exposed services.

```bash
# Basic red team analysis
opndossier audit config.xml --mode red

# Red team analysis with blackhat commentary
opndossier audit config.xml --mode red --blackhat
```

## Exporting Audit Reports

Audit reports support the same output formats as other opnDossier commands.

```bash
# Export as JSON for programmatic access
opndossier audit config.xml -f json -o audit-report.json

# Export as YAML for configuration management
opndossier audit config.xml -f yaml -o audit-report.yaml

# Export as self-contained HTML
opndossier audit config.xml -f html -o audit-report.html

# Redact sensitive fields before sharing
opndossier audit config.xml --redact -o redacted-audit.md
```

## Dynamic Plugins

Custom compliance plugins can be loaded from a directory containing `.so` files that export `var Plugin compliance.Plugin`.

```bash
# Load custom plugins from a directory
opndossier audit config.xml --mode blue --plugin-dir /opt/plugins
```

Failed dynamic plugin loads are non-fatal -- the audit continues with available plugins and logs warnings for any failures.

## Multi-File Audit

When auditing multiple files, each report is auto-named based on the input filename. The `--output` flag cannot be used with multiple input files.

```bash
# Audit multiple files (produces config1-audit.md, config2-audit.md)
opndossier audit config1.xml config2.xml --mode blue

# Files in subdirectories encode the path to prevent collisions
# prod/config.xml -> prod_config-audit.md
# dr/config.xml  -> dr_config-audit.md
opndossier audit prod/config.xml dr/config.xml --mode blue
```

## Automation Workflows

### Validate Then Audit

```bash
# Validate configuration before running an audit
opndossier validate config.xml && opndossier audit config.xml --mode blue
```

### Scheduled Compliance Checks

```bash
#!/bin/bash
# compliance-check.sh — run a blue team audit and archive the report

TIMESTAMP=$(date +%Y-%m-%d)
REPORT_DIR="audits/${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

if opndossier validate config.xml; then
    opndossier audit config.xml --mode blue --comprehensive \
        -o "${REPORT_DIR}/compliance-report.md"
    echo "Compliance report saved to ${REPORT_DIR}"
else
    echo "Configuration validation failed"
    exit 1
fi
```

### Fleet-Wide Audit

```bash
#!/bin/bash
# fleet-audit.sh — audit all configs in a directory

for file in configs/*.xml; do
    opndossier audit "$file" --mode blue --redact
done
```

---

**Next Steps:**

- For the full flag reference, see the [audit command guide](../user-guide/commands/audit.md)
- For automation patterns, see [Automation and Scripting](automation-scripting.md)
- For troubleshooting, see [Troubleshooting](troubleshooting.md)
