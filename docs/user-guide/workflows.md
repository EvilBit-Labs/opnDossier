# Common Workflows

Practical recipes for common opnDossier tasks. Each workflow assumes you have opnDossier installed and an OPNsense `config.xml` file.

---

## Document a Network Configuration

**Goal:** Generate a comprehensive markdown report from a configuration file.

1. Validate the configuration file to catch parsing issues early:

   ```bash
   opndossier validate config.xml
   ```

2. Generate a standard documentation report:

   ```bash
   opndossier convert config.xml -o network-documentation.md
   ```

3. For a more detailed report that includes tunables and additional sections:

   ```bash
   opndossier convert config.xml --comprehensive --include-tunables -o detailed-report.md
   ```

4. Open the generated markdown file in your preferred viewer or commit it to version control.

**Expected result:** A structured markdown document covering system settings, interfaces, firewall rules, VPN configurations, and other sections present in the configuration.

For all convert options, see [convert command](commands/convert.md).

---

## Run a Security Audit

**Goal:** Assess security posture using compliance plugins.

1. Run a defensive (blue team) audit with specific compliance frameworks:

   ```bash
   opndossier convert config.xml --audit-mode blue --audit-plugins stig,sans -o audit-report.md
   ```

2. For a red team assessment that highlights attack surfaces and pivot points:

   ```bash
   opndossier convert config.xml --audit-mode red -o recon-report.md
   ```

3. Review the generated report. Findings are grouped by severity (critical, high, medium, low) with references to the applicable compliance controls.

**Expected result:** A markdown report containing compliance findings, a severity breakdown summary, and actionable recommendations mapped to STIG, SANS, or firewall best-practice controls.

For audit mode details, see [convert command](commands/convert.md).

---

## Compare Two Configurations

**Goal:** Identify changes between configuration versions.

1. Run a terminal diff to quickly review changes:

   ```bash
   opndossier diff old-config.xml new-config.xml
   ```

2. Generate a markdown diff report for change management documentation:

   ```bash
   opndossier diff old-config.xml new-config.xml -f markdown -o change-report.md
   ```

3. To focus on security-relevant changes only:

   ```bash
   opndossier diff old-config.xml new-config.xml --security
   ```

4. For automation, export the diff as JSON and process with `jq`:

   ```bash
   opndossier diff old-config.xml new-config.xml -f json | jq '.changes[]'
   ```

**Expected result:** A structured comparison showing added, removed, and modified configuration elements with security impact scoring.

---

## Sanitize for Sharing

**Goal:** Remove sensitive data before sharing a configuration file.

1. Redact sensitive data (IP addresses, passwords, keys) from the configuration:

   ```bash
   opndossier sanitize config.xml --mode aggressive -o config-safe.xml
   ```

2. To keep a mapping file that lets you correlate redacted values back to originals (for internal use only):

   ```bash
   opndossier sanitize config.xml -o config-safe.xml --mapping mappings.json
   ```

3. Verify the sanitized output does not contain sensitive data before distributing it.

**Expected result:** A sanitized XML file with sensitive values replaced by consistent pseudonyms. The optional mapping file provides a lookup table for internal reference.

---

## Process Multiple Files

**Goal:** Batch-process a directory of configuration files.

Save the following script as `batch-process.sh`:

```bash
#!/bin/bash
# batch-process.sh - Process multiple OPNsense configurations

set -euo pipefail

CONFIG_DIR="${1:?Usage: $0 <config-dir> [output-dir]}"
OUTPUT_DIR="${2:-./reports}"

mkdir -p "$OUTPUT_DIR"

echo "Starting batch processing..."

for config_file in "$CONFIG_DIR"/*.xml; do
    if [[ -f "$config_file" ]]; then
        filename=$(basename "$config_file" .xml)
        output_file="$OUTPUT_DIR/${filename}.md"

        echo "Processing: $config_file"

        if opndossier validate "$config_file" > /dev/null 2>&1; then
            opndossier convert "$config_file" \
                --comprehensive \
                -o "$output_file"
            echo "  Generated: $output_file"
        else
            echo "  Failed to validate: $config_file"
        fi
    fi
done

echo "Batch processing complete. Reports saved to: $OUTPUT_DIR"
```

Run it:

```bash
chmod +x batch-process.sh
./batch-process.sh /path/to/configs ./reports
```

For higher throughput on large directories, process files in parallel:

```bash
find configs/ -name "*.xml" | xargs -P 4 -I {} \
    sh -c 'opndossier convert "$1" -o "docs/$(basename "$1" .xml).md"' _ {}
```

**Expected result:** One markdown report per configuration file in the output directory. Invalid files are skipped with an error message.

---

## Automate with CI/CD

**Goal:** Generate documentation automatically on config changes.

Add the following GitHub Actions workflow to your repository as `.github/workflows/documentation.yml`:

```yaml
# .github/workflows/documentation.yml
name: Generate Network Documentation

on:
  push:
    paths:
      - configs/*.xml

jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Validate Configurations
        run: opndossier validate configs/*.xml

      - name: Generate Reports
        run: |
          mkdir -p reports
          for config in configs/*.xml; do
            filename=$(basename "$config" .xml)
            opndossier convert "$config" \
              --comprehensive \
              -o "reports/${filename}.md"
          done

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: network-reports
          path: reports/
```

**Expected result:** Every push that modifies files in `configs/` triggers validation and report generation. Reports are uploaded as build artifacts for download.

Adapt the `on` trigger and artifact handling to fit your workflow -- for example, committing reports back to the repository or deploying them to an internal documentation site.

---

## Debug Processing Issues

**Goal:** Diagnose why a configuration file is not processing correctly.

1. Validate the file first to isolate XML parsing issues from conversion problems:

   ```bash
   opndossier validate config.xml
   ```

2. If validation passes but conversion fails, re-run with verbose logging to see detailed processing information:

   ```bash
   opndossier --verbose convert config.xml
   ```

3. Capture both output and logs separately for analysis:

   ```bash
   opndossier --verbose convert config.xml > output.md 2> debug.log
   ```

4. Review `debug.log` for warnings about skipped sections, unsupported elements, or data transformation issues.

**Common error patterns:**

- **XML syntax error on line N** -- The configuration file has malformed XML. Open the file and check the indicated line for unclosed tags or invalid characters.
- **Permission denied** -- The current user does not have read access to the file. Check file permissions.
- **Mutually exclusive flags** -- Flags like `--verbose` and `--quiet`, or `--wrap` and `--no-wrap`, cannot be used together. Remove one of the conflicting flags.

**Expected result:** Enough diagnostic information to identify whether the issue is in the input file, the processing pipeline, or the command flags.
