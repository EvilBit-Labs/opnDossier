# Audit and Compliance Examples

> **⚠️ Note: Audit and compliance functionality is not yet implemented in opnDossier v1.0.**
>
> This documentation describes planned features for future releases. The audit mode flags (`--mode`, `--blackhat-mode`, `--plugins`) are currently disabled and not available in the current version.
>
> For current functionality, see the [Basic Usage](../user-guide/usage.md) and [Advanced Configuration](advanced-configuration.md) guides.

This guide covers security auditing and compliance checking workflows using opnDossier (planned for future releases).

## Security Audit Reports

### Blue Team Audit Reports

Generate defensive security audit reports with findings and recommendations:

```bash
# Basic blue team audit
opnDossier convert config.xml --mode blue

# Comprehensive blue team audit
opnDossier convert config.xml --mode blue --comprehensive -o blue-team-audit.md

# Blue team audit with specific plugins
opnDossier convert config.xml --mode blue --plugins stig,sans -o compliance-audit.md

# Blue team audit with custom template
opnDossier convert config.xml --mode blue --template-dir ./custom-templates -o custom-audit.md
```

**Example Blue Team Output:**

```markdown
# Blue Team Security Audit Report

## Executive Summary
- **Overall Security Score**: 7.2/10
- **Critical Findings**: 2
- **High Priority Issues**: 5
- **Medium Priority Issues**: 8

## Critical Security Findings

### 1. HTTP Web Management Enabled
- **Severity**: Critical
- **Description**: Web management interface is accessible via HTTP
- **Risk**: Credentials transmitted in cleartext
- **Recommendation**: Enable HTTPS immediately

### 2. Default SNMP Community
- **Severity**: Critical
- **Description**: SNMP using default community string 'public'
- **Risk**: Unauthorized network access
- **Recommendation**: Change SNMP community string

## Network Security Analysis
...
```

### Red Team Recon Reports

Generate attacker-focused reconnaissance reports highlighting attack surfaces:

```bash
# Basic red team recon
opnDossier convert config.xml --mode red

# Red team recon with blackhat commentary
opnDossier convert config.xml --mode red --blackhat-mode -o red-team-recon.md

# Comprehensive red team analysis
opnDossier convert config.xml --mode red --comprehensive --blackhat-mode -o attack-surface.md
```

**Example Red Team Output:**

```markdown
# Red Team Reconnaissance Report

## Attack Surface Analysis

### Primary Attack Vectors

#### 1. Web Management Interface
- **Target**: 192.168.1.1:80 (HTTP)
- **Vulnerability**: Cleartext authentication
- **Exploitation**: Credential harvesting via man-in-the-middle
- **Impact**: Full administrative access

#### 2. SNMP Service
- **Target**: 192.168.1.1:161 (SNMP)
- **Vulnerability**: Default community string 'public'
- **Exploitation**: Network enumeration and configuration extraction
- **Impact**: Network topology discovery

### Network Exposure Analysis
- **WAN Interfaces**: 1 exposed
- **LAN Interfaces**: 1 internal
- **DMZ Interfaces**: 0 configured
- **VPN Endpoints**: 0 configured

### Firewall Rule Analysis
- **Permissive Rules**: 3 identified
- **Any/Any Rules**: 1 identified
- **Port Exposure**: 80, 161, 22
```

## Compliance Checking

### STIG Compliance

Check configurations against STIG (Security Technical Implementation Guide) standards:

```bash
# STIG compliance check
opnDossier convert config.xml --mode blue --plugins stig -o stig-compliance.md

# STIG compliance with comprehensive analysis
opnDossier convert config.xml --mode blue --plugins stig --comprehensive -o stig-audit.md

# STIG compliance with custom template
opnDossier convert config.xml --mode blue --plugins stig --template stig-report -o stig-report.md
```

**Example STIG Output:**

```markdown
# STIG Compliance Report

## Compliance Summary
- **Total Controls**: 45
- **Compliant**: 32
- **Non-Compliant**: 13
- **Compliance Rate**: 71.1%

## Critical STIG Violations

### STIG-001: SSH Warning Banner
- **Status**: Non-Compliant
- **Requirement**: SSH must display warning banner
- **Finding**: No SSH warning banner configured
- **Remediation**: Configure SSH warning banner

### STIG-002: HTTPS Web Management
- **Status**: Non-Compliant
- **Requirement**: Web management must use HTTPS
- **Finding**: HTTP enabled for web management
- **Remediation**: Disable HTTP, enable HTTPS only
```

### SANS Compliance

Check configurations against SANS security controls:

```bash
# SANS compliance check
opnDossier convert config.xml --mode blue --plugins sans -o sans-compliance.md

# SANS compliance with comprehensive analysis
opnDossier convert config.xml --mode blue --plugins sans --comprehensive -o sans-audit.md

# Multiple compliance frameworks
opnDossier convert config.xml --mode blue --plugins stig,sans -o multi-compliance.md
```

**Example SANS Output:**

```markdown
# SANS Critical Security Controls Report

## Control Coverage Analysis

### Control 1: Inventory and Control of Hardware Assets
- **Status**: Partially Compliant
- **Coverage**: 75%
- **Findings**: Network interfaces properly documented
- **Gaps**: Missing hardware asset tracking

### Control 4: Controlled Access Based on Need to Know
- **Status**: Non-Compliant
- **Coverage**: 40%
- **Findings**: Basic access controls in place
- **Gaps**: Missing role-based access controls
```

## Advanced Audit Workflows

### Comprehensive Security Assessment

```bash
#!/bin/bash
# comprehensive-audit.sh

# Set up environment
export OPNDOSSIER_LOG_FORMAT=json
export OPNDOSSIER_LOG_LEVEL=info

# Create audit directory
AUDIT_DIR="audits/$(date +%Y-%m-%d)"
mkdir -p "$AUDIT_DIR"

# Generate blue team audit
echo "Generating blue team audit..."
opnDossier convert config.xml --mode blue --comprehensive \
    --plugins stig,sans \
    -o "${AUDIT_DIR}/blue-team-audit.md"

# Generate red team recon
echo "Generating red team recon..."
opnDossier convert config.xml --mode red --comprehensive \
    --blackhat-mode \
    -o "${AUDIT_DIR}/red-team-recon.md"

# Generate compliance report
echo "Generating compliance report..."
opnDossier convert config.xml --mode blue \
    --plugins stig,sans \
    --template compliance \
    -o "${AUDIT_DIR}/compliance-report.md"

echo "Comprehensive audit completed in ${AUDIT_DIR}"
```

### Automated Compliance Pipeline

```bash
#!/bin/bash
# compliance-pipeline.sh

set -e

# Configuration
CONFIG_FILE="config.xml"
COMPLIANCE_DIR="compliance-reports"
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Create compliance directory
mkdir -p "$COMPLIANCE_DIR"

# Validate configuration first
echo "Validating configuration..."
if ! opnDossier validate "$CONFIG_FILE"; then
    echo "Configuration validation failed"
    exit 1
fi

# Generate STIG compliance report
echo "Generating STIG compliance report..."
opnDossier convert "$CONFIG_FILE" \
    --mode blue \
    --plugins stig \
    --comprehensive \
    -o "${COMPLIANCE_DIR}/stig-${TIMESTAMP}.md"

# Generate SANS compliance report
echo "Generating SANS compliance report..."
opnDossier convert "$CONFIG_FILE" \
    --mode blue \
    --plugins sans \
    --comprehensive \
    -o "${COMPLIANCE_DIR}/sans-${TIMESTAMP}.md"

# Generate combined compliance report
echo "Generating combined compliance report..."
opnDossier convert "$CONFIG_FILE" \
    --mode blue \
    --plugins stig,sans \
    --comprehensive \
    -o "${COMPLIANCE_DIR}/combined-${TIMESTAMP}.md"

# Generate executive summary
echo "Generating executive summary..."
opnDossier convert "$CONFIG_FILE" \
    --mode blue \
    --plugins stig,sans \
    --template executive \
    -o "${COMPLIANCE_DIR}/executive-summary-${TIMESTAMP}.md"

echo "Compliance pipeline completed successfully"
```

### Security Score Tracking

```bash
#!/bin/bash
# security-score-tracker.sh

# Extract security scores from audit reports
extract_security_score() {
    local report_file="$1"
    if [ ! -f "$report_file" ]; then
        echo "Error: Report file $report_file not found" >&2
        return 1
    fi

    # Try multiple patterns to find security score
    local score=$(grep -i -o "Security Score.*[0-9.]*" "$report_file" | grep -o "[0-9.]*" | head -1)
    if [ -z "$score" ]; then
        score=$(grep -i -o "Overall Security Score.*[0-9.]*" "$report_file" | grep -o "[0-9.]*" | head -1)
    fi

    echo "$score"
}

# Extract STIG compliance scores from audit reports
extract_stig_score() {
    local report_file="$1"
    if [ ! -f "$report_file" ]; then
        echo "Error: Report file $report_file not found" >&2
        return 1
    fi

    # Try multiple patterns to find STIG compliance
    local score=$(grep -i -o "STIG Compliance.*[0-9.]*%" "$report_file" | grep -o "[0-9.]*" | head -1)
    if [ -z "$score" ]; then
        score=$(grep -i -o "STIG.*[0-9.]*%" "$report_file" | grep -o "[0-9.]*" | head -1)
    fi

    echo "$score"
}

# Extract SANS compliance scores from audit reports
extract_sans_score() {
    local report_file="$1"
    if [ ! -f "$report_file" ]; then
        echo "Error: Report file $report_file not found" >&2
        return 1
    fi

    # Try multiple patterns to find SANS compliance
    local score=$(grep -i -o "SANS Compliance.*[0-9.]*%" "$report_file" | grep -o "[0-9.]*" | head -1)
    if [ -z "$score" ]; then
        score=$(grep -i -o "SANS.*[0-9.]*%" "$report_file" | grep -o "[0-9.]*" | head -1)
    fi

    echo "$score"
}

# Generate audit report
opnDossier convert config.xml --mode blue --comprehensive -o current-audit.md

# Extract and log security score
SCORE=$(extract_security_score current-audit.md)
DATE=$(date +%Y-%m-%d)

if [ -n "$SCORE" ]; then
    echo "$DATE,$SCORE" >> security-scores.csv
    echo "Security score for $DATE: $SCORE/10"
else
    echo "Warning: Could not extract security score from report" >&2
fi
```

## Custom Audit Templates

### Executive Summary Template

Create `~/.opnDossier/templates/executive.md.tmpl`:

```markdown
# Executive Security Summary

## Key Metrics
- **Overall Security Score**: {{.SecurityScore}}/10
- **Critical Issues**: {{.CriticalCount}}
- **High Priority Issues**: {{.HighCount}}
- **Compliance Rate**: {{.ComplianceRate}}%

## Top 3 Critical Issues
{{range .TopIssues}}
### {{.Title}}
- **Severity**: {{.Severity}}
- **Impact**: {{.Impact}}
- **Recommendation**: {{.Recommendation}}
{{end}}

## Compliance Status
- **STIG Compliance**: {{.STIGCompliance}}%
- **SANS Compliance**: {{.SANSCompliance}}%

## Next Steps
1. Address critical security issues immediately
2. Implement recommended controls
3. Schedule follow-up assessment
```

### Technical Deep Dive Template

Create `~/.opnDossier/templates/technical.md.tmpl`:

```markdown
# Technical Security Analysis

## Network Architecture
{{range .Interfaces}}
### {{.Name}} Interface
- **IP Address**: {{.IPAddress}}
- **Subnet**: {{.Subnet}}
- **Security Level**: {{.SecurityLevel}}
- **Exposed Services**: {{.ExposedServices}}
{{end}}

## Firewall Rule Analysis
{{range .FirewallRules}}
### Rule {{.Number}}: {{.Description}}
- **Action**: {{.Action}}
- **Interface**: {{.Interface}}
- **Source**: {{.Source}}
- **Destination**: {{.Destination}}
- **Security Risk**: {{.SecurityRisk}}
{{end}}

## Vulnerability Assessment
{{range .Vulnerabilities}}
### {{.Title}}
- **CVE**: {{.CVE}}
- **CVSS Score**: {{.CVSSScore}}
- **Description**: {{.Description}}
- **Remediation**: {{.Remediation}}
{{end}}
```

## Integration Examples

### CI/CD Security Gate

```yaml
# .github/workflows/security-gate.yml
name: Security Compliance Check
on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.21'

      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Run Security Audit
        run: |
          opnDossier convert config.xml --mode blue --plugins stig,sans -o security-audit.md

      - name: Check Security Score
        run: |
          SCORE=$(grep -o "Security Score.*[0-9.]*" security-audit.md | grep -o "[0-9.]*" | head -1)
          if (( $(echo "$SCORE < 7.0" | bc -l) )); then
            echo "Security score $SCORE is below threshold of 7.0"
            exit 1
          fi

      - name: Upload Audit Report
        uses: actions/upload-artifact@v3
        with:
          name: security-audit
          path: security-audit.md
```

### Monthly Compliance Reporting

```bash
#!/bin/bash
# monthly-compliance-report.sh

# Set up environment
export OPNDOSSIER_LOG_FORMAT=json
export OPNDOSSIER_LOG_LEVEL=info

# Create monthly report directory
MONTH=$(date +%Y-%m)
REPORT_DIR="reports/${MONTH}"
mkdir -p "$REPORT_DIR"

# Generate comprehensive compliance report
opnDossier convert config.xml \
    --mode blue \
    --plugins stig,sans \
    --comprehensive \
    --template monthly-report \
    -o "${REPORT_DIR}/compliance-report.md"

# Generate executive summary
opnDossier convert config.xml \
    --mode blue \
    --plugins stig,sans \
    --template executive \
    -o "${REPORT_DIR}/executive-summary.md"

# Generate trend analysis
if [ -f "reports/previous-month/compliance-report.md" ]; then
    echo "Generating trend analysis..."
    # Compare with previous month
    diff "reports/previous-month/compliance-report.md" "${REPORT_DIR}/compliance-report.md" > "${REPORT_DIR}/changes.md"
fi

echo "Monthly compliance report generated in ${REPORT_DIR}"
```

## Best Practices

### 1. Regular Audit Scheduling

```bash
# Add to crontab for weekly audits
0 2 * * 1 /path/to/weekly-audit.sh

# Add to crontab for monthly compliance reports
0 3 1 * * /path/to/monthly-compliance-report.sh
```

### 2. Audit Result Tracking

```bash
# Track security scores over time
echo "$(date +%Y-%m-%d),$(extract_security_score audit.md)" >> security-trends.csv

# Generate trend analysis
gnuplot -e "set datafile separator ','; plot 'security-trends.csv' using 1:2 with lines"
```

### 3. Remediation Tracking

```bash
# Extract remediation items
grep -A 5 "Recommendation" audit.md > remediation-list.md

# Track remediation progress
echo "Remediation items extracted to remediation-list.md"
```

### 4. Compliance Thresholds

```bash
# Set minimum compliance thresholds
MIN_STIG_SCORE=80
MIN_SANS_SCORE=75

# Check thresholds
STIG_SCORE=$(extract_stig_score audit.md)
SANS_SCORE=$(extract_sans_score audit.md)

if [ "$STIG_SCORE" -lt "$MIN_STIG_SCORE" ] || [ "$SANS_SCORE" -lt "$MIN_SANS_SCORE" ]; then
    echo "Compliance thresholds not met"
    exit 1
fi
```

### 5. Complete Score Tracking Example

```bash
#!/bin/bash
# complete-score-tracking.sh

# Configuration
REPORT_FILE="audit-report.md"
SCORES_FILE="compliance-scores.csv"
TIMESTAMP=$(date +%Y-%m-%d)

# Generate comprehensive audit report
echo "Generating audit report..."
opnDossier convert config.xml \
    --mode blue \
    --plugins stig,sans \
    --comprehensive \
    -o "$REPORT_FILE"

# Extract all scores
SECURITY_SCORE=$(extract_security_score "$REPORT_FILE")
STIG_SCORE=$(extract_stig_score "$REPORT_FILE")
SANS_SCORE=$(extract_sans_score "$REPORT_FILE")

# Log scores to CSV file
if [ -n "$SECURITY_SCORE" ] && [ -n "$STIG_SCORE" ] && [ -n "$SANS_SCORE" ]; then
    echo "$TIMESTAMP,$SECURITY_SCORE,$STIG_SCORE,$SANS_SCORE" >> "$SCORES_FILE"
    echo "Scores logged: Security=$SECURITY_SCORE, STIG=$STIG_SCORE%, SANS=$SANS_SCORE%"
else
    echo "Warning: Could not extract all scores from report" >&2
    exit 1
fi

# Check compliance thresholds
MIN_SECURITY=7.0
MIN_STIG=80
MIN_SANS=75

FAILURES=0

if (( $(echo "$SECURITY_SCORE < $MIN_SECURITY" | bc -l) )); then
    echo "Security score $SECURITY_SCORE is below threshold $MIN_SECURITY"
    FAILURES=$((FAILURES + 1))
fi

if [ "$STIG_SCORE" -lt "$MIN_STIG" ]; then
    echo "STIG score $STIG_SCORE% is below threshold $MIN_STIG%"
    FAILURES=$((FAILURES + 1))
fi

if [ "$SANS_SCORE" -lt "$MIN_SANS" ]; then
    echo "SANS score $SANS_SCORE% is below threshold $MIN_SANS%"
    FAILURES=$((FAILURES + 1))
fi

if [ $FAILURES -gt 0 ]; then
    echo "Compliance check failed with $FAILURES violations"
    exit 1
else
    echo "All compliance thresholds met"
fi
```

---

**Next Steps:**

- For automation workflows, see [Automation and Scripting](automation-scripting.md)
- For troubleshooting, see [Troubleshooting](troubleshooting.md)
- For advanced configuration, see [Advanced Configuration](advanced-configuration.md)
