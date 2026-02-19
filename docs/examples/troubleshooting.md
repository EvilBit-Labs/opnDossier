# Troubleshooting and Debugging

This guide covers common issues, error handling, and debugging techniques for opnDossier.

## Common Error Scenarios

### XML Parsing Errors

#### Invalid XML Structure

```bash
# Error: Invalid XML syntax
opndossier convert invalid-config.xml
# Output: failed to parse XML from invalid-config.xml: XML syntax error on line 42

# Debug XML issues with verbose output
opndossier --verbose convert invalid-config.xml

# Validate XML syntax independently
xmllint --noout invalid-config.xml
```

#### Missing OPNsense Root Element

```bash
# Error: Missing required root element
opndossier convert non-opnsense.xml
# Output: invalid XML: missing opnsense root element
```

### File Issues

```bash
# Error: Permission denied
opndossier convert /root/config.xml
# Output: failed to open file /root/config.xml: permission denied

# Solutions:
# 1. Copy file to accessible location
sudo cp /root/config.xml ./config.xml
opndossier convert config.xml

# 2. Change file permissions (if appropriate)
sudo chmod 644 /root/config.xml

# 3. Run with appropriate permissions
sudo opndossier convert /root/config.xml
```

### Flag Validation Errors

```bash
# Error: Mutually exclusive flags
opndossier --verbose --quiet convert config.xml
# Output: `verbose` and `quiet` are mutually exclusive

# Error: Invalid output format
opndossier convert config.xml -f invalid
# Output: invalid format 'invalid', must be one of: markdown, md, json, yaml, yml, text, txt, html, htm

# Error: Invalid color mode
opndossier --color invalid convert config.xml
# Output: invalid color "invalid", must be one of: auto, always, never

# Error: Mutually exclusive wrap flags
opndossier convert config.xml --wrap 100 --no-wrap
# Output: --no-wrap and --wrap flags are mutually exclusive
```

## Debug Techniques

### Verbose Debugging

```bash
# Enable verbose output for detailed debugging
opndossier --verbose convert config.xml

# Combine verbose with file output to capture logs
opndossier --verbose convert config.xml -o output.md 2>debug.log

# Verbose validation
opndossier --verbose validate config.xml
```

### Step-by-Step Debugging

```bash
# 1. Validate configuration first
opndossier validate config.xml

# 2. Test basic conversion
opndossier convert config.xml

# 3. Test with specific format
opndossier convert config.xml -f json

# 4. Test with specific sections
opndossier convert config.xml --section system

# 5. Add complexity gradually
opndossier convert config.xml --comprehensive --include-tunables
```

### JSON Error Output

For scripting and automation, use JSON error output:

```bash
# Get errors in JSON format for programmatic handling
opndossier --json-output validate config.xml

# Parse JSON errors with jq
opndossier --json-output validate config.xml 2>&1 | jq '.error'
```

## Common Issues and Solutions

### Issue 1: Large File Processing

**Symptoms:**

- Slow processing

**Solutions:**

```bash
# Process specific sections only for faster output
opndossier convert large-config.xml --section system,interfaces

# Monitor processing time
time opndossier convert large-config.xml -o output.md
```

### Issue 2: Output File Issues

**Symptoms:**

- File not created
- Permission errors
- Overwrite prompts

**Solutions:**

```bash
# Check output directory permissions
ls -la /path/to/output/directory

# Force overwrite existing files
opndossier convert config.xml -o output.md --force

# Use different output location
opndossier convert config.xml -o /tmp/output.md

# Check disk space
df -h /path/to/output/directory
```

### Issue 3: Encoding Issues

opnDossier supports UTF-8, US-ASCII, ISO-8859-1 (Latin1), and Windows-1252 encoded XML files. If you encounter encoding errors:

```bash
# Check file encoding
file config.xml

# Convert encoding if needed (example: convert from UTF-16 to UTF-8)
iconv -f UTF-16 -t UTF-8 config.xml > config-utf8.xml
opndossier convert config-utf8.xml
```

### Issue 4: Unexpected Output

```bash
# Verify the input is a valid OPNsense configuration
opndossier validate config.xml

# Check with verbose output for processing details
opndossier --verbose convert config.xml

# Try different output formats to isolate the issue
opndossier convert config.xml -f json | jq '.' > /dev/null
```

## Diagnostic Scripts

### Configuration Health Check

```bash
#!/bin/bash
# config-health-check.sh

CONFIG_FILE="${1:?Usage: $0 <config-file>}"
LOG_FILE="health-check.log"

echo "Configuration Health Check for $CONFIG_FILE" > "$LOG_FILE"
echo "Started at $(date)" >> "$LOG_FILE"

# Check file existence
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: File not found: $CONFIG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi

# Check file is readable
if [ ! -r "$CONFIG_FILE" ]; then
    echo "ERROR: File not readable: $CONFIG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi

# Check file is not empty
if [ ! -s "$CONFIG_FILE" ]; then
    echo "ERROR: File is empty: $CONFIG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi

# Validate XML syntax (if xmllint is available)
if command -v xmllint &> /dev/null; then
    if xmllint --noout "$CONFIG_FILE" 2>/dev/null; then
        echo "XML syntax: VALID" | tee -a "$LOG_FILE"
    else
        echo "XML syntax: INVALID" | tee -a "$LOG_FILE"
        exit 1
    fi
fi

# Run opnDossier validation
if opndossier validate "$CONFIG_FILE" >> "$LOG_FILE" 2>&1; then
    echo "opnDossier validation: PASSED" | tee -a "$LOG_FILE"
else
    echo "opnDossier validation: FAILED" | tee -a "$LOG_FILE"
    exit 1
fi

# Test conversion
if opndossier convert "$CONFIG_FILE" -o /tmp/test-output.md >> "$LOG_FILE" 2>&1; then
    echo "Conversion test: PASSED" | tee -a "$LOG_FILE"
    rm -f /tmp/test-output.md
else
    echo "Conversion test: FAILED" | tee -a "$LOG_FILE"
    exit 1
fi

echo "Health check completed successfully at $(date)" | tee -a "$LOG_FILE"
```

## Environment Isolation

```bash
# Test in a clean environment
env -i PATH=/usr/bin:/bin HOME="$HOME" opndossier convert config.xml

# Test without any config file
opndossier --config /dev/null convert config.xml

# Test with specific environment variables
OPNDOSSIER_VERBOSE=true opndossier convert config.xml
```

## Best Practices for Troubleshooting

### 1. Systematic Approach

```bash
# Always start with validation
opndossier validate config.xml

# Test basic functionality
opndossier convert config.xml

# Add complexity gradually
opndossier convert config.xml -f json
opndossier convert config.xml --comprehensive
opndossier convert config.xml --section system,interfaces
```

### 2. Error Handling in Scripts

```bash
#!/bin/bash
set -e  # Exit on any error

handle_error() {
    local exit_code=$?
    echo "Error occurred in line $1, exit code: $exit_code"
    echo "$(date): Error in $0 at line $1, exit code: $exit_code" >> error.log
    exit $exit_code
}

trap 'handle_error $LINENO' ERR

opndossier validate config.xml
opndossier convert config.xml -o output.md
```

### 3. Capture Detailed Logs

```bash
# Capture stdout and stderr separately
opndossier --verbose convert config.xml > output.md 2> debug.log

# Review debug log for issues
cat debug.log
```

---

**Next Steps:**

- For advanced configuration, see [Advanced Configuration](advanced-configuration.md)
- For basic documentation, see [Basic Documentation](basic-documentation.md)
- For automation, see [Automation and Scripting](automation-scripting.md)
