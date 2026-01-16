# Usage Guide

This guide covers common workflows and examples for using opnDossier effectively.

## Basic Usage

### Convert Configuration Files

The primary use case is converting OPNsense configuration files to markdown:

```bash
# Convert to markdown (default format)
opnDossier convert config.xml

# Convert to markdown and save to file
opnDossier convert config.xml -o documentation.md

# Convert to markdown format explicitly
opnDossier convert -f markdown config.xml

# Convert to JSON format
opnDossier convert -f json config.xml -o output.json

# Convert to YAML format
opnDossier convert -f yaml config.xml -o output.yaml

# Convert multiple files (each gets appropriate extension)
opnDossier convert config1.xml config2.xml config3.xml

# Convert multiple files to JSON format
opnDossier convert -f json config1.xml config2.xml config3.xml
```

### Display Options

Control how output is displayed:

```bash
# Verbose output with debug information
opndossier --verbose convert config.xml

# Quiet mode - only errors
opndossier --quiet convert config.xml

# Enable validation with verbose output
opndossier --validate --verbose convert config.xml
```

## Configuration Management

### Using Configuration Files

Create `~/.opnDossier.yaml` for persistent settings:

```yaml
# Default settings for all operations
output_file: ./network-docs.md
verbose: false
```

### Environment Variables

Use environment variables for deployment automation:

```bash
# Set logging preferences
export OPNDOSSIER_VERBOSE=true

# Set default output location
export OPNDOSSIER_OUTPUT_FILE="./documentation.md"

# Run with environment configuration
opndossier convert config.xml
```

### CLI Flag Overrides

CLI flags have the highest precedence:

```bash
# Override config file settings
opndossier --verbose --output=custom.md convert config.xml

# Temporary verbose mode
opndossier --verbose convert config.xml

# Use custom config file
opndossier --config ./project-config.yaml convert config.xml
```

## Common Workflows

### 1. Document Network Configuration

```bash
# Basic documentation workflow
opndossier convert /etc/opnsense/config.xml -o network-documentation.md

# With verbose logging for troubleshooting
opndossier --verbose convert /etc/opnsense/config.xml -o network-docs.md

# Generate multiple formats
opndossier convert config.xml -o current-config.md
opndossier --verbose convert config.xml > config.log
```

### 2. Batch Processing

```bash
# Process multiple configuration files
opndossier convert *.xml

# Process files in a directory
find /path/to/configs -name "*.xml" -exec opndossier convert {} \;

# Process with parallel execution (if multiple files)
opndossier convert config1.xml config2.xml config3.xml
```

### 3. Automated Documentation Pipeline

```bash
#!/bin/bash
# automation-script.sh

# Set up environment
export OPNDOSSIER_VERBOSE=true

# Process configuration
opndossier convert /etc/opnsense/config.xml -o ./docs/network-config.md

# Check if successful
if [ $? -eq 0 ]; then
    echo "Documentation generated successfully"
    # Additional processing (git commit, upload, etc.)
else
    echo "Documentation generation failed"
    exit 1
fi
```

### 4. Debugging and Troubleshooting

```bash
# Debug XML parsing issues
opndossier --verbose convert problematic-config.xml

# Debug with validation enabled
opndossier --validate --verbose convert config.xml

# Capture detailed logs
opndossier --verbose convert config.xml > debug.log 2>&1

# Test configuration loading
opndossier --verbose --config ./test-config.yaml convert --help
```

## Validation and Error Handling

### Understanding Validation Output

opnDossier provides comprehensive validation with detailed error reporting:

```bash
# Enable validation during conversion
opndossier convert config.xml --validate

# Example validation error output
# validation error at opnsense.system.hostname: hostname is required
# validation error at opnsense.interfaces.wan.ipaddr: IP address '300.300.300.300' must be a valid IP address
```

### Common Validation Errors

#### Missing Required Fields

```bash
# Error: hostname is required
opndossier --validate convert incomplete-config.xml
# Output: validation error at opnsense.system.hostname: hostname is required
```

#### Invalid Network Configuration

```bash
# Error: invalid IP address
opndossier --validate convert bad-network-config.xml
# Output: validation error at opnsense.interfaces.lan.ipaddr: IP address '256.256.256.256' must be a valid IP address
```

#### Aggregated Error Reports

```bash
# Multiple validation errors
opndossier --validate convert multi-error-config.xml
# Output: validation failed with 3 errors: hostname is required (and 2 more)
#   - opnsense.system.hostname: hostname is required
#   - opnsense.system.domain: domain is required
#   - opnsense.interfaces.lan.subnet: subnet mask '35' must be valid (0-32)
```

### Streaming Processing

opnDossier handles large configuration files efficiently:

```bash
# Process large configuration files
opndossier convert large-config.xml  # Automatically uses streaming

# Monitor memory usage during processing
opndossier --verbose convert large-config.xml
# Output shows memory cleanup after processing large sections
```

## Advanced Usage

### Configuration Precedence Testing

Test how configuration precedence works:

```bash
# Create test config file
cat > test-config.yaml << EOF
verbose: false
quiet: false
EOF

# Test precedence: config file < env vars < CLI flags
opndossier --config test-config.yaml convert config.xml  # Uses config file settings
OPNDOSSIER_VERBOSE=true opndossier --config test-config.yaml convert config.xml  # Env var overrides config
opndossier --config test-config.yaml --quiet convert config.xml  # CLI flag overrides all
```

### Custom Output Locations

```bash
# Create output directory structure
mkdir -p docs/network/{current,archive}

# Generate documentation with custom paths
opndossier convert config.xml -o docs/network/current/config.md

# Use environment variables for paths
export OPNDOSSIER_OUTPUT_FILE="docs/network/current/config.md"
opndossier convert config.xml

# Batch process to different locations
for config in configs/*.xml; do
    name=$(basename "$config" .xml)
    opndossier convert "$config" -o "docs/${name}.md"
done
```

### Integration with Other Tools

#### Git Integration

```bash
# Document configuration changes
opndossier convert config.xml -o current-config.md
git add current-config.md
git commit -m "docs: update network configuration documentation"
```

#### CI/CD Pipeline Integration

```yaml
# .github/workflows/docs.yml
name: Generate Documentation
on: [push, pull_request]

jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      - name: Install opnDossier
        run: go install github.com/EvilBit-Labs/opnDossier@latest

      - name: Generate Documentation
        env:
          OPNDOSSIER_VERBOSE: true
        run: opndossier convert config.xml -o docs/network-config.md

      - name: Commit Documentation
        if: github.event_name == 'push'
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add docs/network-config.md
          git commit -m "docs: update network configuration" || exit 0
          git push
```

#### Monitoring Integration

```bash
# Generate metrics for monitoring
opndossier --verbose convert config.xml > metrics.log 2>&1

# Parse logs for monitoring
grep -i "error" metrics.log | wc -l

# Health check script
#!/bin/bash
if opndossier convert config.xml -o /tmp/test.md > /dev/null 2>&1; then
    echo "opnDossier: OK"
    exit 0
else
    echo "opnDossier: FAILED"
    exit 1
fi
```

## Error Handling and Troubleshooting

### Common Error Scenarios

#### 1. XML Parsing Errors

```bash
# Invalid XML structure
opndossier convert invalid-config.xml
# Error: failed to parse XML from invalid-config.xml: XML syntax error on line 42

# Debug XML issues
opndossier --verbose convert invalid-config.xml
```

#### 2. File Permission Issues

```bash
# Permission denied
opndossier convert /root/config.xml
# Error: failed to open file /root/config.xml: permission denied

# Solution: copy file or adjust permissions
sudo cp /root/config.xml ./config.xml
opndossier convert config.xml
```

#### 3. Configuration Validation Errors

```bash
# Conflicting flags
opndossier --verbose --quiet convert config.xml
# Error: verbose and quiet options are mutually exclusive

```

### Debugging Tips

1. **Use verbose mode for detailed information:**

   ```bash
   opndossier --verbose convert config.xml
   ```

2. **Check configuration precedence:**

   ```bash
   opndossier --verbose --config /path/to/config.yaml convert --help
   ```

3. **Validate configuration files:**

   ```bash
   # Test config file syntax
   opndossier --config test-config.yaml --help
   ```

4. **Capture verbose logs for automated analysis:**

```bash
opndossier --verbose convert config.xml > output.log 2>&1
```

## Performance Optimization

### Large File Processing

```bash
# Process large files efficiently
opndossier --quiet convert large-config.xml

# Monitor memory usage
/usr/bin/time -v opndossier convert large-config.xml
```

### Batch Processing Optimization

```bash
# Process multiple files concurrently (built-in)
opndossier convert config1.xml config2.xml config3.xml

# Custom parallel processing
find /configs -name "*.xml" | xargs -P 4 -I {} opndossier convert {} -o {}.md
```

## Best Practices

### 1. Configuration Management

- Use configuration files for persistent settings
- Use environment variables for deployment-specific settings
- Use CLI flags for temporary overrides

### 2. File Organization

```bash
# Organize output files logically
opndossier convert config.xml -o docs/network/$(date +%Y-%m-%d)-config.md

# Archive old documentation
mkdir -p docs/network/archive/$(date +%Y/%m)
mv docs/network/*.md docs/network/archive/$(date +%Y/%m)/
```

### 3. Automation

- Always use error checking in scripts
- Use structured logging (JSON) for automated processing
- Implement health checks for monitoring

### 4. Security

- Keep configuration files in secure locations
- Use environment variables for sensitive settings (if any)
- Regularly audit generated documentation for sensitive information

---

For more advanced examples and specific use cases, see our [Examples](../examples/) section.
