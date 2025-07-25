# Usage Guide

This guide covers common workflows and examples for using opnFocus effectively.

## Basic Usage

### Convert Configuration Files

The primary use case is converting OPNsense configuration files to markdown:

```bash
# Convert and display in terminal
opnfocus convert config.xml

# Convert and save to file
opnfocus convert config.xml -o documentation.md

# Convert multiple files
opnfocus convert config1.xml config2.xml config3.xml
```

### Display Options

Control how output is displayed:

```bash
# Verbose output with debug information
opnfocus --verbose convert config.xml

# Quiet mode - only errors
opnfocus --quiet convert config.xml

# JSON logging format
opnfocus --log_format=json convert config.xml
```

## Configuration Management

### Using Configuration Files

Create `~/.opnFocus.yaml` for persistent settings:

```yaml
# Default settings for all operations
log_level: info
log_format: text
output_file: ./network-docs.md
verbose: false
```

### Environment Variables

Use environment variables for deployment automation:

```bash
# Set logging preferences
export OPNFOCUS_LOG_LEVEL=debug
export OPNFOCUS_LOG_FORMAT=json

# Set default output location
export OPNFOCUS_OUTPUT_FILE="./documentation.md"

# Run with environment configuration
opnfocus convert config.xml
```

### CLI Flag Overrides

CLI flags have the highest precedence:

```bash
# Override config file settings
opnfocus --log_level=debug --output=custom.md convert config.xml

# Temporary verbose mode
opnfocus --verbose convert config.xml

# Use custom config file
opnfocus --config ./project-config.yaml convert config.xml
```

## Common Workflows

### 1. Document Network Configuration

```bash
# Basic documentation workflow
opnfocus convert /etc/opnsense/config.xml -o network-documentation.md

# With verbose logging for troubleshooting
opnfocus --verbose convert /etc/opnsense/config.xml -o network-docs.md

# Generate multiple formats
opnfocus convert config.xml -o current-config.md
opnfocus --log_format=json convert config.xml > config-log.json
```

### 2. Batch Processing

```bash
# Process multiple configuration files
opnfocus convert *.xml

# Process files in a directory
find /path/to/configs -name "*.xml" -exec opnfocus convert {} \;

# Process with parallel execution (if multiple files)
opnfocus convert config1.xml config2.xml config3.xml
```

### 3. Automated Documentation Pipeline

```bash
#!/bin/bash
# automation-script.sh

# Set up environment
export OPNFOCUS_LOG_FORMAT=json
export OPNFOCUS_LOG_LEVEL=info

# Process configuration
opnfocus convert /etc/opnsense/config.xml -o ./docs/network-config.md

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
opnfocus --verbose --log_level=debug convert problematic-config.xml

# Capture detailed logs
opnfocus --log_format=json --log_level=debug convert config.xml > debug.log 2>&1

# Test configuration loading
opnfocus --verbose --config ./test-config.yaml convert --help
```

## Advanced Usage

### Configuration Precedence Testing

Test how configuration precedence works:

```bash
# Create test config file
cat > test-config.yaml << EOF
log_level: "warn"
log_format: "json"
verbose: false
EOF

# Test precedence: config file < env vars < CLI flags
opnfocus --config test-config.yaml convert config.xml  # Uses config file settings
OPNFOCUS_LOG_LEVEL=info opnfocus --config test-config.yaml convert config.xml  # Env var overrides config
opnfocus --config test-config.yaml --log_level=debug convert config.xml  # CLI flag overrides all
```

### Custom Output Locations

```bash
# Create output directory structure
mkdir -p docs/network/{current,archive}

# Generate documentation with custom paths
opnfocus convert config.xml -o docs/network/current/config.md

# Use environment variables for paths
export OPNFOCUS_OUTPUT_FILE="docs/network/current/config.md"
opnfocus convert config.xml

# Batch process to different locations
for config in configs/*.xml; do
    name=$(basename "$config" .xml)
    opnfocus convert "$config" -o "docs/${name}.md"
done
```

### Integration with Other Tools

#### Git Integration

```bash
# Document configuration changes
opnfocus convert config.xml -o current-config.md
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
      - name: Install opnFocus
        run: go install github.com/unclesp1d3r/opnFocus@latest

      - name: Generate Documentation
        env:
          OPNFOCUS_LOG_FORMAT: json
          OPNFOCUS_LOG_LEVEL: info
        run: opnfocus convert config.xml -o docs/network-config.md

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
opnfocus --log_format=json convert config.xml 2> metrics.json

# Parse logs for monitoring
jq '.level' metrics.json | sort | uniq -c

# Health check script
#!/bin/bash
if opnfocus convert config.xml -o /tmp/test.md > /dev/null 2>&1; then
    echo "opnFocus: OK"
    exit 0
else
    echo "opnFocus: FAILED"
    exit 1
fi
```

## Error Handling and Troubleshooting

### Common Error Scenarios

#### 1. XML Parsing Errors

```bash
# Invalid XML structure
opnfocus convert invalid-config.xml
# Error: failed to parse XML from invalid-config.xml: XML syntax error on line 42

# Debug XML issues
opnfocus --verbose convert invalid-config.xml
```

#### 2. File Permission Issues

```bash
# Permission denied
opnfocus convert /root/config.xml
# Error: failed to open file /root/config.xml: permission denied

# Solution: copy file or adjust permissions
sudo cp /root/config.xml ./config.xml
opnfocus convert config.xml
```

#### 3. Configuration Validation Errors

```bash
# Conflicting flags
opnfocus --verbose --quiet convert config.xml
# Error: verbose and quiet options are mutually exclusive

# Invalid log level
opnfocus --log_level=trace convert config.xml
# Error: invalid log level 'trace', must be one of: debug, info, warn, error
```

### Debugging Tips

1. **Use verbose mode for detailed information:**

   ```bash
   opnfocus --verbose convert config.xml
   ```

2. **Check configuration precedence:**

   ```bash
   opnfocus --verbose --config /path/to/config.yaml convert --help
   ```

3. **Validate configuration files:**

   ```bash
   # Test config file syntax
   opnfocus --config test-config.yaml --help
   ```

4. **Use JSON logging for automated analysis:**

   ```bash
   opnfocus --log_format=json convert config.xml > output.log 2>&1
   jq '.' output.log  # Parse JSON logs
   ```

## Performance Optimization

### Large File Processing

```bash
# Process large files efficiently
opnfocus --log_level=warn convert large-config.xml

# Monitor memory usage
/usr/bin/time -v opnfocus convert large-config.xml
```

### Batch Processing Optimization

```bash
# Process multiple files concurrently (built-in)
opnfocus convert config1.xml config2.xml config3.xml

# Custom parallel processing
find /configs -name "*.xml" | xargs -P 4 -I {} opnfocus convert {} -o {}.md
```

## Best Practices

### 1. Configuration Management

- Use configuration files for persistent settings
- Use environment variables for deployment-specific settings
- Use CLI flags for temporary overrides

### 2. File Organization

```bash
# Organize output files logically
opnfocus convert config.xml -o docs/network/$(date +%Y-%m-%d)-config.md

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
