# Validation & Error Handling

opnDossier validates OPNsense configuration files during parsing and provides detailed error reporting.

## Validation Features

### XML Structure Validation

The parser validates that the input is well-formed XML with the required OPNsense root element:

- **Well-formed XML**: Standard XML syntax validation via Go's `encoding/xml`
- **Root element check**: Ensures `<opnsense>` root element is present
- **Size limit**: Default 10MB maximum input size (`DefaultMaxInputSize`) to prevent resource exhaustion

### Supported Encodings

opnDossier handles multiple character encodings:

- UTF-8 (default)
- US-ASCII
- ISO-8859-1 (Latin1)
- Windows-1252

## Error Output Examples

### Parse Error Example

When XML syntax errors are encountered:

```text
failed to parse XML from config.xml: XML syntax error on line 42
```

### Missing Root Element

```text
invalid XML: missing opnsense root element
```

## Using the Validate Command

```bash
# Validate a configuration file
opndossier validate config.xml

# Validate with verbose output
opndossier --verbose validate config.xml

# Validate multiple files
opndossier validate config1.xml config2.xml config3.xml
```

The `validate` command returns exit code 0 on success and a non-zero exit code on failure.

## Error Handling in Scripts

```bash
#!/bin/bash
set -e

# Validate before processing
if opndossier validate config.xml; then
    echo "Configuration is valid"
    opndossier convert config.xml -o output.md
else
    echo "Configuration has errors"
    exit 1
fi
```

## JSON Error Output

For programmatic error handling, use JSON output:

```bash
# Get errors in JSON format
opndossier --json-output validate config.xml

# Parse JSON errors with jq
opndossier --json-output validate config.xml 2>&1 | jq '.error'
```

## Parser Security Features

The XML parser implements several security protections:

- **XML bomb protection**: Input size limited to 10MB by default
- **XXE prevention**: External entity expansion disabled via empty entity map
- **Safe charset handling**: Fallback handling for non-UTF-8 encodings

## Best Practices

### Always Validate First

```bash
# Validate before converting (recommended)
opndossier validate config.xml && opndossier convert config.xml -o output.md
```

### Check File Encoding

If you encounter encoding errors:

```bash
# Check file encoding
file config.xml

# Convert encoding if needed
iconv -f UTF-16 -t UTF-8 config.xml > config-utf8.xml
opndossier convert config-utf8.xml
```

### Verbose Debugging

```bash
# Enable verbose output for detailed error context
opndossier --verbose validate config.xml

# Capture debug output to a log file
opndossier --verbose convert config.xml -o output.md 2>debug.log
```

## Related Documentation

- [Security Scoring](../user-guide/security-scoring.md)
- [Configuration Guide](../user-guide/configuration.md)
- [Troubleshooting](../examples/troubleshooting.md)
