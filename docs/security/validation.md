# Validation & Error Handling

opnDossier includes comprehensive validation capabilities to ensure configuration integrity and provide detailed error reporting.

## Validation Features

### Configuration Structure Validation

Validates that all required fields are present and properly structured:

- **System Configuration**: Hostname, domain, timezone
- **Network Interfaces**: IP addresses, subnet masks, gateway assignments
- **Firewall Rules**: Source, destination, port specifications
- **Services**: DNS, DHCP, VPN configuration

### Data Type Validation

Ensures that data values conform to expected types and formats:

- **IP Addresses**: Valid IPv4 and IPv6 addresses
- **Subnet Masks**: Valid CIDR notation and subnet values (0-32 for IPv4, 0-128 for IPv6)
- **Port Numbers**: Valid port ranges (1-65535)
- **Network Configurations**: Gateway reachability, VLAN IDs, MAC addresses

### Cross-Field Validation

Checks relationships and dependencies between configuration elements:

- **Gateway References**: Ensures gateways referenced in rules exist in configuration
- **Interface References**: Validates interface names used in rules and services
- **Alias Resolution**: Verifies aliases are defined before use
- **Service Dependencies**: Checks that services reference valid interfaces and networks

### Streaming Processing

Handles large configuration files efficiently:

- **Memory Efficiency**: Processes large XML files without loading entire document into memory
- **Element Streaming**: Handles configurations with thousands of rules or large sysctl sections
- **Garbage Collection**: Automatic memory cleanup after processing large sections
- **Error Recovery**: Continues processing when possible, collecting all validation errors

## Error Output Examples

### Parse Error Example

When XML syntax errors are encountered:

```text
parse error at line 45, column 12: XML syntax error: expected element name after <
```

### Validation Error Example

Single validation error with context:

```text
validation error at opnsense.system.hostname: hostname is required
validation error at opnsense.interfaces.wan.ipaddr: IP address '300.300.300.300' must be a valid IP address
```

### Aggregated Validation Report

Multiple validation errors collected during processing:

```text
validation failed with 3 errors: hostname is required (and 2 more)
  - opnsense.system.hostname: hostname is required
  - opnsense.system.domain: domain is required
  - opnsense.interfaces.lan.subnet: subnet mask '35' must be a valid subnet mask (0-32)
```

## Streaming Processing Limits

### Memory Management

opnDossier implements streaming processing to handle large configuration files efficiently:

- **Chunk Size**: Processes XML elements in configurable chunks
- **Buffer Management**: Pre-allocated buffers for common operations
- **Memory Limits**: Configurable maximum memory usage
- **Cleanup**: Automatic resource cleanup after each section

### Performance Characteristics

| Configuration Size  | Memory Usage | Processing Time |
| ------------------- | ------------ | --------------- |
| Small (< 1MB)       | < 10MB       | < 1 second      |
| Medium (1-10MB)     | < 50MB       | 1-5 seconds     |
| Large (10-50MB)     | < 200MB      | 5-30 seconds    |
| Very Large (> 50MB) | < 500MB      | 30-120 seconds  |

### Large File Handling

For very large configuration files:

1. **Incremental Processing**: Elements processed as they're read
2. **Partial Results**: Can continue processing after non-fatal errors
3. **Progress Reporting**: Status updates for long-running operations
4. **Resource Monitoring**: Automatic detection of resource constraints

## Validation Error Types

### Required Field Errors

```text
validation error at opnsense.system.hostname: hostname is required
validation error at opnsense.system.domain: domain is required
```

**Resolution**: Ensure all required fields are present in the configuration.

### Data Type Errors

```text
validation error at opnsense.interfaces.wan.ipaddr: IP address '300.300.300.300' is invalid
validation error at opnsense.interfaces.lan.subnet: subnet mask '35' must be between 0-32
validation error at opnsense.firewall.rules[5].dstport: port '99999' must be between 1-65535
```

**Resolution**: Correct the invalid values to match expected types and ranges.

### Reference Errors

```text
validation error at opnsense.firewall.rules[12]: gateway 'WAN_GW' referenced but not defined
validation error at opnsense.firewall.rules[15]: interface 'dmz0' referenced but not configured
validation error at opnsense.firewall.rules[18]: alias 'WebServers' referenced but not defined
```

**Resolution**: Ensure all referenced elements exist in the configuration.

### Structural Errors

```text
validation error at opnsense.interfaces: duplicate interface name 'lan'
validation error at opnsense.firewall.rules: conflicting rules at positions 10 and 15
validation error at opnsense.nat.outbound: missing required interface specification
```

**Resolution**: Fix structural issues in the configuration file.

## Error Handling Modes

### Strict Mode (Default)

- Fails on first validation error
- Returns detailed error message with context
- Prevents processing of invalid configurations

### Lenient Mode

- Collects all validation errors
- Continues processing when possible
- Returns aggregated error report

### Permissive Mode

- Logs validation warnings
- Attempts to process configuration
- Best-effort output generation

## Validation API

### Command-Line Validation

```bash
# Validate configuration file
opnDossier validate config.xml

# Validate with verbose output
opnDossier validate --verbose config.xml

# Validate and show warnings
opnDossier validate --show-warnings config.xml
```

### Programmatic Validation

```go
// Validate during conversion
opnDossier convert --validate config.xml -o output.md

# Convert with lenient validation
opnDossier convert --validation-mode=lenient config.xml

# Skip validation (not recommended)
opnDossier convert --no-validate config.xml
```

## Best Practices

### Regular Validation

1. **Pre-deployment**: Always validate configurations before deployment
2. **Automated Testing**: Include validation in CI/CD pipelines
3. **Version Control**: Validate configurations before committing
4. **Documentation**: Document any validation warnings or exceptions

### Error Resolution Workflow

1. **Identify**: Run validation to collect all errors
2. **Prioritize**: Address critical errors first
3. **Fix**: Correct errors in source configuration
4. **Verify**: Re-run validation to confirm fixes
5. **Document**: Record any permanent exceptions or warnings

### Performance Optimization

For large configurations:

1. **Streaming Mode**: Enable streaming for files > 10MB
2. **Partial Validation**: Validate specific sections when possible
3. **Resource Limits**: Configure memory limits appropriately
4. **Progress Monitoring**: Enable progress reporting for long operations

## Troubleshooting

### Out of Memory Errors

```text
ERROR: out of memory processing configuration file
```

**Solutions**:

- Enable streaming mode: `--streaming`
- Increase memory limit: `--max-memory=1G`
- Process in sections: Validate specific configuration domains

### Timeout Errors

```text
ERROR: validation timeout after 120 seconds
```

**Solutions**:

- Increase timeout: `--timeout=300`
- Enable streaming mode
- Check for infinite recursion in configuration

### XML Parser Errors

```text
ERROR: XML syntax error at line 45, column 12
```

**Solutions**:

- Validate XML syntax with external tool
- Check for special characters requiring escaping
- Ensure proper XML encoding (UTF-8)

## Related Documentation

- [Security Features](../user-guide/security-scoring.md)
- [Configuration Guide](../user-guide/configuration.md)
- [API Reference](../api.md)
- [Examples](../examples.md)
