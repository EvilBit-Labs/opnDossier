# Usage Examples

This section provides comprehensive examples for common workflows and use cases with opnDossier. Each example is designed to be practical and immediately usable.

## Quick Start Examples

### Basic Configuration Conversion

```bash
# Convert OPNsense config to markdown
opnDossier convert config.xml

# Convert to JSON format
opnDossier convert config.xml -f json

# Convert to YAML format
opnDossier convert config.xml -f yaml
```

### Display Configuration in Terminal

```bash
# Display with syntax highlighting
opnDossier display config.xml

# Display with dark theme
opnDossier display --theme dark config.xml

# Display without validation
opnDossier display --no-validate config.xml
```

### Validate Configuration

```bash
# Validate single file
opnDossier validate config.xml

# Validate multiple files
opnDossier validate config1.xml config2.xml config3.xml

# Validate with verbose output
opnDossier --verbose validate config.xml
```

## Common Workflows

### 1. [Basic Documentation](basic-documentation.md)

- Simple configuration conversion
- Output format options
- File management

### 2. [Audit and Compliance](audit-compliance.md)

- Security audit reports
- Compliance checking
- Blue team vs Red team reports

### 3. [Automation and Scripting](automation-scripting.md)

- CI/CD integration
- Batch processing
- Automated documentation

### 4. [Troubleshooting and Debugging](troubleshooting.md)

- Error handling
- Debug techniques
- Common issues

### 5. [Advanced Configuration](advanced-configuration.md)

- Theme customization
- Section filtering
- Performance optimization

## Example Categories

### By Use Case

- **Network Documentation**: Generate readable documentation from OPNsense configs
- **Security Auditing**: Create security-focused audit reports
- **Compliance Checking**: Verify configurations against standards
- **Configuration Analysis**: Analyze and understand complex setups
- **Backup Documentation**: Document configuration backups

### By Output Format

- **Markdown**: Human-readable documentation
- **JSON**: Programmatic access and processing
- **YAML**: Configuration management integration

### By Workflow Type

- **Interactive**: Manual command execution
- **Automated**: Script-based processing
- **CI/CD**: Pipeline integration
- **Batch**: Multiple file processing

## Getting Started

1. **Install opnDossier**: Follow the [installation guide](../user-guide/installation.md)
2. **Get a sample config**: Use one of the sample files in `testdata/`
3. **Try basic conversion**: `opnDossier convert testdata/sample.config.1.xml`
4. **Explore examples**: Browse the examples below for your specific use case

## Sample Files

The project includes sample configuration files for testing:

```bash
# List available sample files
ls testdata/*.xml

# Use a sample file for testing
opnDossier convert testdata/sample.config.1.xml
opnDossier display testdata/sample.config.2.xml
opnDossier validate testdata/sample.config.3.xml
```

## Next Steps

- **New users**: Start with [Basic Documentation](basic-documentation.md)
- **Security professionals**: See [Audit and Compliance](audit-compliance.md)
- **DevOps engineers**: Check [Automation and Scripting](automation-scripting.md)
- **Advanced users**: Explore [Advanced Configuration](advanced-configuration.md)

---

For detailed command reference, see the [Usage Guide](../user-guide/usage.md). For installation instructions, see the [Installation Guide](../user-guide/installation.md).
