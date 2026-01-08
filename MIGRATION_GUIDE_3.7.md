# opnDossier Phase 3.7 Migration Guide

## Overview

Phase 3.7 introduces programmatic generation as the default mode for improved performance, security, and maintainability. Template-based generation remains available through explicit flags for backward compatibility.

## Key Changes

### New Default: Programmatic Mode

- **Before**: Template-based generation was the default
- **After**: Programmatic generation is the default
- **Benefits**: Faster execution, enhanced security, deterministic output

Note: the template engine is Markdown-only - JSON and YAML outputs are always produced programmatically.

### New CLI Flags

- `--engine {programmatic|template}` - Explicit engine selection (highest precedence)
- `--use-template` - Enable built-in template mode
- `--legacy` - Enable legacy template mode (deprecated, shows warning)

### Enhanced Configuration

- `engine: "programmatic"` - Set default engine in config file
- `use_template: true` - Enable template mode in config file

### Environment Variables

All configuration options support environment variables with `OPNDOSSIER_` prefix for CI/offline usage:

#### New Configuration Keys

| Config Key     | Environment Variable      | Type    | Default          | Description                                      |
| -------------- | ------------------------- | ------- | ---------------- | ------------------------------------------------ |
| `engine`       | `OPNDOSSIER_ENGINE`       | string  | `"programmatic"` | Generation engine (`programmatic` or `template`) |
| `use_template` | `OPNDOSSIER_USE_TEMPLATE` | boolean | `false`          | Enable template mode                             |

#### Environment Variable Usage

**String Values:**

```bash
export OPNDOSSIER_ENGINE=template
export OPNDOSSIER_ENGINE="programmatic"
```

**Boolean Values:**

```bash
export OPNDOSSIER_USE_TEMPLATE=true
export OPNDOSSIER_USE_TEMPLATE=false
```

**CI/Offline Examples:**

```bash
# Set engine for CI pipeline
OPNDOSSIER_ENGINE=template opndossier convert config.xml

# Enable template mode in offline environment
OPNDOSSIER_USE_TEMPLATE=true opndossier convert config.xml --comprehensive

# Override multiple settings
OPNDOSSIER_ENGINE=template OPNDOSSIER_USE_TEMPLATE=true opndossier convert config.xml
```

**Precedence Order:**

1. Command-line flags (highest priority)
2. Environment variables (`OPNDOSSIER_*`)
3. Configuration file (`~/.opnDossier.yaml`)
4. Default values (lowest priority)

Environment variables override configuration file settings, making them ideal for CI/CD pipelines and offline deployments where file-based configuration may not be available.

## Migration Examples

### For Existing Template Users

**Old command:**

```bash
./opndossier convert config.xml --comprehensive
```

**New command (to maintain template behavior):**

```bash
./opndossier convert config.xml --use-template --comprehensive
```

### For Custom Template Users

**Old command:**

```bash
./opndossier convert config.xml --custom-template my-template.tmpl
```

**New command (unchanged - automatically enables template mode):**

```bash
./opndossier convert config.xml --custom-template my-template.tmpl
```

### For New Users (Recommended)

**Use default programmatic mode:**

```bash
./opndossier convert config.xml --comprehensive
```

## Flag Precedence Order

1. `--engine` flag (highest priority)
2. `--legacy` flag (deprecated)
3. `--custom-template` flag (automatically enables template mode)
4. `--use-template` flag
5. Configuration file settings
6. Default (programmatic mode)

## Configuration Examples

### Programmatic Mode (Default)

```yaml
# .opnDossier.yaml
engine: programmatic
format: markdown
comprehensive: true
```

### Template Mode

```yaml
# .opnDossier.yaml
engine: template
template: default
```

### Alternative Template Mode

```yaml
# .opnDossier.yaml
use_template: true
template: comprehensive
```

## Security Improvements

### Template Path Validation

- Automatic path traversal protection
- File extension validation
- Security logging for template operations

### Examples of Blocked Paths

```bash
# These will be blocked:
./opndossier convert config.xml --custom-template "../../../etc/passwd"
./opndossier convert config.xml --custom-template "../../sensitive/file"
```

## Performance Comparison

| Mode                   | Performance | Security | Features         |
| ---------------------- | ----------- | -------- | ---------------- |
| Programmatic (default) | 5/5         | 5/5      | Full feature set |
| Template               | 3/5         | 4/5      | Full feature set |

## Testing Your Migration

### Test Default Behavior

```bash
# Should use programmatic mode by default
./opndossier convert config.xml --verbose
# Look for: "Using programmatic engine (default)"
```

### Test Template Override

```bash
# Should use template mode
./opndossier convert config.xml --use-template --verbose
# Look for: "Using template engine (explicit --use-template flag)"
```

### Test Deprecation Warning

```bash
# Should show deprecation warning
./opndossier convert config.xml --legacy --verbose
# Look for: "Legacy mode is deprecated and will be removed in v3.0"
```

## Troubleshooting

### Template Not Found Error

If you see "template not found" errors when using template mode, this is expected behavior when built-in templates are not configured. Use programmatic mode (default) or specify a valid custom template.

### Configuration Validation

```bash
# Test your configuration file
./opndossier --config your-config.yaml convert --help
```

### Verbose Logging

Add `--verbose` to any command to see detailed engine selection logging:

```bash
./opndossier convert config.xml --verbose
```

## Support

For questions about migration:

1. Check the built-in help: `./opndossier convert --help`
2. Review the examples in the help output
3. Use `--verbose` flag to understand engine selection
4. Refer to this migration guide

## Timeline

- **v2.x**: Both modes available, programmatic mode default
- **v3.0**: Legacy flag will be removed
- **v4.0**: Template mode may become optional package
