# validate

The `validate` command checks an OPNsense configuration for structural and semantic correctness. It catches problems early -- malformed XML, missing required fields, invalid values, and cross-field inconsistencies -- so you can fix them before running a conversion or audit. Valid files print a confirmation (e.g., `config.xml: Valid`); invalid files print error details to stderr and exit with a non-zero status.

**When to use it:**

- Verifying a config backup is well-formed before importing or restoring
- Pre-flight check in CI/CD pipelines before generating reports
- Checking multiple configs in bulk to find which ones have issues
- Debugging conversion errors by isolating validation from output generation

## Usage

```text
opndossier validate [flags] <config.xml> [config2.xml ...]
```

## Flags

This command has no command-specific flags.

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).

## Validation Checks

- XML syntax checks
- OPNsense schema validation
- Required field checks
- Cross-field consistency checks

## Examples

```bash
# Validate a single file
opndossier validate config.xml

# Validate multiple files
opndossier validate config1.xml config2.xml config3.xml

# Validate before converting (recommended workflow)
opndossier validate config.xml && opndossier convert config.xml -o output.md
```

## Related

- [convert](convert.md) -- convert after successful validation
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
