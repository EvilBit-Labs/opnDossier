# config

The `config` command helps you manage opnDossier's own settings -- not your OPNsense configuration. Use it to generate a starter config file, inspect what settings are currently active (and where they come from), or validate that a config file is correct.

**When to use it:**

- Setting up opnDossier for the first time with `config init`
- Debugging unexpected behavior by checking which settings are active and their source with `config show`
- Validating a config file before deploying it to a shared environment or CI pipeline

## Usage

```text
opndossier config <subcommand> [flags]
```

## Subcommands

### show

Display the current effective configuration with source indicators.

| Flag     | Short | Default | Description                         |
| -------- | ----- | ------- | ----------------------------------- |
| `--json` |       | `false` | Output configuration in JSON format |

### init

Generate a template configuration file.

| Flag       | Short | Default              | Description                            |
| ---------- | ----- | -------------------- | -------------------------------------- |
| `--output` |       | `~/.opnDossier.yaml` | Output path for the generated template |

### validate

Validate an existing configuration file for correctness.

```text
opndossier config validate <path>
```

## Examples

```bash
# Show current configuration
opndossier config show

# Show configuration as JSON
opndossier config show --json

# Generate template at a specific path
opndossier config init --output ~/.opnDossier.yaml

# Validate a configuration file
opndossier config validate ~/.opnDossier.yaml
```

## Related

- [Configuration Reference](../configuration-reference.md) -- full configuration file format and options
