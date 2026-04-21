# display

The `display` command renders an OPNsense configuration directly in your terminal with syntax highlighting and styled formatting. Unlike `convert`, it does not write to a file -- it is designed for quick, interactive review.

**When to use it:**

- Quickly reviewing a config backup without opening a separate viewer
- Spot-checking a specific section (e.g., firewall rules or interfaces) during troubleshooting
- Verifying what a config contains before running a full conversion or audit
- Reviewing configs over SSH where you cannot easily open generated files

## Usage

```text
opndossier display [flags] <config.xml>
```

## Flags

| Flag                 | Short | Default        | Description                                                                                                |
| -------------------- | ----- | -------------- | ---------------------------------------------------------------------------------------------------------- |
| `--theme`            |       | `auto`         | Terminal color theme: `auto`, `dark`, `light`, `none`                                                      |
| `--section`          |       | all            | Comma-separated list of sections to include: `system`, `network`, `firewall`, `services`, `security`       |
| `--wrap`             |       | terminal width | Set text wrap width in columns                                                                             |
| `--no-wrap`          |       | `false`        | Disable text wrapping                                                                                      |
| `--comprehensive`    |       | `false`        | Generate detailed comprehensive report -- see [convert: Comprehensive Mode](convert.md#comprehensive-mode) |
| `--include-tunables` |       | `false`        | Include system tunables (sysctl) in output -- see [convert: System Tunables](convert.md#system-tunables)   |
| `--redact`           |       | `false`        | Redact sensitive fields -- see [convert: Redacting Sensitive Data](convert.md#redacting-sensitive-data)    |

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).

## Themes

The `--theme` flag controls the color palette used for terminal rendering. Themes are powered by [Glamour](https://github.com/charmbracelet/glamour), Charmbracelet's markdown rendering library.

| Theme   | Behavior                                                                                                                                                            |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auto`  | Detects your terminal's background color and selects light or dark automatically. This is the default.                                                              |
| `dark`  | Light text on dark backgrounds. Use this if auto-detection picks the wrong theme or you prefer to set it explicitly.                                                |
| `light` | Dark text on light backgrounds. Best for terminals with white or light-colored backgrounds.                                                                         |
| `none`  | Disables themed styling. Output is still formatted as Markdown but rendered without color. Useful for piping to other tools or terminals that do not support color. |

```bash
# Force dark theme
opndossier display --theme dark config.xml

# Disable colors entirely
opndossier display --theme none config.xml
```

![Screenshot of opnDossier display command showing glamour-rendered terminal output with system and network configuration](../../images/display.png)

## Examples

```bash
# Display configuration with default theme
opndossier display config.xml

# Display with dark theme and redacted secrets
opndossier display --theme dark --redact config.xml

# Display only system and network sections
opndossier display --section system,network config.xml
```

## Related

- [CLI Reference — `display`](../../cli/opnDossier_display.md) -- auto-generated exhaustive flag list
- [convert](convert.md) -- write output to file instead of terminal
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
