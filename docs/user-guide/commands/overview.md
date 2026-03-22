# Commands Overview

opnDossier provides the following commands for working with OPNsense and pfSense configuration files. Commands that parse config.xml auto-detect the device type from the XML root element (`<opnsense>` or `<pfsense>`).

| Command                   | Alias  | Purpose                                                    |
| ------------------------- | ------ | ---------------------------------------------------------- |
| [`audit`](audit.md)       |        | Run security audit and compliance checks on configurations |
| [`convert`](convert.md)   | `conv` | Convert config.xml to structured output formats            |
| [`display`](display.md)   |        | Render config.xml as formatted Markdown in terminal        |
| [`validate`](validate.md) |        | Check config.xml for structural and semantic correctness   |
| [`diff`](diff.md)         |        | Compare two OPNsense configuration files                   |
| [`sanitize`](sanitize.md) |        | Redact sensitive information from config.xml               |
| [`config`](config.md)     |        | Manage opnDossier configuration (init, show, validate)     |
| `version`                 |        | Display version information                                |

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).
