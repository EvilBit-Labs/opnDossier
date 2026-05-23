# For AI Agents & Automation

This page is the entry point for **AI agents, LLM-driven tools, and automation pipelines** that invoke `opnDossier` programmatically. Every link below points at a stable, machine-readable interface or a reference doc that is kept in sync with the code via generator (so it does not drift).

If you are a human operator, start with the [User Guide](user-guide/getting-started.md) instead — that path is narrative and assumes you are reading top-to-bottom. This page is optimized for agents that need to jump directly to a flag list, an output schema, or an exit-code table.

## Exhaustive CLI reference (auto-generated)

The CLI reference in [docs/cli/](cli/opnDossier.md) is generated from the Cobra command definitions by `just generate-cli-docs`. Every subcommand, flag, alias, and shell-completion hint is listed; the content is always in sync with the binary because it is regenerated on every build.

- [`opnDossier`](cli/opnDossier.md) — root command, global flags
- [`audit`](cli/opnDossier_audit.md) — security audit and compliance
- [`convert`](cli/opnDossier_convert.md) — render config to markdown/json/yaml/html/text
- [`display`](cli/opnDossier_display.md) — render to terminal
- [`diff`](cli/opnDossier_diff.md) — compare two configs
- [`sanitize`](cli/opnDossier_sanitize.md) — redact sensitive values
- [`validate`](cli/opnDossier_validate.md) — structural + semantic validation
- [`config`](cli/opnDossier_config.md) — manage the opnDossier config file
  - [`config init`](cli/opnDossier_config_init.md)
  - [`config show`](cli/opnDossier_config_show.md)
  - [`config validate`](cli/opnDossier_config_validate.md)
- [`list`](cli/opnDossier_list.md) — enumerate supported capabilities (agent-friendly)
  - [`list plugins`](cli/opnDossier_list_plugins.md)
  - [`list devices`](cli/opnDossier_list_devices.md)
  - [`list formats`](cli/opnDossier_list_formats.md)
- [`man`](cli/opnDossier_man.md) — generate man pages
- [`completion`](cli/opnDossier_completion.md) — shell completion scripts
- [`version`](cli/opnDossier_version.md)

## Capability discovery

Use the `list` subcommand group to enumerate what the running binary supports without parsing `--help` text. Each subcommand emits one name per line by default, or a JSON array of objects with `--json`. Pass the discovered names directly to `--device-type`, `--format`, or `--plugins` on the consuming commands.

| Question                                                | Command                                                                                    |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Which compliance plugins are available?                 | `opnDossier list plugins --json` (add `--plugin-dir DIR` to include dynamic `.so` plugins) |
| Which device parsers can I target with `--device-type`? | `opnDossier list devices --json`                                                           |
| Which output formats can I pass to `--format`?          | `opnDossier list formats --json`                                                           |

JSON shape is stable: `list plugins` returns `[{"name":"stig","description":"...","version":"1.0.0"}]` (plus optional `"status"` and `"loadError"` fields when a dynamic plugin failed to load); `list devices` and `list formats` return `[{"name":"opnsense","description":"..."}]`. Empty registries return `[]` (never `null`) and exit code `0`.

- **`list plugins` without `--plugin-dir` returns only built-in plugins** (`stig`, `sans`, `firewall`). Dynamic `.so` plugins are opt-in to keep the default invocation free of any local-filesystem dependency.
- **Per-plugin dynamic load failures surface as `WARN` lines on stderr** (`plugin=<name> error=<reason>`); the command still exits `0` and the failing plugin is omitted from the returned array. Capture stderr alongside stdout when consuming `list plugins --plugin-dir` if you need full visibility.

## Machine-readable output formats

`convert`, `audit`, and `display` all accept `--format` / `-f`. The structured formats below are the recommended consumers for automated pipelines.

| Format | Flag value        | Content                                             | Example                                                            |
| ------ | ----------------- | --------------------------------------------------- | ------------------------------------------------------------------ |
| JSON   | `json`            | `CommonDevice` serialized with `encoding/json`      | [JSON Export Examples](data-model/examples/json-export.md)         |
| YAML   | `yaml` (or `yml`) | `CommonDevice` serialized with `go.yaml.in/yaml/v3` | [YAML Processing Examples](data-model/examples/yaml-processing.md) |

The `CommonDevice` schema these formats expose is documented in [Model Reference](data-model/model-reference.md) (auto-generated from the Go struct definitions in `pkg/model`).

!!! tip "Structural honesty on unpopulated fields"
    JSON and YAML output include every `CommonDevice` field. When a subsystem is not yet implemented for a given device type (e.g., `KeaDHCP` on pfSense), the field is empty AND a `ConversionWarning` is emitted with a stable message: `"not yet implemented in pfSense converter"`. Agents can filter on this substring instead of guessing why a field is empty. The canonical list of gaps is exposed via `pkg/parser/pfsense.KnownGaps()` and documented in the [Device Support Matrix](user-guide/device-support-matrix.md).

## Public Go API

For programmatic consumers embedding opnDossier as a library (not via the CLI), see [API Reference](development/api.md) and the [Public API Contract](development/public-api.md). Key entry points live in `pkg/parser` and `pkg/model`; the public API is under semver commitment from v1.5 onward.

## Configuration

- [Configuration Reference](user-guide/configuration-reference.md) — every flag, environment variable, and config-file key with types, defaults, and precedence rules
- [`config init`](cli/opnDossier_config_init.md) emits a fully annotated default config that can be used as a starting template

## Exit semantics

- Exit code **0** — success (parse/audit/convert completed with no fatal error)
- Exit code **non-zero** — fatal error; details on stderr
- Non-fatal issues (unrecognized XML elements, missing subsystems, unresolved alias references) are reported as **warnings** on stderr and do not change the exit code
- `audit --mode blue` exits 0 even when compliance checks fail; parse the audit output to detect findings
- `list plugins`, `list devices`, and `list formats` exit **0** regardless of registry size — an empty registry yields `[]` (JSON) or an empty stdout (text) with exit code `0`. Non-zero only on internal errors such as plugin-manager initialization failure for `list plugins --plugin-dir <missing-path>`.

## Device support

- [Device Support Matrix](user-guide/device-support-matrix.md) — OPNsense vs. pfSense coverage per `CommonDevice` subsystem
- `pkg/parser.DeviceType` is a typed string enum; use `DeviceTypeOPNsense` / `DeviceTypePfSense` rather than the raw literals

## Security-sensitive operations

If your pipeline loads third-party compliance plugins via `--plugin-dir`, read [Third-Party Plugin Security](user-guide/commands/audit.md#third-party-plugin-security) first. The loader performs preflight checks (symlink rejection, permission-bit enforcement on POSIX, SHA-256 audit logging) but does not sandbox or verify signatures; plugin loading is Linux/macOS/FreeBSD only and is a clean no-op on Windows.

## Integration with the `action.yaml`

opnDossier ships a GitHub Action at the repo root (`action.yaml`). For CI-driven audit pipelines, the action wraps the CLI and emits structured JSON; see the repo root README for the canonical example.
