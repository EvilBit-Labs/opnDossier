# diff

The `diff` command compares two OPNsense configurations and shows what changed between them. Unlike a raw text diff, it understands the structure of OPNsense configs -- it groups changes by section, scores their security impact, and can detect rule reordering separately from content changes.

**When to use it:**

- Reviewing what changed between two config backups (before/after a maintenance window)
- Change management auditing -- documenting exactly what was modified and why it matters
- Security review of configuration changes, filtering to only security-relevant differences
- Comparing configs across environments (production vs staging)

## Usage

```text
opndossier diff [flags] <old-config.xml> <new-config.xml>
```

## Flags

| Flag             | Short | Default    | Description                                                      |
| ---------------- | ----- | ---------- | ---------------------------------------------------------------- |
| `--format`       | `-f`  | `terminal` | Output format: `terminal`, `markdown`, `json`, `html`            |
| `--output`       | `-o`  | stdout     | Output file path                                                 |
| `--mode`         | `-m`  | `unified`  | Display mode: `unified`, `side-by-side` (terminal only)          |
| `--section`      | `-s`  | all        | Comma-separated list of sections to compare                      |
| `--security`     |       | `false`    | Show only security-relevant changes                              |
| `--normalize`    |       | `false`    | Normalize values (whitespace, IPs, ports) for cleaner comparison |
| `--detect-order` |       | `false`    | Detect rule reordering without content changes                   |

For global flags (`--verbose`, `--quiet`, `--config`, etc.), see [Configuration Reference](../configuration-reference.md).

## Display Modes

The `--mode` flag controls how changes are presented in terminal output.

| Mode           | Description                                                                                                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unified`      | Shows changes inline with `+` and `-` markers, similar to `git diff`. This is the default and works well in narrow terminals.                                                                     |
| `side-by-side` | Shows old and new values in adjacent columns. Easier to scan when comparing many small changes, but requires a wider terminal. Only applies to terminal output -- other formats ignore this flag. |

```bash
# Side-by-side comparison
opndossier diff -m side-by-side old-config.xml new-config.xml
```

## Security Filtering

Every change detected by `diff` is scored for security impact using pattern-based rules. The `--security` flag filters the output to show only changes that have a security impact, hiding cosmetic or low-risk differences.

This is useful when reviewing a large set of changes and you only care about what affects the security posture -- for example, during a change management review or incident investigation.

```bash
# Show only security-relevant changes
opndossier diff --security old-config.xml new-config.xml
```

### Security Impact Levels

| Level      | Examples                                                                                                                                         |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **HIGH**   | Permissive any-to-any firewall rules, overly broad access                                                                                        |
| **MEDIUM** | Firewall rule removals, user account changes, NAT mode changes, port forwarding modifications, WebGUI protocol changes, interface enable/disable |
| **LOW**    | New firewall rules, DNS server changes, user modifications                                                                                       |

## Normalization

OPNsense configurations can contain cosmetic differences that are not meaningful -- extra whitespace, different IP address formatting, or inconsistent port notation. The `--normalize` flag cleans up these differences before comparing, so the diff only shows changes that actually matter.

When normalization is enabled:

- Whitespace is standardized
- IP addresses are normalized to a canonical form
- Port numbers and ranges are normalized

If two values are identical after normalization, the change is silently skipped.

```bash
# Skip cosmetic differences
opndossier diff --normalize old-config.xml new-config.xml

# Combine with security filtering for a focused review
opndossier diff --security --normalize old-config.xml new-config.xml
```

## Rule Reordering Detection

Firewall rule order matters in OPNsense -- rules are evaluated top to bottom, and the first match wins. The `--detect-order` flag identifies rules that were reordered without any content changes. These are reported separately from added/removed/modified changes so you can see at a glance whether rule precedence shifted.

By default, reordering detection is off because it requires comparing every rule against every other rule, which adds processing time for large rulesets.

```bash
# Detect reordered firewall rules
opndossier diff --detect-order old-config.xml new-config.xml
```

## Available Sections

`system`, `firewall`, `nat`, `interfaces`, `vlans`, `dhcp`, `users`, `routing`

## Examples

```bash
# Compare two configs in terminal
opndossier diff old-config.xml new-config.xml

# Generate markdown diff report
opndossier diff old-config.xml new-config.xml -f markdown -o changes.md

# Compare only firewall and NAT sections
opndossier diff old-config.xml new-config.xml -s firewall,nat

# Show only security-relevant changes with normalization
opndossier diff old-config.xml new-config.xml --security --normalize
```

## Related

- [convert](convert.md) -- generate full documentation from a single config
- [Configuration Reference](../configuration-reference.md) -- global flags and settings
