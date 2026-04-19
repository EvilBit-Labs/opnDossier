# Public Go API Surface

opnDossier ships as both a CLI binary and a reusable Go library. This document defines which packages under `pkg/` are part of the public API, what stability guarantees apply, and what constitutes a breaking change.

See [README.md § Using as a Go Library](https://github.com/EvilBit-Labs/opnDossier/blob/main/README.md#using-as-a-go-library) for import examples and the quick-start consumer flow.

## Current Regime

This policy takes effect starting with v1.5. Releases prior to v1.5 (including the v1.0–v1.4 line) made no public-API semver commitment on `pkg/` shape; treat those versions as subject to change between any two releases. The "Post-v1.0.0" semver rules below describe what v1.5+ guarantees going forward, not retroactive coverage.

## Package Classification

The module path is `github.com/EvilBit-Labs/opnDossier`.

### Public API (stability-tracked)

These packages are intended for direct consumption by other Go modules. Their exported identifiers follow the stability rules in the next section.

| Import path           | Purpose                                                                                                                                                                                                               |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pkg/model`           | Platform-agnostic `CommonDevice` domain model plus `ConversionWarning`, `Severity`, `DeviceType`, and the subsystem structs reachable from `CommonDevice` (firewall rules, NAT, DHCP, VPN, certificates, etc.).       |
| `pkg/parser`          | Factory, `XMLDecoder` interface, `DeviceParser` interface, and the `DeviceParserRegistry` used for device-type dispatch. Includes `NewSecureXMLDecoder` and `CharsetReader` for consumers wiring their own XML layer. |
| `pkg/parser/opnsense` | OPNsense-specific `Parser`, `ConvertDocument(*schema.OpnSenseDocument)`, and `ErrNilDocument`. Self-registers with the global registry on blank import.                                                               |
| `pkg/parser/pfsense`  | pfSense equivalent. Same shape, same self-registration.                                                                                                                                                               |

### Public but vendor-tracking

These packages expose XML data transfer objects that mirror OPNsense and pfSense on-disk formats. They are importable and useful — for example, config generators or schema-aware tooling need the exact XML shape — but they track the upstream firewall schema, so field changes follow OPNsense/pfSense releases rather than opnDossier's own cadence.

| Import path           | Purpose                                                                               |
| --------------------- | ------------------------------------------------------------------------------------- |
| `pkg/schema/opnsense` | `OpnSenseDocument` and nested XML DTOs for OPNsense `config.xml`.                     |
| `pkg/schema/pfsense`  | Equivalent for pfSense `config.xml`.                                                  |
| `pkg/schema/shared`   | Cross-platform helper types (`FlexBool`, `FlexInt`, DHCP and Unbound shared structs). |

Analyzers and auditors should prefer `pkg/model.CommonDevice` — it is stable across firewall schema drift. Generators, linters, and tooling that must emit or inspect exact XML structure should use `pkg/schema/*` directly and accept that the shape follows the vendor.

### Not public API

Everything under `cmd/` and `internal/` is implementation detail. This includes `internal/cfgparser`, `internal/converter`, `internal/sanitizer`, `internal/validator`, `internal/diff`, and all compliance plugins. These can change or disappear without notice, and Go's `internal/` enforcement prevents direct import regardless.

## Stability Policy

### Pre-v1.5.0

Until `v1.5.0`, the public API is considered beta and was not semver-committed. The v1.0–v1.4 line shipped `pkg/` types but made no cross-release stability guarantee; breaking changes could appear in any minor bump. In practice, breaking changes were batched with migration notes in `CHANGELOG.md`, but the semver contract was not formal.

Pin a specific version in your `go.mod` and read release notes before upgrading to or within the v1.0–v1.4 range.

### Post-v1.5.0

Starting with `v1.5.0` (when this policy took effect), the public API follows [semantic versioning](https://semver.org):

- **Patch** (`v1.2.X`): bug fixes and internal changes. No public API changes.
- **Minor** (`v1.X.0`): new exported symbols, new fields on existing structs, new `Severity` constants, new device types in the parser registry. Existing consumers must continue to compile and behave correctly.
- **Major** (`v2.0.0`): breaking changes, batched and documented in `CHANGELOG.md` with a migration guide.

### What counts as a breaking change

Within the public API packages, these changes require a major version bump:

- Removing or renaming an exported type, function, method, field, constant, or variable.
- Changing the signature of an exported function or method (adding a parameter, changing a return type, reordering arguments).
- Changing the type of an exported field.
- Changing the semantics of an existing function so that correct callers would now misbehave.
- Changing the value of an exported constant that callers might compare against (e.g., renaming `SeverityHigh = "high"` to `"HIGH"`).
- Tightening an interface by adding a method (existing implementations would no longer satisfy it).

These changes are **not** breaking and may appear in minor releases:

- Adding a new exported type, function, method, or constant.
- Adding a new field to a struct (consumers using struct literals without field names will break, but that is their bug — we never promise positional struct literal stability).
- Adding a new `Severity` constant. Consumers that `switch` on severity without a `default` clause should add one.
- Adding a new device type to the parser registry.
- Adding new fields to `ConversionWarning`.
- Widening an accepted input set (e.g., parsing previously-rejected XML).

### CommonDevice specifically

`pkg/model.CommonDevice` is the primary consumer contract. We commit to:

- Never removing a top-level field without a deprecation cycle spanning at least one minor release.
- Keeping `DeviceType`, `Severity`, and the exported `ConversionWarning` shape stable across minor releases.
- Adding new fields in minor releases when we grow support for additional device subsystems. Consumers should not assume the struct is closed.

Fields may be populated more completely over time — for example, a subsystem that currently emits empty slices may begin emitting data as new converter work lands. This is not a breaking change.

### ConversionWarning

`ConversionWarning` is append-only. New severities may be added in minor releases. The `Field`, `Value`, `Message`, and `Severity` fields will not be removed or repurposed. Warning text is not part of the contract — log it, do not match on it.

## Registration Contract (blank imports)

`pkg/parser.Factory.CreateDevice` dispatches through the global `DeviceParserRegistry`. Device parsers self-register from their `init()` function, which Go only runs when the package is imported. Consumers that want auto-detection through the factory must add blank imports:

```go
import (
    "github.com/EvilBit-Labs/opnDossier/pkg/parser"

    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // registers "opnsense"
    _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"  // registers "pfsense"
)
```

When the registry is empty, `Factory.CreateDevice` returns an error whose text contains the substring `"ensure parser packages are imported"`. That substring is covered by a regression test and is safe for tooling to match on. The full wording may change — the hint substring will not.

Consumers who bypass the factory and call `pkg/parser/opnsense.ConvertDocument` or `pkg/parser/pfsense.ConvertDocument` directly do not need the blank import, because they reference the package by name.

## CLI-Only Dependency Isolation

`pkg/` packages must not import CLI-only dependencies. As of this writing, that means no transitive dependency on:

- `github.com/spf13/cobra` and `github.com/spf13/viper`
- `github.com/charmbracelet/glamour`, `bubbletea`, `bubbles`, `lipgloss`
- `github.com/alecthomas/chroma`
- `github.com/olekukonko/tablewriter`
- `github.com/muesli/reflow`

Any PR that introduces a CLI-only import into a public `pkg/` package is a breaking change against the consumer contract — it will pull those deps into every downstream `go.sum`. Reviewers should reject such changes.

opnConfigGenerator maintains a `TestConsumerDependencyIsolation` test that runs `go list -deps` and fails if any of the packages above leak. If that test breaks after an opnDossier upgrade, the leak is in `pkg/`, not in the consumer.

## Handling Secrets in CommonDevice

`CommonDevice` carries plaintext secrets (certificate private keys, pre-shared keys, API tokens, SNMP community strings, HA sync passwords, DHCPv6 key material). opnDossier does not export a public redaction helper in `pkg/` — the sanitizer and export-redaction code paths live in `internal/` and are wired through the CLI.

Consumers who serialize `CommonDevice` to JSON, YAML, or any other format must redact these fields themselves. See the README § [Handling Secrets](https://github.com/EvilBit-Labs/opnDossier/blob/main/README.md#handling-secrets-when-exporting-commondevice) for recommended patterns (subprocess invocation, in-place redaction, custom `json.Marshaler`).

The secret-bearing fields on `CommonDevice` are:

| Struct                       | Field                            |
| ---------------------------- | -------------------------------- |
| `model.Certificate`          | `PrivateKey`                     |
| `model.CertificateAuthority` | `PrivateKey`                     |
| `model.WireGuardClient`      | `PSK`                            |
| `model.APIKey`               | `Secret`                         |
| `model.HighAvailability`     | `Password`                       |
| `model.SNMPConfig`           | `ROCommunity`                    |
| `model.DHCPAdvancedV6`       | `AdvDHCP6KeyInfoStatementSecret` |

If you add a new secret-bearing field to `CommonDevice`, update this table in the same PR.

Notes on fields that are **not** in this table:

- OpenVPN TLS auth / static-key material (raw XML fields on the OPNsense/pfSense schema types) is dropped by the converter and never appears on `CommonDevice` — it can only leak via the raw-XML sanitize path (see `internal/sanitizer` rules, which the CLI applies). Library consumers that work exclusively with `CommonDevice` cannot accidentally emit OpenVPN TLS key material.
- `model.IPsecConfig.KeyPairs` and `model.IPsecConfig.PreSharedKeys` currently carry UUID references to the OPNsense `Ipsec/KeyPairs` and `Ipsec/PreSharedKey` MVC models, not raw key material. They are intentionally omitted from the table above. If a future OPNsense schema revision ever stores raw key bytes in these fields, they must be added here and to the CLI redaction logic in the same PR.
- pfSense `IPsecPhase1.PreSharedKey` (a scalar raw key on the pfSense XML schema) is intentionally not mapped into `model.IPsecPhase1Tunnel`; see `pkg/parser/pfsense/converter_services.go` and the `TestConverter_IPsecPhase1_PreSharedKeyExclusion` regression test.

## Revision History

| Date       | Change                                                                                                                                                                 |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-04-18 | Initial publication as part of NATS-146 (cross-repo integration verification). Establishes the public API classification, stability policy, and blank-import contract. |
| 2026-04-19 | Add "Current Regime" section (v1.5 as the first semver-committed release), inline the secret-bearing field inventory, and document the OpenVPN TLS drop invariant.     |

Every change to this document must add a row to the Revision History table with date (YYYY-MM-DD) and a one-line description.
