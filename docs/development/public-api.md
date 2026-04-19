# Public Go API Surface

opnDossier ships as both a CLI binary and a reusable Go library. This document defines which packages under `pkg/` are part of the public API, what stability guarantees apply, and what constitutes a breaking change.

See [README.md § Using as a Go Library](https://github.com/EvilBit-Labs/opnDossier/blob/main/README.md#using-as-a-go-library) for import examples and the quick-start consumer flow.

## Current Regime

This policy takes effect starting with v1.5. Releases prior to v1.5 made no public-API semver commitment on `pkg/` shape. For v1.4 and earlier, treat `pkg/` as subject to change between any two releases.

## Package Classification

The module path is `github.com/EvilBit-Labs/opnDossier`.

### Public API (stability-tracked)

These packages are intended for direct consumption by other Go modules. Their exported identifiers follow the stability rules in the next section.

| Import path           | Purpose                                                                                                                                                                                                                       |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pkg/model`           | Platform-agnostic `CommonDevice` domain model plus `ConversionWarning`, `Severity`, `DeviceType`, and the subsystem structs reachable from `CommonDevice` (firewall rules, NAT, DHCP, VPN, certificates, etc.).               |
| `pkg/parser`          | Factory, `OPNsenseXMLDecoder` interface, `DeviceParser` interface, and the `DeviceParserRegistry` used for device-type dispatch. Includes `NewSecureXMLDecoder` and `CharsetReader` for consumers wiring their own XML layer. |
| `pkg/parser/opnsense` | OPNsense-specific `Parser`, `ConvertDocument(*schema.OpnSenseDocument)`, and `ErrNilDocument`. Self-registers with the global registry on blank import.                                                                       |
| `pkg/parser/pfsense`  | pfSense equivalent. Same shape, same self-registration.                                                                                                                                                                       |

#### Idiomatic consumer entry point

`opnsense.ConvertDocument(*schema.OpnSenseDocument)` and `pfsense.ConvertDocument(*pfsense.Document)` are the **idiomatic, primary** public-API entry points for Go consumers that already have a parsed vendor DTO. Parse the XML once (with `encoding/xml`, `parser.NewSecureXMLDecoder`, or your own decoder), then call `ConvertDocument` as many times as you need. No blank imports required — the caller references the concrete package directly, so the registry is not involved.

`parser.Factory.CreateDevice(ctx, reader, deviceTypeOverride, validateMode)` is the **auto-detection escape hatch** — the path you use when you have a `reader` but no pre-parsed DTO. The factory peeks the XML root element, dispatches to the registered parser for that device type, and returns a converted `CommonDevice`. `Factory` is stable and covered by the same semver commitments as the rest of `pkg/parser`, but consumers should treat it as a convenience wrapper over `ConvertDocument` rather than the canonical entry point. Auto-detection requires blank imports of the device parser packages so their `init()` functions can self-register (see [Registration Contract](#registration-contract-blank-imports)).

##### Error-semantics difference

The two paths surface different errors for related failure modes:

| Condition                              | `Factory.CreateDevice` error                                                                                                                              | `ConvertDocument` error                                                                                  |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Unrecognized XML root element          | `"unsupported device type: root element <X> is not recognized; supported: ..."` (plus the `"ensure parser packages ..."` hint when the registry is empty) | N/A — `ConvertDocument` is typed to a specific DTO and never sees the raw XML root.                      |
| Caller supplied a nil DTO              | N/A — `Factory` always parses its own DTO from the reader.                                                                                                | `ErrNilDocument` wrapped via `fmt.Errorf("ToCommonDevice: %w", ErrNilDocument)`. Check with `errors.Is`. |
| XML decode / validation failure        | Wrapped decode or validation error from the injected `OPNsenseXMLDecoder` (or the pfSense internal decoder) with element-path context.                    | N/A — `ConvertDocument` receives a pre-parsed DTO; the caller owns decode errors.                        |
| Schema or DTO content fails conversion | Same conversion-warning + error path as `ConvertDocument` (the factory delegates after parsing).                                                          | Conversion errors surfaced directly from the converter.                                                  |

Consumers that already have a DTO in hand should call `ConvertDocument` and handle `errors.Is(err, ErrNilDocument)` explicitly. Consumers that receive raw XML from a reader should call `Factory.CreateDevice` and handle the `"unsupported device type"` and `"ensure parser packages are imported"` strings.

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

### Pre-v1.0.0

Until the first tagged `v1.0.0` release, the public API is considered beta. Minor versions (`v0.X.0`) may contain breaking changes. We still try hard not to break consumers within a single minor line — in practice, breaking changes are batched into minor bumps with migration notes in `CHANGELOG.md` — but the semver contract is not yet formal.

Pin a specific version in your `go.mod` and read release notes before upgrading.

### Post-v1.0.0

Once `v1.0.0` is tagged, the public API follows [semantic versioning](https://semver.org):

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

## API Shape Enforcement

The stability commitments above are enforced by two mechanisms in addition to human review:

### Compile-time interface assertions

`pkg/parser/api_shape_test.go` contains `var _ Interface = (*Impl)(nil)` assertions for every public interface / concrete-type pair in `pkg/parser`, `pkg/parser/opnsense`, and `pkg/parser/pfsense`. Removing a method from an interface, or changing a method signature on a concrete type so it no longer satisfies the interface, breaks the build immediately — before any test runs. Extend this file whenever a new public implementation / interface pair lands.

### API snapshot tests (goldie)

`pkg/parser/api_snapshot_test.go` captures the full `go doc -all` output of each public package into a golden fixture under `pkg/parser/testdata/api-snapshots/`:

- `pkg-parser.golden` — `go doc -all ./pkg/parser`
- `pkg-parser-opnsense.golden` — `go doc -all ./pkg/parser/opnsense`
- `pkg-parser-pfsense.golden` — `go doc -all ./pkg/parser/pfsense`
- `pkg-model.golden` — `go doc -all ./pkg/model`

Any accidental change to the public surface — a renamed type, a new exported method, a rewritten doc comment, a deleted constant — shows up as a diff in one of these fixtures during code review. **This is the authoritative baseline for v1.5 and forward.**

When an intentional API change lands, regenerate the fixtures:

```bash
go test ./pkg/parser/... -run TestPublicAPISnapshot -update
```

Then review the diff carefully — everything new in the snapshot becomes a stability commitment. The release checklist in [RELEASING.md](https://github.com/EvilBit-Labs/opnDossier/blob/main/RELEASING.md) requires a snapshot diff review before any tag is pushed.

Packages outside `pkg/` (everything under `cmd/` and `internal/`) are not snapshot-tracked; they can change without regeneration.

## Revision History

| Date       | Change                                                                                                                                                                                |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-04-18 | Initial publication as part of NATS-146 (cross-repo integration verification). Establishes the public API classification, stability policy, and blank-import contract.                |
| 2026-04-19 | Add "Current Regime" section (v1.5 as the first semver-committed release), inline the secret-bearing field inventory, and document the OpenVPN TLS drop invariant.                    |
| 2026-04-19 | Rename `pkg/parser.XMLDecoder` to `pkg/parser.OPNsenseXMLDecoder` (breaking within the v1.5 free-change window) to reflect that the interface is bound to `*schema.OpnSenseDocument`. |
| 2026-04-19 | Rename `CommonDevice.ComplianceChecks` -> `ComplianceResults` (field + JSON tag); see CHANGELOG.                                                                                      |
| 2026-04-19 | Declare `ConvertDocument` the idiomatic consumer entry point and `Factory.CreateDevice` the auto-detection escape hatch; document error-semantics difference between the two paths.   |
| 2026-04-19 | Add API shape enforcement section — `var _ Interface = (*Impl)(nil)` compile-time assertions plus `go doc -all` goldie snapshot tests capturing the v1.5 public-API baseline.         |

Every change to this document must add a row to the Revision History table with date (YYYY-MM-DD) and a one-line description.
