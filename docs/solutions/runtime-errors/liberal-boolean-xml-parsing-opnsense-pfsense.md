---
title: Liberal boolean parsing for OPNsense/pfSense config.xml
category: runtime-errors
date: '2026-04-18'
tags:
  - xml-parsing
  - schema
  - boolean-coercion
  - opnsense
  - pfsense
  - boolflag
  - flexbool
  - flexint
  - element-path
  - decode-errors
severity: high
components:
  - pkg/schema/shared/bool.go
  - pkg/schema/shared/flex_bool.go
  - pkg/schema/shared/flex_int.go
  - pkg/schema/opnsense/common.go
  - pkg/schema/opnsense/system.go
  - pkg/schema/pfsense/system.go
  - pkg/parser/opnsense/converter.go
  - pkg/parser/pfsense/converter_network.go
  - pkg/parser/pfsense/constants.go
  - pkg/parser/pfsense/parser.go
  - pkg/parser/xmlutil.go
  - internal/cfgparser/xml.go
related_issues:
  - 558
related_docs:
  - docs/solutions/logic-errors/cli-flag-wiring-silent-ignore.md
  - docs/solutions/architecture-issues/pluggable-deviceparser-registry-pattern.md
  - docs/solutions/architecture-issues/pkg-internal-import-boundary.md
  - docs/plans/2026-04-18-002-fix-issue-558-parser-on-value.md
  - https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md#15-liberal-boolean-and-integer-parsing
---

# Liberal Boolean Parsing for OPNsense/pfSense config.xml

## Problem

`opndossier audit <config.xml>` crashed on an OPNsense 26.1 `config.xml` with:

```
opnsense parser: strconv.ParseInt: parsing "on": invalid syntax
```

Reported in [#558](https://github.com/EvilBit-Labs/opnDossier/issues/558). Root cause: several schema fields that semantically represent boolean toggles were typed as Go `int`, but OPNsense and pfSense both emit any of `1|on|yes|true|enable|enabled` for a truthy toggle. `encoding/xml` dispatches `int` fields to `strconv.ParseInt`, which fails fast on non-numeric input and aborts the whole parse with no element path — the user sees only `strconv.ParseInt: parsing "on"` and can't locate the field.

## Symptoms

- Opaque `strconv.ParseInt: parsing "on"` error surfaced to the CLI with no element path to identify the offending field.
- 10 OPNsense `System` fields (`DNSAllowOverride`, `UseVirtualTerminal`, `DisableVLANHWFilter`, `DisableChecksumOffloading`, `DisableSegmentationOffloading`, `DisableLargeReceiveOffloading`, `PfShareForward`, `LbUseSticky`, `RrdBackup`, `NetflowBackup`) and 3 pfSense `System` fields (`DNSAllowOverride`, `DisableSegmentationOffloading`, `DisableLargeReceiveOffloading`) were declared `int` despite being boolean toggles.
- Truthy parsing was duplicated and inconsistent across the codebase:
  - `pfsense.isPfSenseValueTrue` accepted `1|on|yes` only (session history).
  - `internal/converter/formatters/IsTruthy` accepted a broader set at the formatter layer.
  - OPNsense converter sites used `strings.EqualFold(x, xmlBoolYes)` where `xmlBoolYes = "yes"` — rejecting `on`/`1`/`true`/`enabled`.
- Latent bug: `opnsense.BoolFlag.UnmarshalXML` set `true` on any element presence regardless of body — so `<tag>0</tag>` incorrectly decoded to `true`. Predated #558 but only surfaced under the new BoolFlag delegation path.

## What Didn't Work

- **Escape-hatch `FlexInt` on the toggle fields.** First draft introduced a liberal int that coerced truthy strings to `1`. Abandoned — the fields were never semantically int. `FlexInt` still ships as a sibling type for fields that genuinely need int semantics (none in this change; reserved for future hot-fixes), but it is the wrong tool for schema fields whose intent is boolean.
- **Collapsing `BoolFlag` and `FlexBool` into one type.** Rejected: `BoolFlag` is presence-based (absent → false, `<tag/>` → true), `FlexBool` is always-value-based (element always emitted, body carries the signal). Merging would force every consumer to express intent inline and push call-site decisions that the type system was meant to encode.
- **`FlexBool.UnmarshalJSON` with hand-stripped quotes.** First pass extracted the string value by stripping surrounding `"` bytes, then calling `IsValueTrue`. Review caught this silently drops JSON escape sequences — `"\u006fn"` (legal JSON for "on") compared literally and returned false. Rewrote to cascade `json.Unmarshal` through native `bool` → native `int` → `string`, so escapes are decoded before the truthy check.
- **An intermediate pfSense decode layer** was already tried in PR #461 (March 2026) for a related presence-based bug (`<enable/>` on pfSense interfaces) — a `decodeDocument` type that converted between `pfsense.*` and `opnsense.*` mid-decode. That approach was rejected in favor of a clean fork. The #558 fix follows the same architectural direction: one shared helper package, native schema types, no shadow decode layer. (session history)

## Solution

### 1. Canonical truthy parser in `pkg/schema/shared/`

```go
// pkg/schema/shared/bool.go
package shared

import "strings"

func IsValueTrue(s string) bool {
    switch strings.ToLower(strings.TrimSpace(s)) {
    case "1", "on", "yes", "true", "enable", "enabled":
        return true
    }
    return false
}

func IsValueFalse(s string) bool {
    switch strings.ToLower(strings.TrimSpace(s)) {
    case "0", "off", "no", "false", "disable", "disabled", "":
        return true
    }
    return false
}
```

Both opnsense and pfSense converter code consumes this. No device-specific truthy parser remains.

### 2. `FlexBool` — value-level liberal bool

`shared.FlexBool` is a `type FlexBool bool` with XML/JSON/YAML `Marshal`/`Unmarshal`. Use it when the element is always emitted and the body carries the signal. Marshals as `1`/`0` for canonical output. JSON/YAML round-trip as native booleans. The `UnmarshalJSON` cascade delegates string decoding to `encoding/json` so escape sequences are decoded before comparison.

### 3. `FlexInt` — liberal int sibling

Same vocabulary, keeps int semantics. Unknown non-numeric input returns a wrapped error (stricter than FlexBool, which maps unknown → false). No field migrates to it in this change; reserved for future hot-fixes where the field must stay int-typed but may receive truthy strings.

### 4. Upgraded `BoolFlag.UnmarshalXML`

The latent "any presence → true" bug is fixed. Before/after:

```go
// Before: element presence always set true — <tag>0</tag> wrongly decoded to true.
func (bf *BoolFlag) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
    *bf = true
    var content string
    return d.DecodeElement(&content, &start)
}

// After: absent → false (UnmarshalXML not called), <tag/> → true,
// <tag>body</tag> → IsValueTrue(body). Marshal side unchanged to preserve
// GOTCHAS §15.1 pointer-receiver invariants.
func (bf *BoolFlag) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
    var content string
    if err := d.DecodeElement(&content, &start); err != nil {
        return err
    }
    if strings.TrimSpace(content) == "" {
        *bf = true
        return nil
    }
    *bf = BoolFlag(shared.IsValueTrue(content))
    return nil
}
```

### 5. Field migrations

- OPNsense `System`: 10 fields `int` → `BoolFlag` (enumerated above).
- pfSense `System`: 3 fields `int` → `BoolFlag`.
- `pfsense.isPfSenseValueTrue` deleted; call sites (`converter_network.go` for `BlockPriv`, `BlockBogons`, `FarGW`) moved to `shared.IsValueTrue`.
- `pkg/parser/opnsense/converter.go`: both `DisableNATReflection` call sites replaced `strings.EqualFold(x, xmlBoolYes)` with `shared.IsValueTrue(x)`.

Consumers read `bool(field)` or `field.Bool()` instead of `== 1`.

### 6. Universal element-path error annotation

New helper in `pkg/parser/xmlutil.go`:

```go
func WrapDecodeError(err error, elementPath string) error {
    if err == nil {
        return nil
    }
    return fmt.Errorf("field %q: %w", elementPath, err)
}
```

Wired into:

- `internal/cfgparser/xml.go` (`decodeElement` / `decodeSection`) — annotates with `/opnsense/<section>` so the user sees `field "/opnsense/system": strconv.ParseInt: parsing "banana"` when a numeric field gets a malformed body.
- `pkg/parser/pfsense/parser.go` (`decode`) — annotates with `/pfsense`. Single-pass decode architecture limits depth to the root; tracked in todo 099 for deeper refactor.

## Why This Works

- **Root cause addressed at the type level.** The offending fields are now typed as what they semantically are (`BoolFlag`), so `encoding/xml` dispatches to the liberal unmarshaler instead of `strconv.ParseInt`. Changing `pkg/schema/opnsense` types is safe because `common.CommonDevice` (pkg/model) is the documented public surface per the NATS-144 audit (commit `33ccf82`) — raw schema types can change without semver break.
- **Single canonical truthy vocabulary.** OPNsense and pfSense share the same liberal encoding (`1|on|yes|true|enable|enabled` case-insensitive). Replacing three divergent parsers with one `shared.IsValueTrue` eliminates the possibility that one site accepts `on` and another rejects it.
- **Pointer-receiver addressability invariant preserved.** `BoolFlag.MarshalXML` stays on the pointer receiver; only `UnmarshalXML` changed. pfSense forks that embed migrated fields continue to follow GOTCHAS §15.1 (`interfaceAlias` + pointer-receiver `MarshalXML` on the parent struct) so value-marshaled parent structs still emit `<enable/>` rather than `<enable>true</enable>`.
- **Failure diagnostics locatable.** When a decode still fails (non-numeric in a genuinely int field like `NextUID`), `WrapDecodeError` pins the element path. Reporters on future schema/config mismatches can share the exact offending element without having to reproduce on our side.

## Prevention

### Converter-site rule

Never write `strings.EqualFold(x, "yes")`, `x == "1"`, or any ad-hoc truthy parser for XML toggle values. Use `shared.IsValueTrue` / `shared.IsValueFalse`. Grep for new `EqualFold` checks against `"yes"|"on"|"enabled"|"1"` during review.

### Type-choice rubric

Four boolean/int-like styles coexist in the schema layer. Pick by the rubric (see GOTCHAS §15.0 for the full table):

| Type                  | Semantics               | Use when                                                                                               |
| --------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------ |
| `opnsense.BoolFlag`   | presence + liberal body | Absence = false is correct in OPNsense/pfSense semantics; marshal may drop `false` to element absence. |
| `shared.FlexBool`     | always-value-based      | Element is always emitted, body carries the signal. Marshals as `1`/`0` every time.                    |
| `shared.FlexInt`      | liberal int             | Field must stay int but may receive truthy strings; unknown → error (strict).                          |
| strict `bool` / `int` | canonical only          | Schema guarantees numeric/native values (rare for device exports).                                     |

**`BoolFlag` is NOT a drop-in for every value-based boolean.** Because `MarshalXML` emits nothing when false, a field whose on-wire form must always be `<tag>0</tag>` or `<tag>1</tag>` cannot migrate to `BoolFlag` — the `false` case would disappear. Criteria for safe migration:

1. Absence of the element must be semantically equivalent to `false` in the device's behavior.
2. No round-trip consumer must depend on the literal `<tag>0</tag>` form when false.

If either fails, prefer `FlexBool` or keep as `string` + `IsValueTrue` at the converter.

### Element-path annotation

Any new XML decode surface (new device parser, new section decoder) must wrap errors through `parser.WrapDecodeError(err, "/<root>/<section>")`. Future reporters will hand you back the exact field that failed.

### Testing requirements for new schema types

Exercise both marshal and unmarshal, including value-marshaled parent structs (per GOTCHAS §15.1 — pointer-receiver methods are invisible when a parent is encoded by value). Cover:

- `<tag/>` self-closing → true (for BoolFlag)
- `<tag>0</tag>`, `<tag>on</tag>`, `<tag>enabled</tag>` explicit bodies
- Absent element → false
- Unknown body → false (BoolFlag, FlexBool) or error (FlexInt)
- JSON/YAML round-trip parity

### Schema-audit trigger

Whenever a bug report shows `strconv.ParseInt`, `strconv.ParseBool`, or `strconv.Atoi` in the parser stack, treat it as a miscategorization signal first. Confirm the field is genuinely numeric/strict before adding an escape hatch. OPNsense/pfSense fields whose PHP source uses `$config[...] == "1"` are booleans in disguise, not integers.

### Receiver conventions for new liberal-parsing types

`FlexBool` and `FlexInt` use pointer receivers for `Marshal*`/`Unmarshal*` (required by the encoding interfaces) and value receivers for accessor methods (`Bool()`, `Int()`) so they work on non-addressable values like `shared.FlexBool(true).Bool()`. `recvcheck` must be suppressed on the **type declaration** (not on the accessor method) with a directive explaining the mixed-receiver convention is intentional. CI will fail otherwise.

## Historical Context (session history)

- **PR #461 (March 2026)** fixed a related presence-based bug where pfSense interfaces with `<enable/>` always reported as disabled because `opnsense.Interface.Enable` was `string` and `isPfSenseValueTrue("")` returned false for both the empty-body case and the missing-element case. The clean-fork architecture adopted there (native `pfsense.*` types, `.Bool()` readers, no shadow decode layer) set the precedent followed by #558.
- **GOTCHAS §15.1 origin** (session `41a2bf64`, March 23, 2026): the `interfaceAlias` + pointer-receiver `MarshalXML` pattern was introduced when `Interfaces.MarshalXML` iterated a map and called `e.EncodeElement(value, ...)` by value, causing `BoolFlag` fields to fall back to default `bool` serialization. The addressability gotcha now extends to `FlexBool` and `FlexInt` too.
- **`BlockPriv` / `BlockBogons` deferred from #461:** both pfSense interface fields were flagged as additional presence-based booleans during #461's review but scoped out. They still use `shared.IsValueTrue` at the converter site rather than `BoolFlag` typing — a follow-up migration opportunity.
- **No prior `shared/` package existed.** The cross-device helper package (`pkg/schema/shared/`) is new. Prior sessions used `opnsense.BoolFlag` directly; there was no cross-cutting primitive.
- **No prior `WrapDecodeError` pattern.** Element-path annotation on XML decode errors is new with this fix.

## Related Work

- [GOTCHAS §15 — Liberal Boolean and Integer Parsing](https://github.com/EvilBit-Labs/opnDossier/blob/main/GOTCHAS.md) — decision rubric and pointer-receiver caveats.
- [PR #577](https://github.com/EvilBit-Labs/opnDossier/pull/577) — this fix.
- [Issue #558](https://github.com/EvilBit-Labs/opnDossier/issues/558) — reporter-filed bug.
- [Plan: 2026-04-18-002-fix-issue-558-parser-on-value.md](../../plans/2026-04-18-002-fix-issue-558-parser-on-value.md) — implementation plan.
- [`cli-flag-wiring-silent-ignore`](../logic-errors/cli-flag-wiring-silent-ignore.md) — related silent-failure class of bug (different root cause, same symptom shape).
- [`pluggable-deviceparser-registry-pattern`](../architecture-issues/pluggable-deviceparser-registry-pattern.md) — parser registry architecture that `WrapDecodeError` lives within.
