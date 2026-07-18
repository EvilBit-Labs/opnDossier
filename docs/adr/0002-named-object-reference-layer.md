# ADR-0002: Named-object reference layer in CommonDevice

**Date**: 2026-07-18 **Status**: accepted **Deciders**: unclesp1d3r

## Context

`CommonDevice` is a pf-family model: firewall rules hold already-resolved inline address and port strings, with no concept of a named object. FortiGate — and Cisco/Palo Alto in the future — are object-oriented: policies reference named address and service objects (and zones) by name rather than inlining values. Adding the FortiGate parser (issue #199, unblocked now that #196 is closed) forces a decision about where those named objects live in the unified model.

## Decision

Add an additive named-object layer to `CommonDevice`: a `NamedObjects` registry plus an `ObjectRef` reference concept. Firewall rules carry both the resolved inline values (always populated) and an optional object reference (left empty for devices with no named-object concept). Object identity is preserved rather than flattened away.

## Alternatives Considered

### Alternative 1: Flatten-and-resolve (no model change)

- **Pros**: zero change to the shared model; existing OPNsense/pfSense audits and exports work unchanged; the FortiGate parser just expands each object into inline strings.
- **Cons**: loses object identity — no unused-object or dangling-reference audit is possible; lower fidelity; every future object-oriented vendor re-solves the same lossy mapping.
- **Why not**: forfeits reference-integrity auditing, which is a headline value of a security audit tool, and pushes the same loss onto Cisco/Palo later.

### Alternative 2: Parser-internal symbol table, flatten on output

- **Pros**: no model change now; the object table (needed for resolution anyway) can be promoted later.
- **Cons**: object identity never reaches audits or exports; promoting it later is a second migration.
- **Why not**: defers the value without avoiding the eventual model change.

## Consequences

### Positive

- Fidelity preserved; object definitions survive into audits and exports.
- Near-free dangling/unused-object detection (Batfish-style referential integrity).
- Benefits every future object-oriented vendor, not just FortiGate.
- Resolved values stay populated, so existing pf-family checks keep firing unmodified.

### Negative

- Touches the shared `CommonDevice` model — wider blast radius across audit, export, builder, diff, and sanitizer consumers.
- More work now than flattening.

### Risks

- Optionality creep (the layer becoming not-truly-optional) could regress pf-family golden files — mitigate by gating on zero regression to existing golden files and keeping `ObjectRef` empty for pf-family devices.
- This supersedes issue #199's Phase-4 mapping table, which assumed model types (`NetworkObject`, `SecurityZone`, `VirtualContext`, `VPNTunnel`, `Identity`) that were never built; the named-object layer is the concrete replacement.
