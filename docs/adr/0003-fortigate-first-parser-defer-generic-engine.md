# ADR-0003: FortiGate-first parser; defer the generic text-config engine

**Date**: 2026-07-18 **Status**: accepted **Deciders**: unclesp1d3r

## Context

FortiGate is opnDossier's first text-config (non-XML) parser. Auto-detection today is 100% XML-root-element sniffing, and none of the XML hardening (charset detection, XXE guard, size limit) is reusable for text input. The FortiGate ideation floated a generic block-structured text-config engine plus a content-sniffer registry, meant to serve Cisco/Juniper/MikroTik parsers later. There is exactly one text-config consumer today.

## Decision

Build a focused FortiOS parser under `pkg/parser/fortigate/`, self-registered via the pfSense `init()` + blank-import + `parser.Register` template. Do not build a generic text-config engine framework in this slice; extract reusable primitives only when a second text platform actually lands.

## Alternatives Considered

### Alternative 1: Generic text-config engine up front

- **Pros**: matches the STRATEGY bet of making platforms community-contributable; one framework would serve many future vendors.
- **Cons**: designing an abstraction against a single example is speculative generality; the engine's shape is unproven until a second consumer exists.
- **Why not**: YAGNI — an abstraction designed against one example tends to calcify around the wrong seams.

### Alternative 2: Thin seam / narrow interfaces now (no full framework)

- **Pros**: cheap reusable seams (line/block scanner, sniffer hook) without committing to a full engine.
- **Cons**: still guesses seam boundaries with only one consumer to validate them.
- **Why not**: the chosen path already leaves clean extraction points; premature interfaces add cost without a second platform to prove the shape.

## Consequences

### Positive

- Smaller, shippable first slice.
- The existing registration template already makes parsers pluggable without a bespoke engine.
- A later engine extraction is informed by a real second platform, not a guess.

### Negative

- The first parser may bake in FortiOS-isms.
- The generic-engine extraction becomes its own later effort rather than free fallout of this work.

### Risks

- FortiOS-specific coupling could make later extraction harder — mitigate by keeping the tokenizer (line/block scanner) in separate files from the FortiOS-specific mapping, so the reusable layer stays visible before it is extracted.
