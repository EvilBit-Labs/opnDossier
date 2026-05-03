---
name: opnDossier
last_updated: 2026-05-03
---

# opnDossier Strategy

## Target problem

Operators of open-source firewalls (OPNsense, pfSense) have no maintained, modern audit tool. The free options that exist are either abandoned or limited to format conversion, and the commercial firewall-audit tools that do exist target enterprise vendor stacks (Cisco, Palo Alto, Fortinet) and don't cover the open-source ecosystem at all. Operators fall back to reading XML by hand or writing ad-hoc grep scripts that never get the long tail of vendor schema quirks right.

## Our approach

Ship a CLI for OPNsense and pfSense operators — Apache 2.0, offline by default, zero telemetry — and lower the bar far enough that the community shapes where it goes next: new platforms, new analyses, new ways of integrating it. The community moat is the bet that the project's value compounds with contributors, not just maintainers. The Go module is a byproduct — available to the community, but the product is the CLI.

## Who it's for

**Primary:** OPNsense and pfSense operators, homelabbers, and small-shop red/blue practitioners running the CLI directly for single-config analysis, sanitization, and best-practice checks — offline, no account, no telemetry.

**Secondary:** Operators of other firewall platforms (Cisco, Fortinet, Juniper, MikroTik, Ubiquiti) who hit the same gap on their own stack and find a contribution path low-friction enough to add their parser.

## Key metrics

- **Distinct platform parsers shipped** — count of `DeviceParser` implementations in mainline. Directly measures whether the universal-platform thesis is moving. Counted per release; floor today is 2 (OPNsense, pfSense).
- **Community feature requests + non-maintainer PRs / quarter** — issues asking for new functionality plus PRs from outside the maintainer team. Signals that people are using the tool deeply enough to want more from it, not just downloading and forgetting. Measured via GitHub.
- **Releases shipped per quarter with green CI** — proxy for "the project is maintained, not just published." Measured via GitHub releases.
- **CLI binary downloads per release** — operator adoption of the product. Measured via GitHub release asset downloads.
- **Open-issue median age** — responsiveness signal; if this trends up while feature requests rise, the contributor on-ramp is failing on the maintainer side. Measured via GitHub Insights.

## Tracks

### Community CLI

The product: single-config analysis, sanitization, best-practice checks (Cybersecurity Best Practices, SANS/NSA), multi-format export (Markdown, JSON, YAML), red/blue audit modes, plugin loading.

_Why it serves the approach:_ This is what operators actually run. Everything else is in service of this surface staying useful and trustworthy.

### Parser engine

`DeviceParser` interface, `CommonDevice` model, OPNsense and pfSense reference implementations, sanitizer, and the schema layer that mirrors vendor XML faithfully. Internal infrastructure that makes adding new platforms tractable.

_Why it serves the approach:_ A CLI that only handles two platforms can't sustain a community moat. The parser engine is what lets contributors ship their own platform without maintainer hand-holding.

### Contributor on-ramp

`CONTRIBUTING.md`, `GOTCHAS.md`, `docs/development/`, `docs/solutions/`, plugin development docs, issue templates. Lowering the bar for any productive community contact — a sharp feature request, a bug report with a real config, a plugin, a new platform parser, an analysis check.

_Why it serves the approach:_ The community moat thesis is only real if outsiders can actually engage — whether by filing or by building — without maintainer hand-holding.

## Not working on

- Real-time monitoring or live device polling — point-in-time analysis of exported configs is a feature, not a limitation.
- Cloud VPC/NSG ingestion — long-term roadmap, not current scope.
- Hosted SaaS, telemetry, phone-home licensing — offline-first is the wedge.
- Topology mapping, compliance framework overlays beyond best practices, red/blue dual-output reports — out of scope for this project.
- A web UI — the CLI is the surface.
- Marketing the Go module as a product — it's available, not promoted.

## Marketing

**One-liner:** Audit your OPNsense and pfSense configs without leaving the room.

**Key message:** opnDossier is a Go-native CLI for auditing OPNsense, pfSense, and the firewall platforms the open-source community actually runs. Apache 2.0, offline by default, zero telemetry. Built so the next platform comes from the community.
