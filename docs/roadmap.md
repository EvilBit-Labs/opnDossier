# opnDossier Product Roadmap

**Last updated:** March 2026

opnDossier is an offline-first firewall configuration analysis tool built for operators who need full control over their security assessments. It parses OPNsense configuration files and produces detailed security reports, compliance findings, and multi-format exports — all without sending a single byte over the network.

**Current version:** v1.2.1

---

## What's Available Today

opnDossier v1.2 ships with:

- **OPNsense configuration parsing** — full XML config analysis including firewall rules, NAT, VPN, DHCP, DNS, routing, VLANs, bridges, and more
- **Security analysis** — dead rule detection, overly permissive rule identification, and best-practice checks
- **Compliance auditing** — built-in Cybersecurity Best Practices, SANS/NSA, and STIG checks
- **Multi-format export** — Markdown, JSON, YAML, plain text, and HTML output
- **Configuration diff** — compare two configs side-by-side to see what changed
- **Data sanitization** — redact sensitive values (IPs, passwords, SNMP communities) for safe sharing
- **Zero telemetry, fully offline** — runs entirely on your machine with no network access required

---

## Coming Soon — v1.3.0

*Architecture cleanup and platform expansion foundation.*

This release focuses on the structural work needed to support multiple firewall platforms and a professional tier. Key improvements:

- **Public Go module API** — `pkg/model` and `pkg/schema/opnsense` become importable packages, enabling third-party integrations and tooling built on top of opnDossier
- **Parser registry** — a plugin-style registration system for firewall parsers, making it straightforward to add new platforms
- **Shared analysis engine** — unified statistics and compliance analysis shared across all output formats
- **Improved audit reliability** — panic recovery around compliance plugin execution, better error surfacing for plugin failures
- **Format registry** — centralized format handling replacing scattered routing logic

---

## Next Up — v1.4.0+

*Performance and quality improvements.*

- **Performance optimizations** — hash-based duplicate rule detection (replacing O(n^2) scans), memoized analysis computation, reduced memory allocations in hot paths
- **Expanded test coverage** — converter, enrichment, and compliance modules
- **Benchmark tooling** — profiling infrastructure for tracking performance across releases

---

## On the Horizon

### Multi-Platform Support

All platform parsers will be free and open source. opnDossier aims to be the universal firewall config parser.

| Platform           | Status          |
| ------------------ | --------------- |
| OPNsense           | Shipped (v1.0+) |
| pfSense            | In development  |
| Cisco ASA/IOS      | Planned         |
| Fortinet FortiGate | Planned         |
| Palo Alto          | Planned         |
| Juniper            | Planned         |
| MikroTik           | Planned         |
| Ubiquiti/UniFi     | Planned         |

### Advanced Analysis

- **Firewall rule shadowing detection** — find rules that are never matched because earlier rules already cover them
- **Unused object detection** — identify address groups, aliases, and other objects that no rule references
- **Configuration drift detection** — define a baseline config and get alerted when things change
- **Structured remediation guidance** — concrete fix-it instructions attached to each finding

### Compliance Expansion

- **CIS Benchmark scanning** — industry-standard compliance checks for OPNsense and pfSense
- **PCI-DSS Requirement 1** — firewall-specific PCI compliance validation
- **NIST 800-53 / NIST CSF** — control mapping for federal and enterprise environments
- **Custom rule engine** — write your own compliance checks for organization-specific policies

### Professional Reporting

- **PDF report generation** — polished, executive-ready compliance and security reports
- **SARIF export** — integrate findings into CI/CD pipelines and code scanning dashboards
- **SIEM integration** — CEF/LEEF/JSONL export for feeding findings into your SIEM

### Distribution and Usability

- **Scoop package manager** — `scoop install opndossier` on Windows
- **Documentation site** — comprehensive guides, CLI reference, and practical examples
- **Config file support** — persistent settings via `~/.opndossier.yaml` and environment variables
- **pfFocus-compatible output** — migration path for pfFocus users

### Longer Term

- **Desktop application** — a native GUI for interactive configuration exploration (built with Wails)
- **Topology mapping** — ingest multiple device configs and visualize your network as Mermaid diagrams, Graphviz DOT, or JSON/YAML graphs
- **Attack path analysis** — trace permitted paths through your network from a given entry point
- **Red/blue team reports** — same analysis, two perspectives: exploitable findings for red teams, remediation priorities for blue teams

---

## opnDossier Pro

The community edition is a complete, production-ready tool — not a limited preview. We're building a Pro tier for users with specialized needs: government compliance requirements, multi-device topology mapping, or workflow-specific report formats. All platform parsers, security analysis, compliance checks, and multi-format export are community features and always will be.

**Professional tier** adds:

- Expanded STIG coverage (full DISA STIG checklist beyond the community baseline controls)
- Topology mapping and attack path analysis
- Red/blue dual-output reports
- Desktop application with local analysis history
- PDF and SARIF export

**Enterprise tier** adds:

- Server deployment with multi-user support
- Persistent topology history and change tracking
- Custom rule authoring
- API access for tool integration
- Compliance cross-reference mapping (PCI-DSS, SOC 2, ISO 27001)

Pricing and availability will be announced when the Pro tier is ready. If you're interested in early access, watch the [GitHub repository](https://github.com/EvilBit-Labs/opnDossier) or visit [evilbitlabs.io](https://evilbitlabs.io) for updates.

---

## How to Get Involved

- **Report issues or request features** — [GitHub Issues](https://github.com/EvilBit-Labs/opnDossier/issues)
- **Star the repo** — helps others discover the project
- **Try it on your config** — feedback from real-world configs is the most valuable input we get

opnDossier is built by [EvilBit Labs](https://evilbitlabs.io). Maintained by operators, for operators.
