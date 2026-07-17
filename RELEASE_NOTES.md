# opnDossier v1.6.0 — Capability discovery, SNMPv3 key redaction, and CVE remediation

v1.6.0 adds a machine-readable `list` command group for capability discovery, closes a cleartext SNMPv3 encryption-key leak in the `sanitize` command, and remediates a batch of Go stdlib CVEs. It is a drop-in upgrade from v1.5.0 — no breaking changes and no public Go API changes.

## Highlights

**New `list` command group for capability discovery.** `opndossier list plugins`, `opndossier list devices`, and `opndossier list formats` enumerate what the running binary supports — compliance plugins (built-in, plus dynamic ones when `--plugin-dir` is set), supported device-config parsers, and available output formats. Each subcommand emits one entry per line for shell pipelines and accepts `--json` for structured output, so AI agents and automation can enumerate capabilities without scraping `--help` text. (#623)

```bash
# Plain text (one name per line)
opndossier list formats

# Structured output for automation
opndossier list plugins --json
```

**SNMPv3 encryption keys are now redacted.** `opnDossier sanitize` walks raw XML element names — `<password>` was caught by the generic `pass` match, but `<enckey>`, the SNMPv3 privacy/encryption key, was leaking to output in cleartext. It is now redacted. The same change deduplicated the two divergent SNMP `ServiceDetails` redaction paths (processor and converter) behind a single non-mutating `analysis.RedactServiceDetails` primitive, with a convergence test pinning that both paths redact identically. (NATS-163, #667)

**Go stdlib CVE remediation.** The Go toolchain was bumped to 1.26.5 to pick up the fix for GO-2026-5856, and a `govulncheck` crash was resolved alongside remediation of outstanding stdlib CVEs — unblocking Dependabot coverage. (#656, #683)

## Also in this release

- **Performance:** converter allocation and memoization improvements — NAT-heavy conversion benchmarks, firewall-row allocation cut ~41%, multi-format export statistics memoized, and the `CoreProcessor` serialization mutex removed. (#598, #601, #604, #608)
- **Project housekeeping:** modernized issue templates, added `SUPPORT.md` and `FUNDING.yml` (#676), removed the tessl integration (#665), plus routine dependency and GitHub Actions bumps.

## Upgrade notes

Drop-in upgrade from v1.5.0. No config changes, no breaking changes, no public Go API changes.

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md#160---2026-07-17) for the complete list.
