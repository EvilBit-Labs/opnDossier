# ADR-0001: SNMP configuration storage model in OPNsense and pfSense

**Date**: 2026-06-27 **Status**: accepted **Deciders**: UncleSp1d3r (maintainer), Claude Code (Opus 4.8)

> Updated 2026-11-13: the OPNsense findings below are corrected, and the plugin namespace is now parsed. See [Update (2026-11-13)](#update-2026-11-13).

## Context

opnDossier redacts the SNMP community string in statistics and exports. A scope question (deduplicating that redaction) raised a follow-on: should redaction also cover SNMPv3 authentication and privacy secrets? Answering responsibly required examining the upstream OPNsense and pfSense source to determine exactly where SNMP credentials are persisted in `config.xml`. This ADR records those verified findings so future SNMP parser, statistics, and sanitizer work starts from facts rather than assumptions. The findings are the durable artifact here; the scoping choice they enabled is a consequence, not the decision.

## Findings (verified against vendor source)

### pfSense (base / CE)

- SNMP is `bsnmpd`. Config lives under `<snmpd>` with `rocommunity` (plus `syslocation`, `syscontact`). Community-only — **no SNMPv3** in base `config.xml`. (`src/usr/local/www/services_snmp.php`, `src/etc/inc/services.inc`)
- pfSense itself treats `rocommunity` as a secret: it appears in the masked-field list in `src/usr/local/pfSense/include/www/status_output.inc`.

### OPNsense core

- Base `<snmpd>` carries only `syslocation`, `syscontact`, `rocommunity` (`bsnmpd`, v1/v2c). **No SNMPv3** in core `config.xml`.

### OPNsense `os-net-snmp` plugin (`net-mgmt/net-snmp`)

- SNMPv3 lives here, persisted to `config.xml` under `<OPNsense><netsnmp>`. The MVC models mount at `//OPNsense/netsnmp/general` and `//OPNsense/netsnmp/user`.
- **general** (model v1.0.5): `enabled`, `community`, `syslocation`, `syscontact`, `l3visibility`, `versionoid`, `enableagentx`, `enableobservium`, `listen`.
- **user/users/user[]** (model v1.0.1): `enabled`, `username`, **`password`** (SNMPv3 auth passphrase — cleartext `TextField`, 8–64 chars), **`enckey`** (privacy/encryption key — cleartext `TextField`, 8–64 chars), `readwrite`.
- Credentials are stored cleartext in `config.xml`; the daemon template renders them to `snmpd_usercredentials.conf`.

### opnDossier today

- Parses only the base `<snmpd>` → `pkg/schema/opnsense/services.go` `Snmpd{SysLocation, SysContact, ROCommunity}`. The `<OPNsense><netsnmp>` plugin namespace is **not parsed anywhere** (no references in `pkg/` or `internal/`).
- The `sanitize` command walks **raw XML element names**, so credential redaction does not depend on the model parsing the plugin namespace.

## Decision

Scope opnDossier's SNMP credential handling to what the vendor source actually persists, as enumerated above: `rocommunity` (base), and the net-snmp plugin's `password` and `enckey`. Model-based SNMPv3 features require parsing the `<OPNsense><netsnmp>` namespace, which opnDossier does not do today.

## Alternatives Considered

### Alternative: Model SNMPv3 ingestion as part of current SNMP work

- **Pros**: One tracked item covering statistics and redaction across all SNMP versions.
- **Cons**: Requires building a parser for the `<OPNsense><netsnmp>` plugin namespace (a new schema surface); pfSense base has no SNMPv3 to model, so coverage would be OPNsense-plugin-only.
- **Why not**: SNMPv3 ingestion is a feature with its own prerequisite and is not required by the current community-redaction work; it is tracked separately.

## Consequences

### Positive

- Future SNMP parser, statistics, and sanitizer work starts from verified field names, storage locations, and model versions.
- The community-redaction dedup can proceed as a behavior-neutral refactor; a centralized sensitive-key list makes adding `password`/`enckey` a one-line change once the namespace is parsed.

### Negative

- The `<OPNsense><netsnmp>` namespace remains unparsed, so SNMPv3 secrets stay invisible to model-based features until that work lands.

### Risks

- **Schema version drift.** The plugin model element names/versions can change across OPNsense releases (general v1.0.5, user v1.0.1 at time of writing). Re-verify against a real `config.xml` when implementing ingestion (cf. GOTCHAS §18.1 version-pinning).

## Update (2026-11-13)

Two findings above were incomplete, and the parser now reads the plugin namespace.

- OPNsense core has not run an SNMP agent since 17.1. From 17.1 to 18.7 the `os-snmp` plugin (`net-mgmt/snmp`, removed in 19.1) ran `bsnmpd` from the legacy `<snmpd>` block, and like core before it, only when `<snmpd><enable>` was set. From 19.1 the only agent is `os-net-snmp`. Factory defaults kept writing `<snmpd><rocommunity>public</rocommunity></snmpd>` without `<enable>` up to 25.7, so upgraded configs carry a block no agent reads.
- opnDossier now parses `<OPNsense><netsnmp>` (`pkg/schema/opnsense/netsnmp.go`), pins general model versions 1.0.0 to 1.0.7 (the plugin never used 1.0.2) and user model versions 1.0.0 and 1.0.1, and maps an enabled agent into `SNMPConfig`, including SNMPv3 usernames and read-write access. The `password` and `enckey` elements are not bound in the schema, so model-based features never see them.
- pfSense, like OPNsense up to 18.7, starts bsnmpd only when `<snmpd><enable>` is present (`config_path_enabled('snmpd')`, an `isset()` test). Both converters now report an `<snmpd>` block only when it carries `<enable>`, and set `SNMPConfig.Enabled` for a running agent.
- The consequence above that the namespace "remains unparsed" no longer holds; the decision on which credentials exist is unchanged, and SNMPv3 secrets are still kept out of the model.

## Sources

- `opnsense/plugins` — `net-mgmt/net-snmp/src/opnsense/mvc/app/models/OPNsense/Netsnmp/General.xml`, `.../User.xml`; template target `snmpd_usercredentials.conf`
- `opnsense/core` — base `<snmpd>` handling
- `pfsense/pfsense` — `src/usr/local/www/services_snmp.php`, `src/etc/inc/services.inc`, `src/usr/local/pfSense/include/www/status_output.inc`
- opnDossier — `pkg/schema/opnsense/services.go` (`Snmpd`), `internal/analysis/statistics.go` (`populateServiceStats`)
