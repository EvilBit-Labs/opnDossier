# opnDossier v1.4.0 — Kea DHCP, full compliance posture, and container support

This release unifies DHCP parsing across ISC and Kea backends, overhauls blue mode into a true compliance posture report, and ships a Dockerfile and GitHub Action for CI integration. Security hardening and a 710-line net code reduction round it out.

## Highlights

**Kea DHCP4 parsing.** Previously, opnDossier only extracted general-level Kea fields — subnets, pools, and reservations were invisible. Now, full Kea DHCP4 data is parsed and normalized into the same `DHCPScope` model as ISC DHCP, so reports, diffs, and exports work uniformly regardless of backend.

```yaml
# CommonDevice DHCP scopes now include:
  - source: kea        # or "isc"
    subnet: 10.0.1.0/24
    gateway: 10.0.1.1
    staticLeases: ['...']
```

**Three-state compliance posture.** Blue mode reports previously showed only findings. Now every control reports PASS, FAIL, or UNKNOWN — with 75 new controls across STIG, SANS, and Firewall plugins. The new `--failures-only` flag filters to just what needs attention.

**Docker and GitHub Action.** `Dockerfile` and `action.yaml` are wired into goreleaser v2 for container image builds on release. Run opnDossier in CI pipelines without installing Go. (#521, closes #482)

**LDAP pseudonymization.** The sanitizer now pseudonymizes authserver LDAP bind passwords (e.g., `ldap-bindpw-001`) instead of flat-redacting them, preserving the structure needed for config comparison while removing secrets. (#529)

## Upgrade notes

No breaking changes. Drop-in upgrade from v1.3.0.

New optional flags:

- `--failures-only` — show only failing controls in blue mode (markdown format only)
- Docker image available on release for CI/CD pipelines

## Full changelog

See the [weekly changelog discussion](https://github.com/EvilBit-Labs/opnDossier/discussions/537) for the complete list of changes, contributors, and dependency updates.
