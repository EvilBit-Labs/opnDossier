# Sanitizer testdata

## `benchmark-10mb.xml`

A ~10MB synthetic OPNsense config fixture used by `BenchmarkSanitizeXML_10MB` in `fixture_bench_test.go`. The fixture is generated deterministically at benchmark time (see `ensureBenchmark10MBFixture` in `fixture_bench_test.go`) and cached on disk so subsequent benchmark runs skip regeneration.

The file is excluded from version control via `.gitignore` to keep the repository small. If the file is missing or smaller than the target size, the benchmark helper rebuilds it on the next invocation.

Contents:

- ~5000 firewall rules with descriptions, source/destination networks, protocol, interface, log/disabled toggles, and redirect targets.
- ~50 interfaces with IPv4/IPv6 addressing, subnet, description.
- ~200 users with passwords, emails, SSH authorized keys, verbose descriptions to bulk up the field count.
- ~500 certificates with synthetic PEM bodies and private-key fields.
- SNMP community strings, OpenVPN client configs, IPsec PSKs.
- ~1000 DHCP host overrides with hostnames, MACs, static IP assignments.

This mix exercises every major redaction rule in `builtinRules()` without relying on any real customer data.
