# Device Support Matrix

opnDossier supports parsing and auditing configurations from both **OPNsense** and **pfSense**. Coverage of the platform-agnostic `CommonDevice` model differs between the two — OPNsense is the reference platform and currently populates more subsystems than the pfSense converter.

When the pfSense converter has not yet implemented a subsystem, it emits a `ConversionWarning` at `SeverityMedium` with the stable message text **"not yet implemented in pfSense converter"**. Compliance consumers can filter on that substring to skip affected controls for pfSense inputs and avoid false `PASS` verdicts.

## Coverage

| Subsystem (CommonDevice field) | OPNsense | pfSense |
| ------------------------------ | :------: | :-----: |
| `System`                       |    ✅    |   ✅    |
| `Interfaces`                   |    ✅    |   ✅    |
| `VLANs`                        |    ✅    |   ✅    |
| `Bridges`                      |    ✅    |   ❌    |
| `PPPs`                         |    ✅    |   ✅    |
| `GIFs`                         |    ✅    |   ❌    |
| `GREs`                         |    ✅    |   ❌    |
| `LAGGs`                        |    ✅    |   ❌    |
| `VirtualIPs`                   |    ✅    |   ❌    |
| `InterfaceGroups`              |    ✅    |   ❌    |
| `FirewallRules`                |    ✅    |   ✅    |
| `NAT`                          |    ✅    |   ✅    |
| `DHCP`                         |    ✅    |   ✅    |
| `DNS`                          |    ✅    |   ✅    |
| `NTP`                          |    ✅    |   ❌    |
| `SNMP`                         |    ✅    |   ✅    |
| `LoadBalancer`                 |    ✅    |   ✅    |
| `VPN`                          |    ✅    |   ✅    |
| `Routing`                      |    ✅    |   ✅    |
| `Certificates`                 |    ✅    |   ✅    |
| `CAs`                          |    ✅    |   ✅    |
| `HighAvailability`             |    ✅    |   ❌    |
| `IDS`                          |    ✅    |   ❌    |
| `Syslog`                       |    ✅    |   ✅    |
| `Users`                        |    ✅    |   ✅    |
| `Groups`                       |    ✅    |   ✅    |
| `Sysctl`                       |    ✅    |   ❌    |
| `Packages`                     |    ✅    |   ❌    |
| `Monit`                        |    ✅    |   ❌    |
| `Netflow`                      |    ✅    |   ❌    |
| `TrafficShaper`                |    ✅    |   ❌    |
| `CaptivePortal`                |    ✅    |   ❌    |
| `Cron`                         |    ✅    |   ✅    |
| `Trust`                        |    ✅    |   ❌    |
| `KeaDHCP`                      |    ✅    |   ❌    |
| `Revision`                     |    ✅    |   ✅    |
| `Theme`                        |    ✅    |   ❌    |

Legend: ✅ = converter populates the field from the vendor DTO when present in the source XML. ❌ = converter does not yet populate the field; a `ConversionWarning` is emitted per-parse so downstream consumers can detect the gap programmatically.

## Using the gap signal

The pfSense converter exposes two public accessors for the gap list:

- `pfsense.IsKnownGap(field string) bool` — returns `true` for every field listed above as ❌.
- `pfsense.KnownGaps() []string` — returns a fresh copy of the list.

Compliance plugins that query specific subsystems (e.g., `device.HighAvailability`) should consult `IsKnownGap` before treating an empty value as "feature absent," and either skip the control or emit their own "unverifiable on pfSense" finding.

## Keeping this document accurate

The cross-platform parity test at `pkg/parser/parity_test.go` asserts that every subsystem OPNsense populates from a representative fixture is either populated by pfSense or listed in `pfsense.KnownGaps()`. Adding a new OPNsense subsystem without wiring pfSense coverage (or adding the field to the gap list) fails the test.

When a pfSense subsystem gets implemented in the converter, remove the corresponding entry from `pfsenseKnownGaps` in the same change, regenerate this table, and the parity test validates the change automatically.
