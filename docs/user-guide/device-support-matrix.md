# Device Support Matrix

opnDossier supports both **OPNsense** and **pfSense** configuration files.

Today, **OPNsense has the broadest report and audit coverage**. **pfSense support is solid for core firewall and service areas**, but some sections are still in progress. This page shows what you can currently expect to see in generated reports, terminal output, and audit results for each platform.

If a pfSense feature area is listed as **Not yet supported**, opnDossier warns you during processing so you know the missing section reflects current product coverage, not necessarily something absent from your firewall.

## Coverage

| Feature area            | OPNsense  |      pfSense      |
| ----------------------- | :-------: | :---------------: |
| System settings         | Supported |     Supported     |
| Interfaces              | Supported |     Supported     |
| VLANs                   | Supported |     Supported     |
| Bridges                 | Supported | Not yet supported |
| PPP links               | Supported |     Supported     |
| GIF tunnels             | Supported | Not yet supported |
| GRE tunnels             | Supported | Not yet supported |
| LAGG groups             | Supported | Not yet supported |
| Virtual IPs             | Supported | Not yet supported |
| Interface groups        | Supported | Not yet supported |
| Firewall rules          | Supported |     Supported     |
| NAT                     | Supported |     Supported     |
| DHCP                    | Supported |     Supported     |
| DNS                     | Supported |     Supported     |
| NTP                     | Supported | Not yet supported |
| SNMP                    | Supported |     Supported     |
| Load balancer           | Supported |     Supported     |
| VPN                     | Supported |     Supported     |
| Routing                 | Supported |     Supported     |
| Certificates            | Supported |     Supported     |
| Certificate authorities | Supported |     Supported     |
| High availability       | Supported | Not yet supported |
| IDS/IPS                 | Supported | Not yet supported |
| Remote syslog           | Supported |     Supported     |
| Users                   | Supported |     Supported     |
| Groups                  | Supported |     Supported     |
| System tunables         | Supported | Not yet supported |
| Packages                | Supported | Not yet supported |
| Monit                   | Supported | Not yet supported |
| NetFlow                 | Supported | Not yet supported |
| Traffic shaper          | Supported | Not yet supported |
| Captive portal          | Supported | Not yet supported |
| Cron jobs               | Supported |     Supported     |
| Trust settings          | Supported | Not yet supported |
| Kea DHCP                | Supported | Not yet supported |
| Revision history        | Supported |     Supported     |
| Theme settings          | Supported | Not yet supported |

**Legend:**

- **Supported** — opnDossier currently includes this area in parsing, reporting, and related analysis when it exists in the source configuration.
- **Not yet supported** — opnDossier does not currently include this area for that platform.

## What this means in practice

When you process an **OPNsense** configuration, you can expect the broadest coverage across system, networking, security, and service sections.

When you process a **pfSense** configuration, you can still rely on opnDossier for the major day-to-day areas most operators care about, including interfaces, VLANs, firewall rules, NAT, DHCP, DNS, VPN, routing, certificates, users, groups, syslog, cron jobs, and revision history.

For pfSense areas marked **Not yet supported**, opnDossier warns during processing so you can distinguish between:

- a feature that is present on the firewall but not yet covered by the tool, and
- a feature that is genuinely absent from the configuration.

This matters most when you review reports or audit results. If a pfSense-related section is missing, check the matrix before assuming the feature is disabled or misconfigured.

## Practical guidance for pfSense users

- Use the matrix as a quick confidence check before relying on a report for migration, review, or compliance work.
- Treat unsupported pfSense areas as **not yet evaluated**, not as a clean bill of health.
- If you need full coverage for one of the unsupported areas, validate it directly in pfSense until opnDossier adds support.

As pfSense coverage improves, this page will be updated so you can quickly see what has moved from **Not yet supported** to **Supported**. Little by little, the matrix gets more green and less mysterious.
