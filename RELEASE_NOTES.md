# opnDossier v1.8.0 — Reading the config the way the vendor writes it

v1.8.0 is a minor release, and most of it is one class of defect: the schema or converter assumed a shape the vendor does not write, so a configured value read as absent or inverted. No OPNsense port forward was ever read, at any release from 15.1 to 26.7. An empty `<ipv6allow/>`, the form pfSense writes and OPNsense shipped as its default, read as IPv6 disabled. A periodic RRD backup every 24 hours read as no backup. Every one of these failed silently — no error, no warning, exit 0 — and two of them made a compliance control pass on exactly the firewalls it exists to catch.

It also fixes one credential leak in `sanitize`, one false positive in `diff` that fired on diffing a config against itself, and ships the first stability snapshot of the `pkg/schema` public surface.

## Breaking changes

None in the stability-tracked packages. The `pkg/model`, `pkg/parser`, `pkg/parser/opnsense` and `pkg/parser/pfsense` API snapshots are additive only: new fields, new types, and corrected doc comments.

`pkg/schema` is public but vendor-tracking (see [`docs/development/public-api.md`](./docs/development/public-api.md)), and this release changes several of its types to match what the vendors actually write. Consumers unmarshaling `config.xml` through these types directly should review:

- **`schema.Nat.Inbound` now binds `<nat><rule>`** and `schema.InboundRule` reads the redirect address from `<target>`. The previous binding, `inbound>rule` with `<internalip>`, matches no OPNsense release. `InboundRule` also gains `sequence`, `pass` and the 26.1 Destination NAT fields. ([#881](https://github.com/EvilBit-Labs/opnDossier/pull/881))
- **`System.IPv6Allow` is `*string` on both vendors**, so presence and absence are distinguishable. The JSON/YAML key is unchanged. ([#874](https://github.com/EvilBit-Labs/opnDossier/pull/874))
- **Six OPNsense fields are `string`, not `BoolFlag`:** `System.RrdBackup`, `System.NetflowBackup`, `User.Expires`, `User.AuthorizedKeys`, `User.IPSecPSK` and `User.OTPSeed`. They hold an hour interval, a date, SSH keys, a PSK and an OTP seed, and `BoolFlag` read every set value as false. `IPSecPSK` and `OTPSeed` are secrets and are no longer serialized to JSON or YAML. ([#867](https://github.com/EvilBit-Labs/opnDossier/pull/867))
- **The `pkg/schema` surface is now snapshot-tested.** `pkg/parser/testdata/api-snapshots/pkg-schema-*.golden` freeze the opnsense, pfsense and shared packages, so a field removed or a key renamed there is visible in review rather than silent. ([#827](https://github.com/EvilBit-Labs/opnDossier/pull/827))

Two CLI surfaces change shape without a flag to revert:

- **`completion bash` and `completion powershell` emit different scripts.** The duplicate `completion` command was deleted in favor of Cobra's built-in, which uses the V2 bash generator and supports `--no-descriptions`. `zsh` and `fish` output is byte-identical. The `completion` command is now four per-shell subcommands, and the CLI reference reflects that. ([#841](https://github.com/EvilBit-Labs/opnDossier/pull/841), [#854](https://github.com/EvilBit-Labs/opnDossier/pull/854))
- **The GitHub Action default `version:` input is `v1.8.0`.** Re-pin `uses:` lines accordingly.

## Fixed

**No OPNsense port forward was ever read.** The schema bound port forwards as `<nat><inbound><rule>` and took the redirect address from `<internalip>`. OPNsense stores them as `<rule>` directly under `<nat>` with the address in `<target>`, at every release checked from 15.1 to 26.7. `encoding/xml` dropped the unmatched element without an error, so the report said no port forwards were configured, the red audit and `FIREWALL-054` had nothing to check, and `diff` never saw a port forward change. The converter now reads both the legacy page's shape and the 26.1 Destination NAT model: rules are returned in `<sequence>` order where one is recorded, the association survives in `InboundNATRule.AssociatedRuleID` whichever element carried it, an alias held in `<network>` resolves like one held in `<address>`, a no-RDR rule no longer draws the "no internal IP" warning, and the empty `<rule/>` OPNsense 18.7.10 to 25.7 leave behind after the last forward is deleted is skipped as a placeholder rather than counted. Filter rules keep `<associated-rule-id>` on both vendors, and the pfSense converter gains the same no-RDR and `<not>` handling. Fixes [#877](https://github.com/EvilBit-Labs/opnDossier/issues/877). ([#881](https://github.com/EvilBit-Labs/opnDossier/pull/881))

**A port forward exported differently depending on which vendor wrote it.** A pfSense forward whose `<source>` or `<destination>` had no address exported an empty string where OPNsense exported `any`, so the same rule produced different JSON per vendor and `diff` rendered the pfSense side as `unknown`. Both read as `any` now. `InboundNATRule` gains `category` and `poolOpts`, mapped from the OPNsense schema and compared by the diff engine, so a change to either produces a diff entry whose old and new text actually differ. ([#900](https://github.com/EvilBit-Labs/opnDossier/pull/900))

**`FIREWALL-006` passed on firewalls with IPv6 enabled.** Two independent causes. OPNsense before 26.1 and pfSense test `<system><ipv6allow>` with `isset()`, so the element's presence is what allows IPv6, and pfSense writes an enabled setting as an empty element. Both schemas typed the field `string` and both converters compared it with `""`, so every pfSense config with IPv6 allowed, and eight of the nine OPNsense fixtures carrying the element, read as IPv6 disabled. Separately, OPNsense 26.1 moved the IPv6, offload and VLAN hardware filter settings from `<system>` into `<OPNsense><Interfaces><settings>`, inverting `ipv6allow` into `disableipv6` and deleting the originals, so on a 26.1 or later config all five fields read as off. The field is `*string` now and the converters test presence; the schema carries the 26.1 block and the converter reads it when present, warning on a model version it does not recognize. The control's remediation now names the OPNsense menu as well as the pfSense one. ([#874](https://github.com/EvilBit-Labs/opnDossier/pull/874))

**A PEM private key survived `sanitize` in clear when its field name matched no rule.** The value-detector path split a leaf on whitespace and matched each token alone, so the armor line split into `-----BEGIN`, `RSA`, `PRIVATE`, `KEY-----` and no token ever carried both markers. An RSA key or OpenVPN static key in an unexpected element was emitted verbatim in every mode. The whole value is now tried first, gated on it being armor-shaped so that a multi-member alias field cannot be swallowed by one member's shape. ([#842](https://github.com/EvilBit-Labs/opnDossier/pull/842))

**`diff` reported a rule as modified with identical old and new values** whenever its source or destination named an alias. Diffing a config against itself was enough to see it: the equality helpers compared `RuleEndpoint` with `==`, which compared the `*ObjectRef` pointers each parse allocates afresh. Endpoints are compared by value now. Fixes [#878](https://github.com/EvilBit-Labs/opnDossier/issues/878). ([#880](https://github.com/EvilBit-Labs/opnDossier/pull/880))

**A config declaring aliases in the legacy top-level `<aliases>` block decoded to nothing.** The top-level element dispatcher had no case for it, so `convert --format json` reported `namedObjects: null` even though the schema and converter both handled the block correctly. A coverage test now parses the dispatch switch with `go/ast` and asserts every schema tag has a case that decodes into the field owning it. ([#841](https://github.com/EvilBit-Labs/opnDossier/pull/841))

**Periodic RRD and NetFlow backups read as disabled.** The two settings hold an hour interval from 1 to 24, or `-1` for off. They were migrated to `BoolFlag` with the real toggles, which runs the body through a truthiness parser, so every value from 2 to 24 read as no backup. They are strings now and a positive whole number of hours reads as a configured interval. Four `User` fields holding a date, SSH keys, a PSK and an OTP seed had the same mis-typing; nothing maps them into the model yet, so no output changes there. ([#867](https://github.com/EvilBit-Labs/opnDossier/pull/867))

## Added

**The advanced DHCP client settings on interfaces reach the report.** Both vendors write them under `<interfaces><wan>`, not `<dhcpd>`, and each `Interface` schema struct declared 5 of the 41 elements a real config carries there. The other 36 were discarded during unmarshaling and neither converter referenced any of them. `Interface` gains `dhcpAdvancedV4` and `dhcpAdvancedV6`, omitted when unset. ([#829](https://github.com/EvilBit-Labs/opnDossier/pull/829)) A follow-up corrected the three DHCPv6 checkboxes, which pfSense and OPNsense 15.x store as `Selected` and later OPNsense stores as `on`, while releases through 26.7.4 write an unticked box as a self-closing element. The schema keeps them as strings and a non-empty value is ticked, as both vendors' `interfaces.inc` do. ([#866](https://github.com/EvilBit-Labs/opnDossier/pull/866))

## Security

**Built with Go 1.26.9.** `govulncheck` reported five `net/http` advisories reachable on go1.26.6 (GO-2026-6603, 6611, 6612, 6613, 6617). opnDossier imports no network package and a test enforces that; the symbols enter through `spf13/afero` and `olekukonko/errors`, and the scan reaches them through interface calls rather than any HTTP path the binary exercises. The toolchain and mise pins are both bumped, so every release artifact is built with the fixed version. ([#889](https://github.com/EvilBit-Labs/opnDossier/pull/889))

## Also in this release

- **Unreachable Go surface removed, with a guard against its return.** Net −7,338 / +1,960 lines across 113 files and four dependencies dropped, including a second markdown renderer nothing called and help templates that never rendered. A `deadcode` gate with a reasoned allowlist now blocks in CI and in `just ci-check`; `unused` cannot catch this class because it counts a symbol's own tests as callers. Every output surface was verified byte-identical against the merge-base. ([#841](https://github.com/EvilBit-Labs/opnDossier/pull/841), [#863](https://github.com/EvilBit-Labs/opnDossier/pull/863), [#854](https://github.com/EvilBit-Labs/opnDossier/pull/854))
- **The lint gate can fail on formatter drift.** `.golangci.yml` set `fix: true`, so CI repaired formatting in its own checkout and reported zero issues. The key is gone, CI pins `--fix=false`, and a construct `golines` and `gofumpt` could never agree on was rewritten. ([#838](https://github.com/EvilBit-Labs/opnDossier/pull/838), [#847](https://github.com/EvilBit-Labs/opnDossier/pull/847))
- **CI runs `modernize` and the completeness suite**, which sat behind a build tag no workflow set. ([#828](https://github.com/EvilBit-Labs/opnDossier/pull/828))
- The stale `completion` page in the CLI reference regenerated ([#854](https://github.com/EvilBit-Labs/opnDossier/pull/854)), the model reference page correctly labelled as hand-maintained ([#900](https://github.com/EvilBit-Labs/opnDossier/pull/900)), outdated README badges removed, and routine dependency bumps.

## Upgrade notes

Upgrading is a drop-in replacement — no config changes and no CLI flag changes — but this release reads configuration it previously discarded, so expect output to change.

**OPNsense port forwards appear for the first time.** Every report, export, red-mode audit and diff of an OPNsense config now includes them. `FIREWALL-054` will evaluate rules it never saw, and red mode will report WAN-reachable forwards it never knew about. These are not new checks; review the findings before assuming a regression.

**Audits may now fail `FIREWALL-006`.** A firewall with IPv6 allowed, on either vendor, previously passed. `audit` still exits 0 whether or not a control fails, so a pipeline reading the report rather than the exit status will see counts move.

**Exports gain fields.** Port forwards on OPNsense, `dhcpAdvancedV4` and `dhcpAdvancedV6` on interfaces, `category` and `poolOpts` on port forwards, `associatedRuleId` on filter rules, and RRD and NetFlow backup intervals that previously read as unset. Golden files and snapshot tests will need regenerating.

**`diff` output changes in both directions.** Self-diffs and alias-bearing rule pairs no longer produce phantom Modified entries, and port forward changes on OPNsense produce entries for the first time.

**Sanitized output differs** for any PEM-armored value in a field the rules did not name. It is now `[REDACTED-PRIVATE-KEY]` in every mode.

**Regenerate sourced completion scripts** for bash and PowerShell if you keep them checked in.

**GitHub Action users should re-pin to `v1.8.0`.**

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md#180---2026-10-18) for the complete list.
