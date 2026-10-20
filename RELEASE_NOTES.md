# opnDossier v1.8.0: reading the config the way the vendor writes it

Most of v1.8.0 is one kind of bug. The schema or the converter assumed a shape the vendor never writes, so a configured value read as absent or as its opposite. No OPNsense port forward was ever read, on any release from 15.1 to 26.7. An empty `<ipv6allow/>`, which is what pfSense writes and what OPNsense shipped as its default, read as IPv6 disabled. A periodic RRD backup every 24 hours read as no backup. None of this produced an error or a warning. The exit code was 0 every time, and in two cases a compliance control passed on exactly the firewalls it exists to catch.

The release also closes a credential leak in `sanitize`, fixes a `diff` false positive you could trigger by diffing a config against itself, and adds the first stability snapshot of the `pkg/schema` public surface.

## Breaking changes

None in the stability-tracked packages. The `pkg/model`, `pkg/parser`, `pkg/parser/opnsense` and `pkg/parser/pfsense` API snapshots only gained things: new fields, new types, corrected doc comments.

`pkg/schema` is public but follows the vendor (see [`docs/development/public-api.md`](./docs/development/public-api.md)), and several of its types change here to match what the vendors write. If you unmarshal `config.xml` through these types yourself, review the following.

- `schema.Nat.Inbound` now binds `<nat><rule>`, and `schema.InboundRule` reads the redirect address from `<target>`. The old binding, `inbound>rule` with `<internalip>`, matches no OPNsense release. `InboundRule` also gains `sequence`, `pass` and the 26.1 Destination NAT fields. ([#881](https://github.com/EvilBit-Labs/opnDossier/pull/881))
- `System.IPv6Allow` is a `*string` on both vendors, so presence and absence can be told apart. The JSON and YAML key is unchanged. ([#874](https://github.com/EvilBit-Labs/opnDossier/pull/874))
- Six OPNsense fields are `string` rather than `BoolFlag`: `System.RrdBackup`, `System.NetflowBackup`, `User.Expires`, `User.AuthorizedKeys`, `User.IPSecPSK` and `User.OTPSeed`. They hold an hour interval, a date, SSH keys, a PSK and an OTP seed, and `BoolFlag` read every set value as false. `IPSecPSK` and `OTPSeed` are secrets and no longer serialize to JSON or YAML. ([#867](https://github.com/EvilBit-Labs/opnDossier/pull/867))
- The `pkg/schema` surface now has a snapshot test. `pkg/parser/testdata/api-snapshots/pkg-schema-*.golden` freeze the opnsense, pfsense and shared packages, so a removed field or a renamed key shows up in review instead of reaching a consumer silently. ([#827](https://github.com/EvilBit-Labs/opnDossier/pull/827))

Two CLI surfaces also change, with no flag to get the old behavior back.

- `completion bash` and `completion powershell` emit different scripts. The duplicate `completion` command is gone in favor of Cobra's built-in one, which uses the V2 bash generator and supports `--no-descriptions`. `zsh` and `fish` output is byte for byte the same as before. `completion` is now four per-shell subcommands and the CLI reference says so. ([#841](https://github.com/EvilBit-Labs/opnDossier/pull/841), [#854](https://github.com/EvilBit-Labs/opnDossier/pull/854))
- The GitHub Action's default `version:` input is `v1.8.0`. Re-pin your `uses:` lines.

## Fixed

**No OPNsense port forward was ever read.** The schema bound port forwards as `<nat><inbound><rule>` and took the redirect address from `<internalip>`. OPNsense stores them as `<rule>` directly under `<nat>` with the address in `<target>`, and has done so on every release we checked from 15.1 to 26.7. `encoding/xml` drops an unmatched element without complaint, so the report said no port forwards were configured, the red audit and `FIREWALL-054` had nothing to look at, and `diff` never noticed a port forward changing. The converter now reads both the legacy page's shape and the 26.1 Destination NAT model. Rules come back in `<sequence>` order where one is recorded, the association lands in `InboundNATRule.AssociatedRuleID` whichever element carried it, and an alias in `<network>` resolves the same as one in `<address>`. A no-RDR rule no longer draws the "no internal IP" warning, and the empty `<rule/>` that OPNsense 18.7.10 through 25.7 leave behind after you delete the last forward is skipped as a placeholder instead of counted. Filter rules keep `<associated-rule-id>` on both vendors, and the pfSense converter gets the same no-RDR and `<not>` handling. Fixes [#877](https://github.com/EvilBit-Labs/opnDossier/issues/877). ([#881](https://github.com/EvilBit-Labs/opnDossier/pull/881))

**The same port forward exported differently depending on who wrote it.** A pfSense forward with no address in `<source>` or `<destination>` exported an empty string where OPNsense exported `any`, so one rule produced two different JSON documents and `diff` showed the pfSense side as `unknown`. Both read as `any` now. `InboundNATRule` also gains `category` and `poolOpts`, mapped from the OPNsense schema and compared by the diff engine, so a change to either shows up as a diff entry whose old and new text differ. ([#900](https://github.com/EvilBit-Labs/opnDossier/pull/900))

**`FIREWALL-006` passed on firewalls with IPv6 enabled.** There were two causes. OPNsense before 26.1 and pfSense both test `<system><ipv6allow>` with `isset()`, so the element's presence is what allows IPv6, and pfSense writes an enabled setting as an empty element. Both schemas typed the field as a string and both converters compared it with `""`, so every pfSense config with IPv6 allowed, plus eight of the nine OPNsense fixtures carrying the element, read as IPv6 disabled. The second cause is newer. OPNsense 26.1 moved the IPv6, offload and VLAN hardware filter settings from `<system>` into `<OPNsense><Interfaces><settings>`, inverted `ipv6allow` into `disableipv6`, and deleted the originals. On a 26.1 or later config all five fields read as off. The field is a `*string` now and the converters test for presence. The schema carries the 26.1 block, the converter reads it when it is there, and it warns on a model version it does not know. The control's remediation now names the OPNsense menu as well as the pfSense one. ([#874](https://github.com/EvilBit-Labs/opnDossier/pull/874))

**A PEM private key survived `sanitize` in clear when its field name matched no rule.** The value detector split each leaf on whitespace and matched the tokens one at a time, so the armor line became `-----BEGIN`, `RSA`, `PRIVATE`, `KEY-----` and no single token ever carried both markers. An RSA key or an OpenVPN static key in an element we did not expect went out verbatim in every mode. The whole value is tried first now. That path only runs when the value looks like an armored envelope, so a multi-member alias field cannot be swallowed because one member happens to match. ([#842](https://github.com/EvilBit-Labs/opnDossier/pull/842))

**`diff` reported a rule as modified with identical old and new values** whenever its source or destination named an alias. Diffing a config against itself was enough to see it. The equality helpers compared `RuleEndpoint` with `==`, which compares the `*ObjectRef` pointers, and each parse allocates fresh ones. Endpoints compare by value now. Fixes [#878](https://github.com/EvilBit-Labs/opnDossier/issues/878). ([#880](https://github.com/EvilBit-Labs/opnDossier/pull/880))

**A config with aliases in the legacy top-level `<aliases>` block decoded to nothing.** The top-level element dispatcher had no case for it, so `convert --format json` reported `namedObjects: null` even though the schema and the converter both handled the block fine. A coverage test now parses the dispatch switch with `go/ast` and checks that every schema tag has a case, and that the case decodes into the field that owns the tag. ([#841](https://github.com/EvilBit-Labs/opnDossier/pull/841))

**Periodic RRD and NetFlow backups read as disabled.** The two settings hold an hour interval from 1 to 24, or `-1` for off. They were migrated to `BoolFlag` along with the real toggles, and `BoolFlag` runs the body through a truthiness parser, so every value from 2 to 24 read as no backup. They are strings now, and a positive whole number of hours reads as a configured interval. Four `User` fields holding a date, SSH keys, a PSK and an OTP seed had the same wrong type. Nothing maps those into the model yet, so no output changes there. ([#867](https://github.com/EvilBit-Labs/opnDossier/pull/867))

## Added

**The advanced DHCP client settings on interfaces reach the report.** Both vendors write them under `<interfaces><wan>`, not `<dhcpd>`. Each `Interface` schema struct declared 5 of the 41 elements a real config carries there, the other 36 were thrown away during unmarshaling, and neither converter referenced any of them. `Interface` gains `dhcpAdvancedV4` and `dhcpAdvancedV6`, omitted when unset. ([#829](https://github.com/EvilBit-Labs/opnDossier/pull/829)) A follow-up corrected the three DHCPv6 checkboxes. pfSense and OPNsense 15.x store a ticked box as `Selected`, later OPNsense stores `on`, and releases through 26.7.4 write an unticked box as a self-closing element. The schema keeps them as strings and treats any non-empty value as ticked, which is what both vendors' `interfaces.inc` do. ([#866](https://github.com/EvilBit-Labs/opnDossier/pull/866))

## Security

**Built with Go 1.27.2.** `govulncheck` had been reporting five `net/http` advisories reachable on go1.26.6 (GO-2026-6603, 6611, 6612, 6613 and 6617), all fixed from go1.26.9 on. opnDossier imports no network package and a test enforces that. The symbols come in through `spf13/afero` and `olekukonko/errors`, and the scanner reaches them through interface calls, not through any HTTP path the binary takes. The toolchain and mise pins moved together, so every release artifact is built with the fixed version. ([#889](https://github.com/EvilBit-Labs/opnDossier/pull/889))

## Also in this release

- Unreachable Go surface is gone, and a guard stops it coming back. Net −7,338 / +1,960 lines across 113 files, four dependencies dropped, including a second markdown renderer nothing called and help templates that never rendered. A `deadcode` gate with a reasoned allowlist now blocks in CI and in `just ci-check`. The `unused` linter could not catch this class because it counts a symbol's own tests as callers. Every output surface was checked byte for byte against the merge base. ([#841](https://github.com/EvilBit-Labs/opnDossier/pull/841), [#863](https://github.com/EvilBit-Labs/opnDossier/pull/863), [#854](https://github.com/EvilBit-Labs/opnDossier/pull/854))
- The lint gate can fail on formatter drift. `.golangci.yml` had `fix: true`, so CI repaired formatting in its own checkout and reported zero issues. The key is gone, CI pins `--fix=false`, and a construct that `golines` and `gofumpt` could never agree on was rewritten. ([#838](https://github.com/EvilBit-Labs/opnDossier/pull/838), [#847](https://github.com/EvilBit-Labs/opnDossier/pull/847))
- CI runs `modernize` and the completeness suite. The suite sat behind a build tag that no workflow set. ([#828](https://github.com/EvilBit-Labs/opnDossier/pull/828))
- The stale `completion` page in the CLI reference was regenerated ([#854](https://github.com/EvilBit-Labs/opnDossier/pull/854)), the model reference page now says it is maintained by hand ([#900](https://github.com/EvilBit-Labs/opnDossier/pull/900)), two dead README badges are gone, and the usual dependency bumps landed.

## Upgrade notes

Upgrading is a drop-in replacement. No config changes, no CLI flag changes. But this release reads configuration it used to discard, so expect your output to change.

**OPNsense port forwards appear for the first time.** Every report, export, red-mode audit and diff of an OPNsense config now includes them. `FIREWALL-054` will evaluate rules it has never seen, and red mode will report WAN-reachable forwards it never knew about. These are not new checks. Read the new findings before you call it a regression.

**Audits may now fail `FIREWALL-006`.** A firewall with IPv6 allowed, on either vendor, used to pass. `audit` still exits 0 whether or not a control fails, so a pipeline that reads the report rather than the exit status will see the counts move.

**Exports gain fields.** Port forwards on OPNsense, `dhcpAdvancedV4` and `dhcpAdvancedV6` on interfaces, `category` and `poolOpts` on port forwards, `associatedRuleId` on filter rules, and RRD and NetFlow backup intervals that used to read as unset. Golden files and snapshot tests will need regenerating.

**`diff` output changes in both directions.** Self-diffs and rule pairs that name an alias no longer produce phantom Modified entries, and port forward changes on OPNsense produce entries for the first time.

**Sanitized output differs** for any PEM-armored value in a field the rules did not name. It is `[REDACTED-PRIVATE-KEY]` in every mode now.

**Regenerate sourced completion scripts** for bash and PowerShell if you keep them checked in.

**GitHub Action users should re-pin to `v1.8.0`.**

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md#180---2026-10-19) for the complete list.
