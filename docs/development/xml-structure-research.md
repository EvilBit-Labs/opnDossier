# OPNsense / pfSense config.xml Data Structure Research

> Research conducted Feb 2025 by analyzing upstream OPNsense and pfSense source code, config.xml samples, and the Go schema package. This document informs parsing accuracy and identifies gaps in our data model.

## Sources

| Source                          | URL / Path                                                     | Purpose                            |
| ------------------------------- | -------------------------------------------------------------- | ---------------------------------- |
| OPNsense config.xml.sample      | `src/etc/config.xml.sample` (GitHub)                           | Default configuration template     |
| OPNsense FilterRule.php         | `src/opnsense/mvc/app/models/OPNsense/Firewall/FilterRule.php` | Rule processing logic              |
| OPNsense Rule.php               | `src/opnsense/mvc/app/models/OPNsense/Firewall/Rule.php`       | MVC model definitions              |
| pfSense filter.inc              | `src/etc/inc/filter.inc`                                       | pf rule generation from config.xml |
| pfSense firewall_rules_edit.php | `src/usr/local/www/firewall_rules_edit.php`                    | Web UI address handling            |
| pfSense Bug #6893               | Redmine issue tracker                                          | Self-closing tag inconsistency fix |
| Go schema package               | `internal/schema/*.go`                                         | Our current data model             |

---

## 1. XML Boolean Patterns

OPNsense/pfSense uses two distinct patterns for boolean-like values. Understanding these is critical for correct Go type selection.

### 1a. Presence-Based Booleans (Self-Closing Tags)

Element existing = true, absent = false. Content is irrelevant.

**Upstream PHP pattern:** `isset($rule['disabled'])` or `!empty($rule['disabled'])`

**Go type:** `BoolFlag` (custom type in `internal/schema/common.go`)

| Element                     | Parent Context              | Upstream Evidence                                       |
| --------------------------- | --------------------------- | ------------------------------------------------------- |
| `<any/>`                    | `<source>`, `<destination>` | `isset($this->rule['source']['any'])` in FilterRule.php |
| `<not/>`                    | `<source>`, `<destination>` | `isset($adr['not'])` in filter.inc                      |
| `<disabled/>`               | `<rule>` (filter, NAT)      | `isset($rule['disabled'])` in filter.inc                |
| `<log/>`                    | `<rule>` (filter)           | `isset($rule['log'])` sets `$filterent['log'] = true`   |
| `<quick/>`                  | `<rule>` (filter)           | `isset($rule['quick'])` in OPNsense                     |
| `<disableconsolemenu/>`     | `<system>`                  | config.xml.sample: self-closing                         |
| `<enable/>`                 | `<rrd>`                     | config.xml.sample: self-closing                         |
| `<tcpflags_any/>`           | `<rule>` (filter)           | `isset($rule['tcpflags_any'])`                          |
| `<nopfsync/>`               | `<rule>` (filter)           | `isset($rule['nopfsync'])`                              |
| `<allowopts/>`              | `<rule>` (filter)           | `$filterent['allowopts'] = true`                        |
| `<disablereplyto/>`         | `<rule>` (filter)           | `$filterent['disablereplyto'] = true`                   |
| `<nosync/>`                 | `<rule>` (filter, NAT)      | `$natent['nosync'] = true`                              |
| `<nordr/>`                  | `<rule>` (NAT inbound)      | `isset($natent['nordr'])`                               |
| `<staticnatport/>`          | `<rule>` (NAT outbound)     | Presence-checked in OPNsense                            |
| `<nonat/>`                  | `<rule>` (NAT outbound)     | Presence-checked                                        |
| `<interfacenot/>`           | `<rule>` (filter)           | `!empty($rule['interfacenot'])`                         |
| `<nottagged/>`              | `<rule>` (filter)           | Match packets NOT tagged                                |
| `<trigger_initial_wizard/>` | `<opnsense>` (root)         | First-boot wizard trigger                               |

**pfSense Bug #6893 note:** Prior to pfSense 2.3.3, some code produced `<tag/>` while other code produced `<tag></tag>`. Both forms are valid XML and our `*string` / `BoolFlag` types handle both correctly via Go's `encoding/xml`.

### 1b. Value-Based Booleans

Element contains `1`, `yes`, or a specific value. Absent or empty = false.

**Upstream PHP pattern:** `$config['system']['ipv6allow'] == "1"`

**Go type:** `string` with value check, or potentially a custom type

| Element                  | Parent                   | Values | Notes                    |
| ------------------------ | ------------------------ | ------ | ------------------------ |
| `<enable>`               | `<interfaces><wan>`      | `1`    | Interface enable/disable |
| `<blockpriv>`            | `<interfaces><wan>`      | `1`    | Block private networks   |
| `<blockbogons>`          | `<interfaces><wan>`      | `1`    | Block bogon networks     |
| `<dnsallowoverride>`     | `<system>`               | `1`    | Allow DNS override       |
| `<ipv6allow>`            | `<system>`               | `1`    | IPv6 enabled             |
| `<usevirtualterminal>`   | `<system>`               | `1`    | Virtual terminal         |
| `<pf_share_forward>`     | `<system>`               | `1`    | Shared forwarding        |
| `<lb_use_sticky>`        | `<system>`               | `1`    | Sticky load balancing    |
| `<disablenatreflection>` | `<system>`               | `yes`  | NAT reflection disabled  |
| `<enable>`               | various OPNsense modules | `1`    | Service/feature enabled  |

### 1c. Design Rationale

The distinction is not arbitrary:

- **Presence-based** = flags typically absent (disabled, negation, special modes)
- **Value-based** = feature toggles typically enabled (with explicit `1`)

---

## 2. Source/Destination Structure

The `<source>` and `<destination>` elements are the most complex sub-structures in firewall rules. Understanding their design is critical.

### 2a. XML Structure Examples

```xml
<!-- Match any address -->
<source><any/></source>

<!-- Match interface subnet -->
<source><network>lan</network></source>

<!-- Match specific IP/CIDR -->
<source><address>192.168.1.0/24</address></source>

<!-- Match alias -->
<source><address>MyAlias</address></source>

<!-- Negated match -->
<source><not/><network>lan</network></source>

<!-- With port (TCP/UDP only) -->
<destination><network>wan</network><port>443</port></destination>

<!-- Port range -->
<destination><any/><port>8000-9000</port></destination>
```

### 2b. Mutual Exclusivity

`<any>`, `<network>`, and `<address>` are **mutually exclusive**. Resolution priority (from OPNsense `legacyMoveAddressFields`):

1. `<network>` (highest priority)
2. `<address>`
3. `<any>` / implicit any (when none present)

### 2c. Valid `<network>` Values

- Interface names: `lan`, `wan`, `opt1`, `opt2`, ...
- Interface IP: `lanip`, `wanip`, `opt1ip`
- Special: `(self)` (all local IPs)
- Interface group names
- VIP names

### 2d. Port Range Delimiters

- In config.xml: hyphen (`80-443`)
- In pf rules: colon (`80:443`)
- OPNsense/pfSense code handles the conversion

---

## 3. Filter Rule Fields Reference

### 3a. Currently Modeled (in `Rule` struct)

| Field       | XML Element     | Go Type         | Status                              |
| ----------- | --------------- | --------------- | ----------------------------------- |
| Type        | `<type>`        | `string`        | Correct                             |
| Descr       | `<descr>`       | `string`        | Correct                             |
| Interface   | `<interface>`   | `InterfaceList` | Correct                             |
| IPProtocol  | `<ipprotocol>`  | `string`        | Correct                             |
| Protocol    | `<protocol>`    | `string`        | Correct                             |
| Source      | `<source>`      | `Source`        | **Incomplete** (see 4)              |
| Destination | `<destination>` | `Destination`   | **Incomplete** (see 4)              |
| Target      | `<target>`      | `string`        | Correct                             |
| SourcePort  | `<sourceport>`  | `string`        | Correct                             |
| Disabled    | `<disabled>`    | `string`        | **Wrong type** (should be BoolFlag) |
| Quick       | `<quick>`       | `string`        | **Wrong type** (should be BoolFlag) |
| Updated     | `<updated>`     | `*Updated`      | Correct                             |
| Created     | `<created>`     | `*Created`      | Correct                             |
| UUID        | `uuid` attr     | `string`        | Correct                             |

### 3b. Missing Fields (HIGH importance for security auditing)

| Field            | XML Element            | Recommended Go Type | Importance                   |
| ---------------- | ---------------------- | ------------------- | ---------------------------- |
| Log              | `<log>`                | `BoolFlag`          | HIGH - audit visibility      |
| Floating         | `<floating>`           | `string`            | HIGH - rule semantics        |
| Gateway          | `<gateway>`            | `string`            | HIGH - policy routing        |
| Tracker          | `<tracker>`            | `string`            | MEDIUM - rule identification |
| Sched            | `<sched>`              | `string`            | MEDIUM - time-based rules    |
| AssociatedRuleID | `<associated-rule-id>` | `string`            | MEDIUM - NAT linkage         |
| Direction        | `<direction>`          | `string`            | MEDIUM - floating rules      |

### 3c. Missing Fields (MEDIUM importance)

| Field           | XML Element            | Recommended Go Type |
| --------------- | ---------------------- | ------------------- |
| MaxSrcNodes     | `<max-src-nodes>`      | `string`            |
| MaxSrcConn      | `<max-src-conn>`       | `string`            |
| MaxSrcConnRate  | `<max-src-conn-rate>`  | `string`            |
| MaxSrcConnRates | `<max-src-conn-rates>` | `string`            |
| TCPFlags1       | `<tcpflags1>`          | `string`            |
| TCPFlags2       | `<tcpflags2>`          | `string`            |
| TCPFlagsAny     | `<tcpflags_any>`       | `BoolFlag`          |
| ICMPType        | `<icmptype>`           | `string`            |
| ICMP6Type       | `<icmp6-type>`         | `string`            |
| StateType       | `<statetype>`          | `string`            |
| StateTimeout    | `<statetimeout>`       | `string`            |

### 3d. Missing Fields (LOW importance)

| Field          | XML Element        | Recommended Go Type |
| -------------- | ------------------ | ------------------- |
| AllowOpts      | `<allowopts>`      | `BoolFlag`          |
| DisableReplyTo | `<disablereplyto>` | `BoolFlag`          |
| NoPfSync       | `<nopfsync>`       | `BoolFlag`          |
| NoSync         | `<nosync>`         | `BoolFlag`          |
| Tag            | `<tag>`            | `string`            |
| Tagged         | `<tagged>`         | `string`            |
| OS             | `<os>`             | `string`            |
| DSCP           | `<dscp>`           | `string`            |
| DNPipe         | `<dnpipe>`         | `string`            |
| PDNPipe        | `<pdnpipe>`        | `string`            |
| DefaultQueue   | `<defaultqueue>`   | `string`            |
| AckQueue       | `<ackqueue>`       | `string`            |
| Max            | `<max>`            | `string`            |
| MaxSrcStates   | `<max-src-states>` | `string`            |
| VLANPrio       | `<vlanprio>`       | `string`            |
| VLANPrioSet    | `<vlanprioset>`    | `string`            |
| SetPrio        | `<set-prio>`       | `string`            |
| SetPrioLow     | `<set-prio-low>`   | `string`            |
| InterfaceNot   | `<interfacenot>`   | `BoolFlag`          |
| NotTagged      | `<nottagged>`      | `BoolFlag`          |

---

## 4. Schema Gaps: Source and Destination

### 4a. Current Implementation

```go
// security.go
type Source struct {
    Any     *string `xml:"any,omitempty"`
    Network string  `xml:"network,omitempty"`
}

type Destination struct {
    Any     *string `xml:"any,omitempty"`
    Network string  `xml:"network,omitempty"`
    Port    string  `xml:"port,omitempty"`
}
```

### 4b. Missing Fields

| Field                | XML Element | Impact                                                     |
| -------------------- | ----------- | ---------------------------------------------------------- |
| `Address`            | `<address>` | **CRITICAL** - Rules with IP/CIDR/alias silently lose data |
| `Not`                | `<not>`     | **HIGH** - Negated rules lose semantics                    |
| `Port` (Source only) | `<port>`    | **MEDIUM** - Source port matching lost                     |

### 4c. Existing `RuleLocation` Type (Already Complete!)

`internal/schema/common.go` already defines `RuleLocation` with all needed fields:

```go
type RuleLocation struct {
    Network string   `xml:"network,omitempty"`
    Address string   `xml:"address,omitempty"`
    Subnet  string   `xml:"subnet,omitempty"`
    Port    string   `xml:"port,omitempty"`
    Not     BoolFlag `xml:"not,omitempty"`
}
```

However, `RuleLocation` is **not used** by `Source`/`Destination` in `security.go`. The types are parallel but disconnected.

### 4d. Recommended Fix

Either:

1. Add missing fields to `Source`/`Destination` (preserving `*string` for `Any`)
2. Embed `RuleLocation` into `Source`/`Destination` and add the `Any *string` field
3. Migrate to using `RuleLocation` directly (breaking change)

---

## 5. Type Mismatches: string vs BoolFlag

### Resolution Status

**Converted to BoolFlag (presence-based — `isset()` in PHP):**

- Rule: Disabled, Quick, Log (security.go) — Phase 2
- NATRule: Disabled, Log (security.go) — Phase 2
- InboundRule: Disabled, Log (security.go) — Phase 2
- System: DisableConsoleMenu (system.go) — Phase 3
- Firmware: Type, Subscription, Reboot (system.go) — Phase 3
- User: Expires, AuthorizedKeys, IPSecPSK, OTPSeed (system.go) — Phase 3
- System.RRD: Enable (system.go) — Phase 3
- Rrd: Enable (services.go) — Phase 3
- OpnSenseDocument: TriggerInitialWizard (opnsense.go) — Phase 3

**Kept as string (value-based — `== "1"` in PHP):**

The following fields use OPNsense MVC value-based semantics where `<field>0</field>` is valid and distinct from absent. `BoolFlag` would incorrectly treat `<field>0</field>` as true (element present), breaking the `== "1"` / `== "0"` distinction. These remain `string`:

### 5a. Security (security.go) — value-based, kept as string

| Struct          | Field             | Type     | Rationale                                   |
| --------------- | ----------------- | -------- | ------------------------------------------- |
| IDS.General     | Enabled           | `string` | MVC field, uses `== "1"` with helper method |
| IDS.General     | Ips               | `string` | MVC field, uses `== "1"` with helper method |
| IDS.General     | Promisc           | `string` | MVC field, uses `== "1"` with helper method |
| IDS.EveLog.HTTP | Enable            | `string` | MVC field, value-based                      |
| IDS.EveLog.HTTP | Extended          | `string` | MVC field, value-based                      |
| IDS.EveLog.HTTP | DumpAllHeaders    | `string` | MVC field, value-based                      |
| IDS.EveLog.TLS  | Enable            | `string` | MVC field, value-based                      |
| IDS.EveLog.TLS  | Extended          | `string` | MVC field, value-based                      |
| IDS.EveLog.TLS  | SessionResumption | `string` | MVC field, value-based                      |
| IPsec.General   | Enabled           | `string` | MVC field, uses `FormatBoolean()`           |
| IPsec.General   | Disablevpnrules   | `string` | MVC field, uses `FormatBoolean()`           |

### 5b. Services (services.go) — value-based, kept as string

| Struct        | Field        | Type     | Rationale                                   |
| ------------- | ------------ | -------- | ------------------------------------------- |
| Unbound       | Enable       | `string` | Heavily used with `== "1"` across 10+ files |
| Monit.General | Enabled      | `string` | MVC field, value-based                      |
| Monit.General | Ssl          | `string` | MVC field, value-based                      |
| Monit.General | Sslverify    | `string` | MVC field, value-based                      |
| Monit.General | HttpdEnabled | `string` | MVC field, value-based                      |
| Monit.Alert   | Enabled      | `string` | MVC field, value-based                      |
| MonitService  | Enabled      | `string` | MVC field, value-based                      |

### 5c. OPNsense module (opnsense.go) — value-based, kept as string

| Struct                 | Field               | Type     | Rationale              |
| ---------------------- | ------------------- | -------- | ---------------------- |
| Kea.Dhcp4.General      | Enabled             | `string` | MVC field, value-based |
| Kea.HighAvailability   | Enabled             | `string` | MVC field, value-based |
| UnboundPlus.General    | Enabled             | `string` | MVC field, value-based |
| UnboundPlus.General    | Stats               | `string` | MVC field, value-based |
| UnboundPlus.General    | Dnssec              | `string` | MVC field, value-based |
| UnboundPlus.General    | DNS64               | `string` | MVC field, value-based |
| UnboundPlus.General    | RegisterDHCP\* (x3) | `string` | MVC field, value-based |
| UnboundPlus.General    | No\* fields (x2)    | `string` | MVC field, value-based |
| UnboundPlus.General    | Txtsupport          | `string` | MVC field, value-based |
| UnboundPlus.General    | Cacheflush          | `string` | MVC field, value-based |
| UnboundPlus.General    | EnableWpad          | `string` | MVC field, value-based |
| UnboundPlus.Dnsbl      | Enabled             | `string` | MVC field, value-based |
| UnboundPlus.Dnsbl      | Safesearch          | `string` | MVC field, value-based |
| UnboundPlus.Forwarding | Enabled             | `string` | MVC field, value-based |
| SyslogInternal.General | Enabled             | `string` | MVC field, value-based |
| Netflow.Capture        | EgressOnly          | `string` | MVC field, value-based |
| Netflow.Collect        | Enable              | `string` | MVC field, value-based |

### 5d. DHCP (dhcp.go) — value-based, kept as string

| Struct         | Field  | Type     | Rationale                                     |
| -------------- | ------ | -------- | --------------------------------------------- |
| DhcpdInterface | Enable | `string` | Value-based (`<enable>1</enable>`), heavy use |

**Note on value-based fields:** These use OPNsense MVC pattern `<field>1</field>` / `<field>0</field>`. Converting to `BoolFlag` would break semantics because `BoolFlag.UnmarshalXML` treats any present element as true, regardless of content — so `<enabled>0</enabled>` would incorrectly become `true`.

---

## 6. NAT Structure Issues

### 6a. NAT XML Path

In OPNsense config.xml, inbound NAT (port forward) rules are at `<nat><rule>`, **not** `<nat><inbound><rule>`. Verify the XML path in the current schema matches.

### 6b. Missing NAT Outbound Rule Fields

| Field              | XML Element                | Type                        |
| ------------------ | -------------------------- | --------------------------- |
| StaticNatPort      | `<staticnatport>`          | `BoolFlag` (presence-based) |
| NoNat              | `<nonat>`                  | `BoolFlag` (presence-based) |
| NatPort            | `<natport>`                | `string`                    |
| PoolOptsSrcHashKey | `<poolopts_sourcehashkey>` | `string`                    |

### 6c. Missing NAT Inbound Rule Fields

| Field            | XML Element            | Type       |
| ---------------- | ---------------------- | ---------- |
| NATReflection    | `<natreflection>`      | `string`   |
| AssociatedRuleID | `<associated-rule-id>` | `string`   |
| NoRDR            | `<nordr>`              | `BoolFlag` |
| NoSync           | `<nosync>`             | `BoolFlag` |
| LocalPort        | `<local-port>`         | `string`   |

### 6d. Outbound NAT Mode Values

| Value       | Meaning                          |
| ----------- | -------------------------------- |
| `automatic` | Automatic outbound NAT (default) |
| `hybrid`    | Hybrid: auto + manual rules      |
| `advanced`  | Manual outbound NAT only         |
| `disabled`  | Disable outbound NAT             |

---

## 7. Key XML Design Decisions

### 7a. Dynamic Interface Keys

The `<interfaces>` section uses dynamic element names (`<wan>`, `<lan>`, `<opt0>`) rather than repeated `<interface name="wan">`. This requires custom unmarshaling in Go. Our map-based approach in `Interfaces` and `Dhcpd` types is correct.

### 7b. Comma-Separated Lists

Several fields pack multiple values into a single element:

- `<interface>wan,lan,opt1</interface>` (floating rules)
- `<icmptype>3,11,0</icmptype>` (ICMP type list)
- Space-separated: `<timeservers>0.ntp.org 1.ntp.org</timeservers>`

Our `InterfaceList` custom type correctly handles the comma-separated case.

### 7c. UUID vs Tracker

- OPNsense: `uuid` attribute on rule elements (`<rule uuid="...">`)
- pfSense: `<tracker>` element (integer, auto-generated from `microtime`)
- Both may be present in migrated configs

### 7d. Legacy vs MVC Model Split

OPNsense maintains two parallel systems:

- **Legacy**: Rules in `<filter><rule>` and `<nat><rule>` (pfSense-compatible)
- **MVC/New-style**: Rules in `<OPNsense><Firewall><Filter>` with `<rules>`, `<snatrules>`, etc.

Both are loaded by `pf_firewall()`. Our schema currently only models the legacy format.

---

## 8. Correctly Implemented Patterns

### 8a. `Source.Any` / `Destination.Any` as `*string`

Go's `encoding/xml` produces `""` for both `<any/>` and absent elements when using plain `string`. Using `*string` correctly distinguishes presence (non-nil) from absence (nil). Validated against `FilterRule.php`'s `isset()` pattern.

### 8b. `BoolFlag` Custom Type

Correctly implements presence-based boolean semantics: `UnmarshalXML` sets true on any element presence, regardless of content.

### 8c. `InterfaceList` Custom Type

Correctly handles comma-separated interface lists for floating rules.

### 8d. `Interfaces` and `Dhcpd` Map Types

Correctly handle dynamic interface element names via custom `UnmarshalXML`/`MarshalXML`.

### 8e. `RuleLocation` Struct

Already has all needed fields for complete source/destination modeling. Just needs to be connected to the actual `Source`/`Destination` types.

---

## 9. Action Items (Priority Order)

01. **CRITICAL**: Add `Address` field to `Source` and `Destination` structs
02. **HIGH**: Add `Not` field (BoolFlag) to `Source` and `Destination`
03. **HIGH**: Add `Port` field to `Source` struct
04. **HIGH**: Add `Log` field (BoolFlag) to `Rule` struct
05. **HIGH**: Convert `Rule.Disabled`, `NATRule.Disabled`, `InboundRule.Disabled` from `string` to `BoolFlag`
06. **HIGH**: Add `Floating`, `Gateway`, `Direction` fields to `Rule`
07. **MEDIUM**: Convert `struct{}` fields in system.go to `BoolFlag`
08. **MEDIUM**: Add rate-limiting fields to `Rule` (max-src-nodes, etc.)
09. **MEDIUM**: Convert IDS/IPsec Enabled fields from `string` to `BoolFlag`
10. **LOW**: Add remaining missing filter rule fields (tag, tagged, DSCP, etc.)
11. **LOW**: Add missing NAT rule fields
