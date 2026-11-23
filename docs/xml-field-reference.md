# XML Field Reference

This reference documents the OPNsense `config.xml` fields that opnDossier parses and validates, with XML examples showing each field's usage. This is useful for understanding how OPNsense represents configuration in XML.

## dnsmasq DNS and DHCP

From 25.1.2 `<dnsmasq>` is the Dnsmasq MVC model and carries a `version` attribute. Every list is written as the item's own element name, repeated directly under `<dnsmasq>`; there is no container element. An empty `<hosts/>` or `<domainoverrides/>` is a placeholder the legacy pages leave once the last entry is deleted, and opnDossier skips it.

```xml
<dnsmasq version="1.0.9">
  <enable>1</enable>
  <dnssec>1</dnssec>
  <port />
  <interface>lan,opt1</interface>
  <dhcp>
    <no_interface>opt2</no_interface>
  </dhcp>
  <hosts uuid="...">
    <host>printer</host>
    <domain>internal</domain>
    <ip>192.168.1.50</ip>
    <hwaddr>aa:bb:cc:dd:ee:01</hwaddr>
    <descr>Printer</descr>
    <aliases>print.internal</aliases>
  </hosts>
  <domainoverrides uuid="...">
    <domain>corp.example</domain>
    <ip>10.9.0.53</ip>
    <port>5353</port>
    <srcip />
  </domainoverrides>
  <dhcp_ranges uuid="...">
    <interface>lan</interface>
    <start_addr>192.168.1.100</start_addr>
    <end_addr>192.168.1.199</end_addr>
  </dhcp_ranges>
  <dhcp_ranges uuid="...">
    <interface>lan</interface>
    <start_addr>::1000</start_addr>
    <end_addr>::2000</end_addr>
    <constructor>lan</constructor>
    <ra_mode>slaac</ra_mode>
  </dhcp_ranges>
  <dhcp_options uuid="...">
    <type>set</type>
    <option>6</option>
    <interface>lan</interface>
    <value>9.9.9.9</value>
  </dhcp_options>
</dnsmasq>
```

`<dnssec>` set to `1` turns DNSSEC validation on, which FIREWALL-058 reads when Unbound is off and dnsmasq answers on port 53; an empty `<port>` means 53 and `0` turns DNS off. A `<hosts>` entry is a host override, and a DHCP reservation too when it has a `<client_id>` or a `<hwaddr>` holding a colon. A range is IPv6 when `<start_addr>` holds a colon. An IPv6 range with `ra-stateless` in its `<ra_mode>` answers stateless DHCPv6 and allocates no address, with or without an `<end_addr>`, so it makes a scope with no `rangeV6`. Any other IPv6 range with no `<end_addr>` only sends router advertisements and makes no scope. An `<end_addr>` makes dnsmasq serve DHCP from the range whatever else `<ra_mode>` holds, `ra-only` included.

The ranges become `dhcp[]` scopes with `source: dnsmasq`, one per interface: the first IPv4 range in `range`, the first IPv6 range in `rangeV6`. A range whose `<interface>` is empty (Any) is served on the interface whose network holds it, or whose prefix its `<constructor>` names, and joins that interface's scope; one that no interface's network holds keeps a scope of its own with an empty `interface` and, in `subnet`, the network dnsmasq assumes for it. An IPv4 range is local when the network of the interface it serves holds its start and its end, or when that interface has no static IPv4 network the config shows (`dhcp`, `pppoe`, or an address only a virtual IP carries), mask or no mask; it is relayed otherwise. Each range is matched on one network: its `<subnet_mask>` when it has one, applied bit by bit as dnsmasq applies it, so a mask narrower than the interface's network narrows what the range serves; else, for a local range, the interface's network; else, for a range on an interface with no static IPv4 network the config shows (`dhcp`, `pppoe`, or an address only a virtual IP carries), the smallest network holding its start and end, since dnsmasq takes the mask from whichever local address holds them and any mask it can use keeps both in one network; else a mask dnsmasq guesses from the address class (/8, /16 or /24), only when the start and the end are in the same class. A relayed range with different classes has no network. dnsmasq accepts only 64 for a constructor and nothing below 64 (`option.c`), so an IPv6 range with any other `<prefix_len>` matches nothing, although the model allows 1 to 64. An IPv6 range is matched on its `<prefix_len>` network (64 when empty) around its start. A range with a `<constructor>` is matched on the /64 around the start dnsmasq builds, the interface's address with the low 64 bits replaced by the range's host part, and dnsmasq builds none on an interface whose prefix is longer than 64. Each address of a reservation goes to one scope: an IPv4 address to the first scope with a local range on a network the config shows that holds it; only when none does, to the first with a range on an interface with no static IPv4 network whose network holds it; and only when none does, to the first with a relayed range whose network holds it; a full IPv6 address to the first scope with a range whose prefix holds it. An address holding only a host part, such as `::50`, goes to every scope with a constructed range. A reservation is attached once to each scope its addresses reach, and only a reservation with no address goes to the one scope with an IPv4 range. A dnsmasq scope counts toward STIG V-206690's limit of two DHCP interfaces only while dnsmasq serves DHCP on its interface; ISC and Kea scopes count whatever their enable flag. A range whose `<mode>` holds `static` serves reservations only and leaves `range` empty. Untagged DHCPv4 `set` options 3, 6, 42 and 44 fill the gateway, DNS, NTP and WINS servers, and other untagged DHCPv4 `set` options become number options. The legacy page before 25.1.2 wrote the same `<hosts>` and `<domainoverrides>` shape, with aliases as `<aliases><item><host/><domain/></item></aliases>` and the port and source address packed into `<ip>` as `ip#port@srcip`.

## Source and Destination Fields

Firewall rule source and destination support multiple addressing modes. The fields `any`, `network`, and `address` are **mutually exclusive** -- only one should be present per source/destination block.

**Address-based rules (IP/CIDR or alias):**

```xml
<source>
  <address>192.168.1.0/24</address>
  <port>1024-65535</port>
</source>
```

**Network-based rules (interface subnet):**

```xml
<source>
  <network>lan</network>
</source>
```

**Negated rules (NOT semantics):**

```xml
<source>
  <not />
  <network>lan</network>
</source>
```

**Any address:**

```xml
<source>
  <any />
</source>
```

**Field priority:** Network > Address > Any (per OPNsense semantics)

## Firewall-Wide Settings

Two `<system>` elements change what the firewall enforces without any rule changing. Both are presence fields: the firewall tests them with `isset()`, so an empty element counts the same as the value the page writes.

```xml
<system>
  <disablefilter>enabled</disablefilter>
  <webgui>
    <protocol>https</protocol>
    <noantilockout>1</noantilockout>
  </webgui>
</system>
```

- `<disablefilter>` ("Disable all packet filtering") turns pf off before any ruleset loads, so no rule, block option or NAT applies. It is read on OPNsense and pfSense as `system.packetFilterDisabled`.
- `<noantilockout>` removes the anti-lockout rule, a quick pass rule to the web GUI port and, with SSH enabled, the SSH port, which both vendors otherwise add ahead of every user rule. On a firewall with no LAN or OPT interface the rule lands on the WAN, and red mode then reports the web GUI and SSH as WAN-exposed. It is read on both vendors as `system.webGui.noAntiLockout`.

## Rules in the Firewall Filter Model

OPNsense keeps a second set of firewall rules under `<OPNsense><Firewall><Filter><rules>`. The "Rules [new]" page of 26.1 and the rules page of 26.7 write them, and the 26.7 default config ships its LAN rules there. opnDossier reads them together with the rules under `<filter>` and reports both in the order the firewall evaluates them: floating rules first, then rules on an interface group by the group's sequence, then rules on one interface, with the filter model's rules ahead of the legacy ones within each. A config the os-firewall plugin saved, at filter model version 1.0.0 to 1.0.2, is ordered as that plugin ordered it, with every rule of the model ahead of the legacy ones.

```xml
<OPNsense>
  <Firewall>
    <Filter version="1.0.6">
      <rules>
        <rule uuid="c3c3c3c3-0000-4000-8000-000000000002">
          <enabled>1</enabled>
          <statetype>keep</statetype>
          <sequence>200</sequence>
          <action>pass</action>
          <quick>1</quick>
          <interface>lan</interface>
          <direction>in</direction>
          <ipprotocol>inet</ipprotocol>
          <protocol>TCP/UDP</protocol>
          <source_net>lan,MGMT_NETS</source_net>
          <source_not>0</source_not>
          <destination_net>WEB_HOSTS,DB_HOSTS</destination_net>
          <destination_not>0</destination_not>
          <destination_port>https</destination_port>
          <log>0</log>
          <description>Inside to the servers</description>
        </rule>
      </rules>
    </Filter>
  </Firewall>
</OPNsense>
```

The rule body differs from the one under `<filter>`. The values are reported in the spelling the legacy rule uses:

| Element                           | In the report                                                                                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `enabled`                         | `disabled` is its opposite; a rule without the element is enabled                                                                                |
| `action`                          | `type`                                                                                                                                           |
| `description`                     | `description`                                                                                                                                    |
| `sequence`                        | decides the rule's place in the list; not reported itself                                                                                        |
| `interface`                       | one name, or several; none means every interface; several, none, or `interfacenot` make the rule floating                                        |
| `protocol`                        | lower case; `any` is reported as no protocol                                                                                                     |
| `statetype`                       | `keep` is `keep state`, and likewise `sloppy`, `modulate` and `synproxy`                                                                         |
| `source_net`, `destination_net`   | an alias, an interface name, an address or `any`, or a list of them                                                                              |
| `interfacenot`                    | the rule applies on every interface but the one named; the others are listed, or none when it names the only one, which reads as every interface |
| `source_not`, `destination_not`   | `negated`                                                                                                                                        |
| `source_port`, `destination_port` | a number, a range or a port alias; a service name such as `https` becomes its number                                                             |
| `icmp6type`                       | type numbers become the names the legacy rule uses                                                                                               |

An element a rule leaves out takes OPNsense's default: enabled, quick, `pass`, `in`, `inet`, `keep state`, any source and any destination. A rule under `<filter>` that leaves out `<type>`, `<direction>`, `<statetype>` or `<quick>` takes the same default (`pass`, and quick unless floating), so a rule reads alike in both stores.

The source NAT, NPT and one-to-one NAT rules of the same model (`<snatrules>`, `<npt>`, `<onetoone>`) are not read.

## Advanced Rule Fields

**Floating rules (interface-independent):**

```xml
<rule>
  <floating>yes</floating>
  <direction>any</direction>
  <interface>wan,lan</interface>
  ...
</rule>
```

Floating rules require a `direction` field (`in`, `out`, or `any`).

**Policy routing:**

```xml
<rule>
  <gateway>WAN_GW</gateway>
  ...
</rule>
```

**State tracking:**

```xml
<rule>
  <statetype>keep state</statetype>
  <statetimeout>3600</statetimeout>
  ...
</rule>
```

Valid state types: `keep state`, `sloppy state`, `modulate state`, `synproxy state`, `none`

A pass rule that leaves `<statetype>` out keeps state on both vendors, and is reported as `keep state`. pfSense's port forward page never writes the element.

## Interface Groups and Uplinks

opnDossier reads these elements to decide which interfaces face the internet. The rules are in [How WAN Interfaces Are Identified](firewall-security-controls-reference.md#how-wan-interfaces-are-identified).

```xml
<opnsense>
  <interfaces>
    <opt1>
      <ipaddr>198.51.100.2</ipaddr>
      <gateway>ISP2_GW</gateway>
      <ipaddrv6>dhcp6</ipaddrv6>
    </opt1>
    <UPLINKS>
      <virtual>1</virtual>
      <type>group</type>
    </UPLINKS>
  </interfaces>
  <ifgroups version="1.0.0">
    <ifgroupentry uuid="...">
      <ifname>UPLINKS</ifname>
      <members>wan,opt1</members>
      <descr>Internet uplinks</descr>
    </ifgroupentry>
  </ifgroups>
</opnsense>
```

- `<ipaddr>` marks an uplink when it is `dhcp`, `pppoe`, `pptp`, `l2tp` or `ppp`; `<ipaddrv6>` when it is `dhcp6`, `slaac`, `6rd` or `6to4`. `track6` does not count.
- `<gateway>` and `<gatewayv6>` select an upstream gateway. A gateway counts for the interface it is defined on (`<gateway_item><interface>` under `<OPNsense><Gateways>` or `<gateways>`).
- The `<UPLINKS>` entry is the one OPNsense writes under `<interfaces>` for each group. It is never an uplink itself.
- `<members>` is comma-separated; older releases wrote it space-separated, and both read the same. A rule or port forward whose `<interface>` names the group applies on every member.

## Rate-Limiting and DoS Protection

**Connection limits:**

```xml
<rule>
  <max-src-nodes>100</max-src-nodes>
  <max-src-conn>10</max-src-conn>
  <max-src-conn-rate>15/5</max-src-conn-rate>
  <max-src-conn-rates>300</max-src-conn-rates>
  ...
</rule>
```

The `max-src-conn-rate` field uses the format `connections/seconds` (e.g., `15/5` means 15 connections per 5 seconds).

**TCP flags matching:**

```xml
<rule>
  <tcpflags1>syn</tcpflags1>
  <tcpflags2>syn,ack</tcpflags2>
  ...
</rule>
```

**ICMP type filtering:**

```xml
<rule>
  <protocol>icmp</protocol>
  <icmptype>3,11,0</icmptype>
  ...
</rule>
```

## SNMP Agent

On OPNsense from 19.1 the SNMP agent is the os-net-snmp plugin. opnDossier reads it from `<OPNsense><netsnmp>`, pinned to the general model versions the plugin has shipped, 1.0.0, 1.0.1 and 1.0.3 to 1.0.7 (it never used 1.0.2), and to user model versions 1.0.0 and 1.0.1. The agent runs only with `<enabled>1</enabled>`, compared as raw text, so an absent or empty element is off. A user is loaded only with its own `<enabled>1</enabled>`, and `<readwrite>1</readwrite>` gives it read-write access. `<password>` and `<enckey>` are not read.

```xml
<OPNsense>
  <netsnmp>
    <general version="1.0.7">
      <enabled>1</enabled>
      <community>s3cret</community>
      <syslocation>rack 4</syslocation>
      <syscontact>noc</syscontact>
      <listen>192.0.2.1,2001:db8::1</listen>
    </general>
    <user version="1.0.1">
      <users>
        <user uuid="...">
          <enabled>1</enabled>
          <username>monitor</username>
          <password>...</password>
          <enckey>...</enckey>
          <readwrite>0</readwrite>
        </user>
      </users>
    </user>
  </netsnmp>
</OPNsense>
```

The legacy top-level `<snmpd>` starts an agent only when it carries `<enable>`, tested for presence, so `<enable/>` counts. That holds on pfSense and on OPNsense up to 18.7; OPNsense 19.1 and later run nothing from it, and opnDossier still reports it there, with a warning, when net-snmp is not enabled.

```xml
<snmpd>
  <syslocation />
  <syscontact />
  <rocommunity>public</rocommunity>
  <enable />
</snmpd>
```

## NAT Rule Enhancements

**Outbound NAT with port preservation:**

```xml
<rule>
  <staticnatport />
  <natport>1024-65535</natport>
  <poolopts_sourcehashkey>0x12345678</poolopts_sourcehashkey>
  ...
</rule>
```

**NAT exclusion:**

```xml
<rule>
  <nonat />
  ...
</rule>
```

**Inbound NAT (port forward) with reflection:**

Port forwards are `<rule>` elements directly under `<nat>`. `<target>` is the redirect address and `<local-port>` the redirect port; the port the rule matches on is `<destination><port>`.

The example is the shape written through 25.7. From 26.1 each rule also has a `uuid` attribute and a `<sequence>`, and `<pass>` holds the filter rule association while `<associated-rule-id>` is written empty.

```xml
<nat>
  <rule>
    <destination>
      <network>wanip</network>
      <port>443</port>
    </destination>
    <target>192.168.1.50</target>
    <local-port>8080</local-port>
    <natreflection>purenat</natreflection>
    <associated-rule-id>nat_5f1234567890ab.12345678</associated-rule-id>
    ...
  </rule>
</nat>
```

A forward's `<natreflection>` decides reflection for that forward. An empty value takes the global `<system><disablenatreflection>` setting, `disable` turns reflection off, and `purenat` or `enable` turns it on even when reflection is disabled globally (OPNsense `ForwardRule.php`, pfSense `filter.inc`). OPNsense fills the global default into any value `empty()` accepts from 26.1, and only into an absent element up to 25.7; pfSense's GUI saves "Use system default" by removing the element. `nat.reflectionDisabled` in the export, which FIREWALL-056 and the NAT Summary read, is true only when reflection is disabled globally and no enabled, redirecting forward sets `purenat` or `enable`. Disabled and no-RDR forwards do not count. `system.disableNatReflection` reports the global setting as written.

Valid NAT reflection modes: `enable`, `disable`, `purenat`

## Related

- [Configuration Reference](user-guide/configuration-reference.md) -- opnDossier flags and options
- [Firewall Security Controls](firewall-security-controls-reference.md) -- firewall best practices
