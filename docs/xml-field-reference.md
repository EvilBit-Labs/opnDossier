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

`<dnssec>` set to `1` turns DNSSEC validation on, which FIREWALL-058 reads when Unbound is off and dnsmasq answers on port 53; an empty `<port>` means 53 and `0` turns DNS off. A `<hosts>` entry is a host override, and a DHCP reservation too when it has a `<client_id>` or a `<hwaddr>` holding a colon. A range is IPv6 when `<start_addr>` holds a colon, and an IPv6 range with no `<end_addr>` only sends router advertisements, so it makes no scope.

The ranges become `dhcp[]` scopes with `source: dnsmasq`, one per interface: the first IPv4 range in `range`, the first IPv6 range in `rangeV6`. A range whose `<mode>` holds `static` serves reservations only and leaves `range` empty. Untagged DHCPv4 `set` options 3, 6, 42 and 44 fill the gateway, DNS, NTP and WINS servers, and other untagged DHCPv4 `set` options become number options. The legacy page before 25.1.2 wrote the same `<hosts>` and `<domainoverrides>` shape, with aliases as `<aliases><item><host/><domain/></item></aliases>` and the port and source address packed into `<ip>` as `ip#port@srcip`.

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

Valid NAT reflection modes: `enable`, `disable`, `purenat`

## Related

- [Configuration Reference](user-guide/configuration-reference.md) -- opnDossier flags and options
- [Firewall Security Controls](firewall-security-controls-reference.md) -- firewall best practices
