# XML Field Reference

This reference documents the OPNsense `config.xml` fields that opnDossier parses and validates, with XML examples showing each field's usage. This is useful for understanding how OPNsense represents configuration in XML.

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

## Remote Logging and Retention

From 20.1, OPNsense forwards logs only to the destinations of the Syslog model. A destination forwards when `<enabled>` is `1` and `<transport>` is one of `udp4`, `tcp4`, `udp6`, `tcp6`, `tls4` or `tls6`; `<program>`, `<level>` and `<facility>` are comma-separated filters that must all match, and an empty one matches every message. Remote servers left under the legacy `<syslog>` block (`<enable>`, `<remoteserver>`) are not read when the model is present, and opnDossier warns about them.

```xml
<OPNsense>
  <Syslog version="1.0.3">
    <general>
      <enabled>1</enabled>
      <loglocal>1</loglocal>
      <maxpreserve>31</maxpreserve>
      <maxfilesize />
    </general>
    <destinations>
      <destination uuid="5b0c3f7e-1d2a-4c5b-9e8f-0a1b2c3d4e5f">
        <enabled>1</enabled>
        <transport>udp4</transport>
        <program />
        <level />
        <facility />
        <hostname>10.0.0.50</hostname>
        <port>514</port>
        <description>SIEM</description>
      </destination>
    </destinations>
  </Syslog>
</OPNsense>
```

Local retention is read from where each release keeps it: `<syslog><logfilesize>` (bytes, default 511488) for the circular logs up to 21.7, `<syslog><preservelogs>` (days, default 31) and, on 24.1, `<syslog><maxfilesize>` (MB) for the daily archives up to 24.1, and `<general><maxpreserve>` and `<general><maxfilesize>` from 24.7.

## Related

- [Configuration Reference](user-guide/configuration-reference.md) -- opnDossier flags and options
- [Firewall Security Controls](firewall-security-controls-reference.md) -- firewall best practices
