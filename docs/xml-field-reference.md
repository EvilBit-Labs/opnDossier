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

Valid state types: `keep state`, `sloppy state`, `synproxy state`, `none`

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

**Inbound NAT with reflection:**

```xml
<rule>
  <natreflection>enable</natreflection>
  <associated-rule-id>5f1234567890abcd</associated-rule-id>
  <local-port>8080</local-port>
  ...
</rule>
```

Valid NAT reflection modes: `enable`, `disable`, `purenat`

## Related

- [Configuration Reference](user-guide/configuration-reference.md) -- opnDossier flags and options
- [Firewall Security Controls](firewall-security-controls-reference.md) -- firewall best practices
