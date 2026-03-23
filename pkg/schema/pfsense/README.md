# pfSense Configuration Schema

This package defines Go structs for parsing pfSense `config.xml` files. It follows the copy-on-write pattern described in AGENTS.md: reuse OPNsense types where XML structures are identical, fork locally at first divergence.

## Config Versions

| pfSense CE | Plus  | Config Rev | FreeBSD      |
| ---------- | ----- | ---------- | ------------ |
| 2.5.x      | 21.02 | 21.4-21.7  | 12.2-STABLE  |
| 2.6.0      | 22.01 | 22.2       | 12.3-STABLE  |
| 2.7.0      | 23.05 | 22.9       | 14.0-CURRENT |
| 2.8.0      | 25.07 | 24.0       | 15.0-CURRENT |

CE and Plus share the same config format at corresponding releases. Config upgrades are sequential, handled by `upgrade_NNN_to_NNN()` functions in the pfSense source (`upgrade_config.inc`).

## Root Element

The root XML element is `<pfsense>` (vs OPNsense's `<opnsense>`).

## Key Structural Differences from OPNsense

| Area                  | pfSense                                                | OPNsense                             |
| --------------------- | ------------------------------------------------------ | ------------------------------------ |
| Root element          | `<pfsense>`                                            | `<opnsense>`                         |
| NAT port forwards     | `<nat><rule>` (direct child)                           | `<nat><inbound><rule>` (nested)      |
| NAT redirect IP field | `<target>`                                             | `<internalip>`                       |
| NAT 1:1 / NPt         | `<nat><onetoone>`, `<nat><npt>`                        | Different location                   |
| User passwords        | `<bcrypt-hash>`                                        | `<password>` (SHA-based)             |
| User privileges       | `<priv>[]` per-user array                              | Group-based model                    |
| DNS servers           | `<dnsserver>[]` (repeating elements)                   | Single `<dnsserver>` string          |
| Aliases               | Flat `aliases/alias[]`                                 | UUID-based `OPNsense/Firewall/Alias` |
| Captive portal        | Zone-keyed map                                         | Completely different implementation  |
| Traffic shaping       | ALTQ + dummynet                                        | Different model in newer OPNsense    |
| Auth servers          | `system/authserver[]`                                  | Different location                   |
| Notifications         | `system/notifications` (SMTP/Telegram/etc.)            | Different system                     |
| Filter rules          | Adds `id`, `tag`, `tagged`, `os`, `associated-rule-id` | Does not have these                  |
| Config version        | Decimal (22.9, 24.0)                                   | Different numbering                  |
| CRL                   | Top-level `<crl>[]`                                    | Integrated differently               |
| Kea DHCP              | `<kea>` / `<kea6>` (newer versions)                    | Not present                          |

## listtags (XML Array Elements)

From pfSense's `xmlparse.inc`, these elements are always parsed as arrays even with a single entry. In Go, these must use `[]Type`, never `Type`:

```text
alias, authserver, bridged, ca, cert, crl, dnsserver, domainoverrides,
dyndns, gateway_item, gateway_group, gif, gre, group, hosts,
ifgroupentry, igmpentry, item, lagg, member, mobilekey, monitor_type,
npt, onetoone, openvpn-server, openvpn-client, openvpn-csc, phase1,
phase2, pool, ppp, pppoe, priv, qinqentry, queue, route, rule,
schedule, shellcmd, staticmap, timerange, user, vip, virtual_server,
vlan, wolentry
```

## Complete Top-Level Section Inventory

### Implemented in This Package

| Section                    | File          | Reuses OPNsense?              | Notes                                                                          |
| -------------------------- | ------------- | ----------------------------- | ------------------------------------------------------------------------------ |
| `<pfsense>` root           | `document.go` | Partial                       | Root document with all top-level fields                                        |
| `system`                   | `system.go`   | Partial (Group, SSHConfig)    | pfSense-specific User, WebGUI, DNS arrays                                      |
| `interfaces`               | `document.go` | Yes (full)                    | Map-based, identical structure                                                 |
| `filter`                   | `security.go` | Partial (Source, Destination) | pfSense-specific FilterRule                                                    |
| `nat` (inbound + outbound) | `security.go` | Outbound reused               | Inbound forked for `<target>` vs `<internalip>`                                |
| `dhcpd`                    | `document.go` | Yes (full)                    | Identical map-based structure                                                  |
| `dhcpdv6`                  | `network.go`  | No (pfSense-specific)         | Map-based with RAMode, RAPriority                                              |
| `snmpd`                    | `document.go` | Yes (full)                    | Identical                                                                      |
| `openvpn`                  | `document.go` | Yes (full)                    | Client + server arrays                                                         |
| `syslog`                   | `services.go` | No (pfSense-specific)         | Currently minimal                                                              |
| `unbound`                  | `services.go` | No (pfSense-specific)         | Core fields                                                                    |
| `cron`                     | `services.go` | No (pfSense-specific)         | `item[]` array                                                                 |
| `widgets`                  | `services.go` | No (pfSense-specific)         | Adds Period field                                                              |
| `diag`                     | `services.go` | No (pfSense-specific)         | IPv6NAT only                                                                   |
| `rrd`                      | `document.go` | Yes (full)                    | Enable flag                                                                    |
| `load_balancer`            | `document.go` | Yes (full)                    | Deprecated in pfSense 2.8+                                                     |
| `staticroutes`             | `document.go` | Yes (full)                    | Identical                                                                      |
| `ppps`                     | `document.go` | Yes (full)                    | Identical base                                                                 |
| `gateways`                 | `document.go` | Yes (full)                    | Identical base                                                                 |
| `ca[]` / `cert[]`          | `document.go` | Yes (full)                    | Top-level arrays                                                               |
| `vlans`                    | `document.go` | Yes (full)                    | Identical                                                                      |
| `revision`                 | `document.go` | Yes (full)                    | Identical                                                                      |
| `ipsec`                    | `vpn.go`      | Partial (`BoolFlag`)          | `phase1[]`, `phase2[]` listtags; `client` mobile config; `logging` sub-element |

### Not Yet Implemented

#### High Priority (common in production configs)

##### `<aliases>` -- Firewall Aliases

Path: `aliases/alias[]`

| Field        | Type     | Description                                                    |
| ------------ | -------- | -------------------------------------------------------------- |
| `name`       | string   | Alias identifier (alphanumeric + underscore)                   |
| `type`       | string   | `host`, `network`, `port`, `url`, `urltable`, `urltable_ports` |
| `address`    | string   | Space-separated IPs/networks/ports/FQDNs                       |
| `descr`      | string   | Description                                                    |
| `detail`     | string   | Per-entry descriptions (pipe-pipe delimited)                   |
| `url`        | string   | URL source (for urltable types)                                |
| `updatefreq` | string   | Update frequency in days (urltable types)                      |
| `aliasurl`   | string[] | Array of alias URLs (alternative to single url)                |

OPNsense difference: OPNsense stores aliases at `OPNsense/Firewall/Alias` with a UUID-based model. pfSense uses a flat `aliases/alias[]` array.

##### `<virtualip>` -- Virtual IPs (CARP/Alias/ProxyARP)

Path: `virtualip/vip[]`

| Field         | Type     | Description                                     |
| ------------- | -------- | ----------------------------------------------- |
| `mode`        | string   | `ipalias`, `carp`, `proxyarp`, `other`          |
| `interface`   | string   | Network interface                               |
| `vhid`        | string   | Virtual Host ID (1-255, CARP only)              |
| `advskew`     | string   | Advertisement skew (0-254, CARP only)           |
| `advbase`     | string   | Advertisement base frequency (1-254, CARP only) |
| `password`    | string   | CARP cluster password                           |
| `subnet`      | string   | IP address                                      |
| `subnet_bits` | string   | CIDR prefix                                     |
| `type`        | string   | `single` or `network`                           |
| `descr`       | string   | Description                                     |
| `uniqid`      | string   | Unique identifier                               |
| `noexpand`    | presence | Disable NAT list expansion                      |

Reusable: nearly identical to OPNsense's `virtualip/vip[]`.

##### `<hasync>` -- High Availability Sync

Path: `hasync/`

| Field                             | Type   | Description                      |
| --------------------------------- | ------ | -------------------------------- |
| `pfsyncenabled`                   | string | State sync enable (`on`/`false`) |
| `pfsyncinterface`                 | string | pfsync interface                 |
| `pfsyncpeerip`                    | string | Peer IP                          |
| `pfhostid`                        | string | Host ID                          |
| `synchronizetoip`                 | string | XMLRPC target IP                 |
| `username`                        | string | XMLRPC username                  |
| `password`                        | string | XMLRPC password                  |
| `adminsync`                       | string | Admin sync flag                  |
| `synchronizeusers`                | string | Sync users                       |
| `synchronizeauthservers`          | string | Sync auth servers                |
| `synchronizecerts`                | string | Sync certificates                |
| `synchronizerules`                | string | Sync firewall rules              |
| `synchronizeschedules`            | string | Sync schedules                   |
| `synchronizealiases`              | string | Sync aliases                     |
| `synchronizenat`                  | string | Sync NAT                         |
| `synchronizeipsec`                | string | Sync IPsec                       |
| `synchronizeopenvpn`              | string | Sync OpenVPN                     |
| `synchronizedhcpd`                | string | Sync DHCP server                 |
| `synchronizedhcrelay`             | string | Sync DHCP relay                  |
| `synchronizekea6`                 | string | Sync Kea DHCPv6                  |
| `synchronizedhcrelay6`            | string | Sync DHCPv6 relay                |
| `synchronizewol`                  | string | Sync WOL                         |
| `synchronizestaticroutes`         | string | Sync static routes               |
| `synchronizevirtualip`            | string | Sync Virtual IPs                 |
| `synchronizetrafficshaper`        | string | Sync ALTQ shaper                 |
| `synchronizetrafficshaperlimiter` | string | Sync limiters                    |
| `synchronizednsforwarder`         | string | Sync DNS forwarder               |
| `synchronizecaptiveportal`        | string | Sync captive portal              |

All boolean fields store `on` or `false`.

##### `<bridges>` -- Bridge Interfaces

Path: `bridges/bridged[]`

| Field          | Type     | Description                                |
| -------------- | -------- | ------------------------------------------ |
| `bridgeif`     | string   | Bridge interface name (e.g., `bridge0`)    |
| `members`      | string   | Comma-separated interface list             |
| `descr`        | string   | Description                                |
| `enablestp`    | presence | RSTP/STP support                           |
| `ip6linklocal` | presence | IPv6 auto link-local                       |
| `maxaddr`      | string   | Address cache size                         |
| `timeout`      | string   | Cache expiration (seconds)                 |
| `maxage`       | string   | STP config validity                        |
| `fwdelay`      | string   | STP forward delay                          |
| `hellotime`    | string   | STP hello interval                         |
| `priority`     | string   | Bridge STP priority                        |
| `proto`        | string   | `rstp` or `stp`                            |
| `holdcnt`      | string   | STP transmit hold count                    |
| `ifpriority`   | string   | Comma-separated `interface:priority` pairs |
| `ifpathcost`   | string   | Comma-separated `interface:cost` pairs     |
| `stp`          | string   | Comma-separated STP-enabled interfaces     |
| `span`         | string   | Comma-separated span ports                 |
| `edge`         | string   | Comma-separated edge ports                 |
| `autoedge`     | string   | Comma-separated auto-edge                  |
| `ptp`          | string   | Comma-separated point-to-point             |
| `autoptp`      | string   | Comma-separated auto-PTP                   |
| `static`       | string   | Comma-separated sticky ports               |
| `private`      | string   | Comma-separated private ports              |

Reusable: very similar to OPNsense's `bridges/bridged[]`.

##### `<gifs>` -- GIF Tunnels

Path: `gifs/gif[]`

| Field                 | Type     | Description                   |
| --------------------- | -------- | ----------------------------- |
| `if`                  | string   | Parent interface              |
| `gifif`               | string   | GIF interface identifier      |
| `remote-addr`         | string   | Peer encapsulation address    |
| `tunnel-local-addr`   | string   | Local tunnel endpoint         |
| `tunnel-remote-addr`  | string   | Remote tunnel endpoint        |
| `tunnel-remote-net`   | string   | Subnet prefix (1-32 or 1-128) |
| `tunnel-local-addr6`  | string   | IPv6 local tunnel             |
| `tunnel-remote-addr6` | string   | IPv6 remote tunnel            |
| `tunnel-remote-net6`  | string   | IPv6 prefix                   |
| `link1`               | presence | ECN friendly behavior         |
| `link2`               | presence | Outer source filtering        |
| `descr`               | string   | Description                   |

Reusable: nearly identical to OPNsense.

##### `<gres>` -- GRE Tunnels

Path: `gres/gre[]`

Same structure as GIF tunnels but uses `greif` instead of `gifif`, and adds `link0`.

Reusable: nearly identical to OPNsense.

##### `<laggs>` -- Link Aggregation

Path: `laggs/lagg[]`

| Field            | Type   | Description                                             |
| ---------------- | ------ | ------------------------------------------------------- |
| `laggif`         | string | LAGG interface name (e.g., `lagg0`)                     |
| `members`        | string | Comma-separated physical interfaces                     |
| `proto`          | string | `none`, `lacp`, `failover`, `loadbalance`, `roundrobin` |
| `descr`          | string | Description                                             |
| `failovermaster` | string | Primary failover interface or `auto`                    |
| `lacptimeout`    | string | `slow` or `fast`                                        |
| `lagghash`       | string | Hash algorithm for load balancing                       |

OPNsense difference: pfSense adds `failovermaster` and `lagghash`.

##### `<crl>` -- Certificate Revocation Lists

Path: `crl[]` (top-level array, repeating)

| Field      | Type   | Description                                              |
| ---------- | ------ | -------------------------------------------------------- |
| `refid`    | string | Unique identifier                                        |
| `caref`    | string | Parent CA reference                                      |
| `descr`    | string | Description                                              |
| `method`   | string | `internal` or `existing`                                 |
| `text`     | string | Base64-encoded CRL (imported)                            |
| `lifetime` | string | Validity (days)                                          |
| `serial`   | string | Serial number                                            |
| `cert[]`   | array  | Revoked certs: `refid`, `descr`, `reason`, `revoke_time` |

##### `nat/onetoone[]` -- 1:1 NAT (BiNAT)

| Field             | Type   | Description         |
| ----------------- | ------ | ------------------- |
| `interface`       | string | Interface           |
| `ipprotocol`      | string | `inet` / `inet6`    |
| `external`        | string | External address    |
| `src` / `srcmask` | string | Source network      |
| `srcnot`          | string | Negate source       |
| `dst` / `dstmask` | string | Destination network |
| `dstnot`          | string | Negate destination  |
| `nobinat`         | string | Disable binat       |
| `natreflection`   | string | Reflection mode     |
| `disabled`        | string | Disable flag        |
| `descr`           | string | Description         |

##### `nat/npt[]` -- IPv6 Network Prefix Translation

| Field             | Type   | Description        |
| ----------------- | ------ | ------------------ |
| `interface`       | string | Interface          |
| `src` / `srcmask` | string | Internal prefix    |
| `srcnot`          | string | Negate source      |
| `dst` / `dstmask` | string | External prefix    |
| `dstnot`          | string | Negate destination |
| `disabled`        | string | Disable flag       |
| `descr`           | string | Description        |

##### `<ntpd>` -- NTP Daemon

Path: `ntpd/`

| Field                                    | Type     | Description                          |
| ---------------------------------------- | -------- | ------------------------------------ |
| `enable`                                 | presence | Enable NTP                           |
| `interface`                              | string   | Listening interfaces                 |
| `prefer`                                 | string   | Preferred servers                    |
| `noselect`                               | string   | Excluded servers                     |
| `ispool`                                 | string   | Pool-type servers                    |
| `ispeer`                                 | string   | Peer-type servers                    |
| `ntpminpoll` / `ntpmaxpoll`              | string   | Poll intervals                       |
| `ntpmaxpeers`                            | string   | Max pool peers                       |
| `orphan`                                 | string   | Orphan stratum                       |
| `dnsresolv`                              | string   | DNS protocol (`auto`/`inet`/`inet6`) |
| `logpeer` / `logsys`                     | presence | Logging                              |
| `clockstats` / `loopstats` / `peerstats` | presence | Statistics                           |
| `statsgraph`                             | presence | RRD graphs                           |
| `serverauth`                             | presence | NTPv3 auth                           |
| `serverauthkey`                          | string   | Base64 auth key                      |
| `serverauthkeyid`                        | string   | Key ID (1-65535)                     |
| `serverauthalgo`                         | string   | `md5`/`sha1`/`sha256`                |
| `gps/port`                               | string   | GPS serial port                      |
| `gps/speed`                              | string   | GPS baud rate                        |
| `pps/port`                               | string   | PPS serial port                      |

Note: time servers are at `system/timeservers` (space-separated), not under `ntpd/`.

##### `<dnsmasq>` -- DNS Forwarder

Path: `dnsmasq/`

| Field                | Type     | Description                                                       |
| -------------------- | -------- | ----------------------------------------------------------------- |
| `enable`             | presence | Enable forwarder                                                  |
| `port`               | string   | Listen port                                                       |
| `interface`          | string   | Listening interfaces                                              |
| `regdhcp`            | presence | Register DHCP leases                                              |
| `regdhcpstatic`      | presence | Register static DHCP                                              |
| `dhcpfirst`          | presence | DHCP before static                                                |
| `strict_order`       | presence | Strict query ordering                                             |
| `domain_needed`      | presence | Require domain for queries                                        |
| `no_private_reverse` | presence | No reverse for private IPs                                        |
| `no_system_dns`      | presence | Ignore system DNS                                                 |
| `strictbind`         | presence | Strict interface binding                                          |
| `custom_options`     | string   | Raw dnsmasq config                                                |
| `hosts[]`            | array    | Host overrides: `host`, `domain`, `ip`, `descr`, `aliases/item[]` |
| `domainoverrides[]`  | array    | Domain overrides: `domain`, `ip`, `dnssrcip`, `descr`             |

##### `system/authserver[]` -- Authentication Servers

| Field   | Type   | Description        |
| ------- | ------ | ------------------ |
| `refid` | string | Unique identifier  |
| `name`  | string | Server name        |
| `type`  | string | `ldap` or `radius` |
| `host`  | string | Server address     |

LDAP-specific: `ldap_caref`, `ldap_port`, `ldap_urltype`, `ldap_protver`, `ldap_scope`, `ldap_basedn`, `ldap_authcn`, `ldap_binddn`, `ldap_bindpw`, `ldap_timeout`, `ldap_attr_user`, `ldap_attr_group`, `ldap_attr_member`, `ldap_attr_groupobj`, `ldap_pam_groupdn`, `ldap_extended_enabled`, `ldap_extended_query`, `ldap_utf8`, `ldap_nostrip_at`, `ldap_allow_unauthenticated`, `ldap_rfc2307`, `ldap_rfc2307_userdn`, `ldap_rfc2307_basedn_groups`.

RADIUS-specific: `radius_protocol`, `radius_secret`, `radius_nasip_attribute`, `radius_auth_port`, `radius_acct_port`, `radius_timeout`, `disable_radius_msg_auth`.

##### `system/notifications` -- Notification Channels

| Sub-section | Fields                                                                                                                                   |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `smtp`      | `disable`, `ipaddress`, `port`, `timeout`, `ssl`, `sslvalidate`, `fromaddress`, `notifyemailaddress`, `username`, `password`, `authmech` |
| `telegram`  | `enable`, `api`, `chatid`                                                                                                                |
| `pushover`  | `enable`, `apikey`, `userkey`, `sound`, `priority`, `retry`, `expire`                                                                    |
| `slack`     | `enable`, `api`, `channel`                                                                                                               |

##### `system/sysctl/item[]` -- Kernel Tunables

| Field     | Type   | Description                                 |
| --------- | ------ | ------------------------------------------- |
| `tunable` | string | Sysctl key (e.g., `net.inet.ip.forwarding`) |
| `value`   | string | Sysctl value                                |
| `descr`   | string | Description                                 |

#### Medium Priority

##### `<captiveportal>` -- Captive Portal

Zone-keyed map (NOT an array). Each child element is a zone name:

| Field                          | Type     | Description                    |
| ------------------------------ | -------- | ------------------------------ |
| `enable`                       | presence | Enable zone                    |
| `zoneid`                       | string   | Numeric zone identifier        |
| `descr`                        | string   | Description                    |
| `interface`                    | string   | Interface(s)                   |
| `timeout`                      | string   | Hard timeout (minutes)         |
| `idletimeout`                  | string   | Idle timeout (minutes)         |
| `trafficquota`                 | string   | Megabytes                      |
| `auth_method`                  | string   | `none`, `authserver`, `radmac` |
| `auth_server` / `auth_server2` | string   | Comma-separated servers        |
| `httpslogin`                   | presence | HTTPS login                    |
| `certref`                      | string   | Certificate reference          |
| `preauthurl`                   | string   | Pre-auth URL                   |
| `redirurl`                     | string   | Redirect URL                   |
| `bwdefaultdn` / `bwdefaultup`  | string   | Default bandwidth (Kbit/s)     |
| `noconcurrentlogins`           | presence | No concurrent logins           |
| `termsconditions`              | string   | Base64-encoded terms           |
| `page/htmltext`                | string   | Base64-encoded portal page     |
| `page/errtext`                 | string   | Base64-encoded error page      |
| `page/logouttext`              | string   | Base64-encoded logout page     |
| `element[]`                    | array    | Uploaded files                 |
| `allowedip[]`                  | array    | Allowed IP entries             |
| `allowedhostname[]`            | array    | Allowed hostname entries       |
| `passthrumac[]`                | array    | Passthrough MAC entries        |

##### `<shaper>` -- ALTQ Traffic Shaping

Path: `shaper/queue[]` (recursive hierarchy)

Root queue:

| Field           | Type   | Description                              |
| --------------- | ------ | ---------------------------------------- |
| `interface`     | string | Interface                                |
| `name`          | string | Queue name                               |
| `scheduler`     | string | `HFSC`, `CBQ`, `FAIRQ`, `CODELQ`, `PRIQ` |
| `bandwidth`     | string | Numeric capacity                         |
| `bandwidthtype` | string | `b`, `Kb`, `Mb`, `Gb`, `%`               |
| `qlimit`        | string | Max queue depth (packets)                |
| `tbrconfig`     | string | Token bucket regulator (bytes)           |
| `enabled`       | string | `on` or empty                            |

Child queue (adds to root):

| Field                           | Type     | Description                       |
| ------------------------------- | -------- | --------------------------------- |
| `priority`                      | string   | 0-15 (PRIQ) or 0-7 (CBQ/FAIRQ)    |
| `description`                   | string   | Admin text                        |
| `default`                       | presence | Default queue flag                |
| `red` / `rio` / `ecn` / `codel` | presence | AQM toggles                       |
| `borrow`                        | presence | CBQ bandwidth borrowing           |
| `linkshare1,2,3`                | string   | HFSC link share curve (m1, d, m2) |
| `realtime1,2,3`                 | string   | HFSC real-time curve              |
| `upperlimit1,2,3`               | string   | HFSC upper limit curve            |
| `queue[]`                       | nested   | Child queues (recursive)          |

##### `<dnshaper>` -- Dummynet Limiters

Path: `dnshaper/queue[]`

| Field                       | Type   | Description                               |
| --------------------------- | ------ | ----------------------------------------- |
| `name`                      | string | Pipe identifier                           |
| `number`                    | string | Dummynet pipe number                      |
| `bandwidth`                 | string | Capacity                                  |
| `bandwidthtype`             | string | Scale                                     |
| `qlimit`                    | string | Queue size (packets)                      |
| `plr`                       | string | Packet loss rate (0-1)                    |
| `delay`                     | string | Latency (ms)                              |
| `buckets`                   | string | Hash table entries                        |
| `sched`                     | string | `wf2q+`, `fifo`, `qfq`, `rr`, `prio`      |
| `aqm`                       | string | `droptail`, `codel`, `pie`, `red`, `gred` |
| `enabled`                   | string | Activation                                |
| `mask/type`                 | string | `srcaddress`, `dstaddress`, `none`        |
| `mask/bits` / `mask/bitsv6` | string | CIDR prefix                               |
| `queue[]`                   | nested | Child queues                              |

##### `<schedules>` -- Firewall Schedules

Path: `schedules/schedule[]`

| Field         | Type   | Description                                      |
| ------------- | ------ | ------------------------------------------------ |
| `name`        | string | Schedule identifier                              |
| `descr`       | string | Description                                      |
| `schedlabel`  | string | Label                                            |
| `timerange[]` | array  | `position`, `month`, `day`, `hour`, `rangedescr` |

##### `<dyndnses>` -- Dynamic DNS

Path: `dyndnses/dyndns[]`

| Field           | Type     | Description                |
| --------------- | -------- | -------------------------- |
| `enable`        | presence | Enable entry               |
| `type`          | string   | Provider identifier        |
| `interface`     | string   | Source interface           |
| `host`          | string   | Hostname to update         |
| `domainname`    | string   | Domain name                |
| `username`      | string   | Provider username          |
| `password`      | string   | Provider password (base64) |
| `wildcard`      | string   | Wildcard DNS               |
| `proxied`       | string   | CDN proxied (Cloudflare)   |
| `zoneid`        | string   | Zone ID (Cloudflare)       |
| `ttl`           | string   | TTL value                  |
| `updateurl`     | string   | Custom update URL          |
| `resultmatch`   | string   | Custom result regex        |
| `check_ip_mode` | string   | IP detection method        |
| `descr`         | string   | Description                |

##### `<dhcrelay>` / `<dhcrelay6>` -- DHCP Relay

| Field           | Type     | Description                           |
| --------------- | -------- | ------------------------------------- |
| `enable`        | presence | Enable relay                          |
| `interface`     | string   | Comma-separated downstream interfaces |
| `server`        | string   | Comma-separated upstream server IPs   |
| `agentoption`   | presence | Append circuit/agent ID               |
| `carpstatusvip` | string   | CARP VIP for status                   |

Note: DHCP relay and DHCP server are mutually exclusive.

##### `<ifgroups>` -- Interface Groups

Path: `ifgroups/ifgroupentry[]`

| Field     | Type   | Description                |
| --------- | ------ | -------------------------- |
| `ifname`  | string | Group name                 |
| `members` | string | Comma-separated interfaces |
| `descr`   | string | Description                |

Reusable: identical to OPNsense.

##### `<qinqs>` -- QinQ (802.1ad)

Path: `qinqs/qinqentry[]`

| Field      | Type   | Description                     |
| ---------- | ------ | ------------------------------- |
| `if`       | string | Parent interface                |
| `tag`      | string | Outer VLAN tag                  |
| `tag_type` | string | `ctag` or `stag`                |
| `members`  | string | Space-separated inner VLAN tags |
| `descr`    | string | Description                     |
| `vlanif`   | string | QinQ interface name             |

##### `<wol>` -- Wake on LAN

Path: `wol/wolentry[]`

| Field       | Type   | Description       |
| ----------- | ------ | ----------------- |
| `interface` | string | Network interface |
| `mac`       | string | MAC address       |
| `descr`     | string | Description       |

##### `<installedpackages>` -- Package Configuration

Dynamic structure per installed package. Common packages: miniupnpd, haproxy, pfblockerng, suricata, snort, acme.

Sub-arrays: `package[]` (name, internal_name, configurationfile, include_file), `menu[]`, `service[]`.

##### `<igmpproxy>` -- IGMP Proxy

Path: `igmpproxy/igmpentry[]`

| Field       | Type   | Description                |
| ----------- | ------ | -------------------------- |
| `ifname`    | string | Interface                  |
| `threshold` | string | TTL threshold              |
| `type`      | string | `upstream` or `downstream` |
| `address`   | string | Space-separated CIDRs      |
| `descr`     | string | Description                |

#### Low Priority (legacy/niche)

##### `<l2tp>` -- L2TP VPN Server

| Field                             | Type   | Description              |
| --------------------------------- | ------ | ------------------------ |
| `mode`                            | string | `off` / `server`         |
| `interface`                       | string | Interface                |
| `localip` / `remoteip`            | string | IP pool                  |
| `n_l2tp_units`                    | string | Max clients              |
| `secret`                          | string | L2TP secret              |
| `dns1` / `dns2`                   | string | DNS servers              |
| `user[]`                          | array  | `name`, `password`, `ip` |
| `radius/server` / `radius/secret` | string | RADIUS auth              |

##### `<pppoes>` -- PPPoE Server

Path: `pppoes/pppoe[]`

Fields: `pppoeid`, `mode`, `interface`, `paporchap`, `localip`, `remoteip`, `n_pppoe_units`, `n_pppoe_maxlogin`, `dns1`, `dns2`, `username`, `radius/*`.

##### `<voucher>` -- Captive Portal Vouchers

Zone-keyed map: `enable`, `freelogins_count`, `freelogins_resettimeout`, `freelogins_updatetimeouts`.

##### `<kea>` / `<kea6>` -- Kea DHCP Backend (pfSense 2.7+)

| Field                                             | Type   | Description          |
| ------------------------------------------------- | ------ | -------------------- |
| `enable`                                          | string | Enable Kea           |
| `loglevel`                                        | string | Log verbosity        |
| `custom_kea_config`                               | string | Custom configuration |
| `ha/role`                                         | string | HA role              |
| `ha/localname` / `ha/localip` / `ha/localport`    | string | Local HA node        |
| `ha/remotename` / `ha/remoteip` / `ha/remoteport` | string | Remote HA node       |
| `ha/tls` / `ha/scertref` / `ha/ccertref`          | string | TLS settings         |

##### Other Legacy Sections

| Section                          | Notes                                 |
| -------------------------------- | ------------------------------------- |
| `<pptpd>`                        | PPTP daemon (deprecated, insecure)    |
| `<proxyarp>`                     | Proxy ARP (legacy)                    |
| `<wireless>`                     | Wireless interface clones             |
| `<rrddata>`                      | Embedded RRD backup data              |
| `<shellcmd>` / `<earlyshellcmd>` | Boot-time commands (shellcmd package) |

## Expanded System Fields (Not Yet in Schema)

The `<system>` section has many fields beyond what is currently implemented. Notable missing fields:

### Firewall Tuning

| Field                 | Description                    |
| --------------------- | ------------------------------ |
| `maximumstates`       | Max firewall states            |
| `maximumtableentries` | Max pf table entries           |
| `maximumfrags`        | Max fragment entries           |
| `disablefilter`       | Disable firewall entirely      |
| `scrubnodf`           | Clear DF bit                   |
| `scrubrnid`           | Randomize IP ID                |
| `disablescrub`        | Disable scrub                  |
| `bypassstaticroutes`  | Bypass rules for static routes |
| `disablevpnrules`     | Disable auto VPN rules         |

### NAT Reflection

| Field                        | Description               |
| ---------------------------- | ------------------------- |
| `disablenatreflection`       | Disable NAT reflection    |
| `enablenatreflectionpurenat` | Pure NAT reflection mode  |
| `enablebinatreflection`      | 1:1 NAT reflection        |
| `enablenatreflectionhelper`  | FTP helper for reflection |
| `reflectiontimeout`          | Reflection timeout        |

### IPv6

| Field                    | Description           |
| ------------------------ | --------------------- |
| `ipv6allow`              | Allow IPv6            |
| `ipv6nat_enable`         | IPv6 NAT66            |
| `ipv6nat_ipaddr`         | NAT66 address         |
| `prefer_ipv4`            | Prefer IPv4           |
| `ipv6dontcreatelocaldns` | Skip IPv6 DNS entries |
| `ipv6duidtype`           | DUID type             |
| `global-v6duid`          | Global DHCPv6 DUID    |

### Network Offloading

| Field                           | Description              |
| ------------------------------- | ------------------------ |
| `disablechecksumoffloading`     | Disable checksum offload |
| `disablesegmentationoffloading` | Disable TSO              |
| `disablelargereceiveoffloading` | Disable LRO              |

### Miscellaneous

| Field                                     | Description                   |
| ----------------------------------------- | ----------------------------- |
| `ip_change_kill_states`                   | Kill states on IP change      |
| `gw_down_kill_states`                     | Kill states on gateway down   |
| `skip_rules_gw_down`                      | Skip rules when GW down       |
| `keep_failover_states`                    | Keep states on failover       |
| `lb_use_sticky`                           | Sticky load balancer          |
| `schedule_states`                         | Schedule-based state clearing |
| `pti_disabled`                            | Meltdown mitigation toggle    |
| `mds_disable`                             | MDS mitigation toggle         |
| `thermal_hardware`                        | Thermal sensor driver         |
| `harddiskstandby`                         | Disk standby timer            |
| `php_memory_limit`                        | PHP memory limit              |
| `use_mfs_tmpvar`                          | RAM-based /tmp and /var       |
| `rrdbackup` / `dhcpbackup` / `logsbackup` | Backup intervals              |
| `do_not_send_uniqueid`                    | Privacy flag                  |

### WebGUI Extended Fields

| Field                 | Description                                 |
| --------------------- | ------------------------------------------- |
| `port`                | Custom HTTPS port                           |
| `disablehttpredirect` | Disable HTTP-to-HTTPS redirect              |
| `disablehsts`         | Disable HSTS header                         |
| `ocsp-staple`         | OCSP stapling                               |
| `max_procs`           | Max web server processes                    |
| `session_timeout`     | Session timeout (minutes)                   |
| `authmode`            | Authentication mode                         |
| `nodnsrebindcheck`    | Disable DNS rebind check                    |
| `nohttpreferercheck`  | Disable HTTP referer check                  |
| `noantilockout`       | Disable anti-lockout rule                   |
| `roaming`             | Allow roaming (multi-IP sessions)           |
| `pwhash`              | Password hash algorithm (`bcrypt`/`sha512`) |
| `pagenamefirst`       | Page name first in title                    |

### User Extended Fields

| Field                | Description                  |
| -------------------- | ---------------------------- |
| `sha512-hash`        | Legacy SHA-512 password hash |
| `customsettings`     | Custom GUI preferences flag  |
| `widgets`            | Personal widget layout       |
| `dashboardcolumns`   | Personal dashboard columns   |
| `webguicss`          | Personal CSS theme           |
| `webguihostnamemenu` | Hostname display preference  |
| `interfacessort`     | Interface sort preference    |
| `keephistory`        | Shell history retention      |
| `cert[]`             | User certificate references  |

### SSHGuard (`system/sshguard`)

| Field            | Description                     |
| ---------------- | ------------------------------- |
| `threshold`      | Attack score threshold          |
| `blocktime`      | Block duration (seconds)        |
| `detection_time` | Detection window (seconds)      |
| `whitelist`      | Space-separated whitelisted IPs |

### Auto Config Backup (`system/acb`)

| Field                 | Description                |
| --------------------- | -------------------------- |
| `enable`              | Enable ACB                 |
| `device_key`          | Device identifier          |
| `encryption_password` | Backup encryption password |
| `frequency`           | Backup frequency           |

## Expanded Syslog Fields (Not Yet in Schema)

The current schema only captures `filterdescriptions`. Full pfSense syslog:

| Field                                                                                                                             | Description                   |
| --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `enable`                                                                                                                          | Enable remote logging         |
| `remoteserver` / `remoteserver2` / `remoteserver3`                                                                                | Up to 3 remote servers        |
| `sourceip`                                                                                                                        | Source IP for syslog packets  |
| `ipproto`                                                                                                                         | `ipv4` / `ipv6`               |
| `format`                                                                                                                          | `rfc3164` / `rfc5424`         |
| `logfilesize`                                                                                                                     | Max log file size             |
| `rotatecount`                                                                                                                     | Number of rotated logs        |
| `reverse`                                                                                                                         | Reverse display order         |
| `logcompressiontype`                                                                                                              | Compression for rotated logs  |
| `disablelocallogging`                                                                                                             | Disable local log storage     |
| `logall`                                                                                                                          | Log all facilities            |
| `default_log_level`                                                                                                               | Default syslog level          |
| `filterdescriptions`                                                                                                              | Filter log descriptions (1/2) |
| `logconfigchanges`                                                                                                                | Log config changes            |
| Per-facility: `auth`, `routing`, `ntpd`, `ppp`, `vpn`, `dpinger`, `resolver`, `dhcp`, `hostapd`, `filter`, `portalauth`, `system` | Remote log flags              |

## Expanded Unbound Fields (Not Yet in Schema)

| Field                               | Description                                                                       |
| ----------------------------------- | --------------------------------------------------------------------------------- |
| `forwarding`                        | Enable forwarding mode                                                            |
| `forward_tls_upstream`              | TLS to upstream forwarders                                                        |
| `enablessl`                         | Enable DNS-over-TLS service                                                       |
| `tlsport`                           | TLS port (default 853)                                                            |
| `regdhcp`                           | Register DHCP leases                                                              |
| `regdhcpstatic`                     | Register static DHCP                                                              |
| `regovpnclients`                    | Register OpenVPN clients                                                          |
| `aggressivensec`                    | Aggressive NSEC                                                                   |
| `use_caps`                          | 0x20 encoding                                                                     |
| `prefetch` / `prefetchkey`          | Cache prefetching                                                                 |
| `dnsrecordcache`                    | Record cache size                                                                 |
| `qname-minimisation`                | QNAME minimisation                                                                |
| `qname-minimisation-strict`         | Strict QNAME minimisation                                                         |
| `always_add_short_names`            | Short hostname entries                                                            |
| `disable_auto_added_host_entries`   | Skip auto host entries                                                            |
| `disable_auto_added_access_control` | Skip auto ACLs                                                                    |
| `python`                            | Python module support                                                             |
| `python_order` / `python_script`    | Module config                                                                     |
| `dns64` / `dns64/prefix`            | DNS64 support                                                                     |
| `stats` / `stats_interval`          | Statistics                                                                        |
| `msgcachesize`                      | Message cache (MB)                                                                |
| `cache_max_ttl` / `cache_min_ttl`   | TTL bounds                                                                        |
| `log_verbosity`                     | Log level                                                                         |
| `custom_options`                    | Base64-encoded custom config                                                      |
| `hosts[]`                           | Host overrides: `host`, `domain`, `ip`, `descr`, `aliases/item[]`                 |
| `domainoverrides[]`                 | Domain overrides: `domain`, `ip`, `descr`, `tls_hostname`, `forward_tls_upstream` |
| `acls[]`                            | Access control lists: `aclid`, `aclname`, `aclaction`, `row[]`                    |

## Sources

- [pfSense source: xmlparse.inc](https://github.com/pfsense/pfsense/blob/master/src/etc/inc/xmlparse.inc) -- listtags, XML parsing
- [pfSense source: config.lib.inc](https://github.com/pfsense/pfsense/blob/master/src/etc/inc/config.lib.inc) -- config management
- [pfSense source: upgrade_config.inc](https://github.com/pfsense/pfsense/blob/master/src/etc/inc/upgrade_config.inc) -- version migrations
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/) -- official docs
- [pfSense Versions](https://docs.netgate.com/pfsense/en/latest/releases/versions.html) -- version mapping
