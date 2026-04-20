package sanitizer

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkSanitizeXML_10MB measures sanitize throughput on a realistic
// ~10MB OPNsense config fixture. The fixture is generated lazily at
// testdata/benchmark-10mb.xml on first run and is excluded from git to
// avoid repo bloat.
//
// This is the post-fix baseline captured after PERF-M1/M2/M5
// (#148/#149/#150) landed in Phase 6. It serves as the reference point
// for future sanitizer performance regression detection.
//
// Run with:
//
//	go test -bench=BenchmarkSanitizeXML_10MB -benchmem -run=NONE ./internal/sanitizer/
func BenchmarkSanitizeXML_10MB(b *testing.B) {
	ensureBenchmark10MBFixture(b)
	data, err := os.ReadFile(bench10MBFixturePath)
	if err != nil {
		b.Fatalf("reading benchmark fixture: %v", err)
	}

	// SetBytes makes `go test -bench` report MB/s throughput alongside
	// ns/op — the standard way to communicate sanitize speed.
	b.SetBytes(int64(len(data)))

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		s := NewSanitizer(ModeAggressive)
		var output bytes.Buffer
		output.Grow(len(data))
		if err := s.SanitizeXML(bytes.NewReader(data), &output); err != nil {
			b.Fatal(err)
		}
	}
}

// bench10MBFixturePath is the on-disk location of the generated ~10MB
// OPNsense config fixture used by BenchmarkSanitizeXML_10MB.
//
// The path is intentionally relative — `go test` sets the working
// directory to the package directory, so this resolves to
// internal/sanitizer/testdata/benchmark-10mb.xml when the benchmark
// runs via `go test ./internal/sanitizer/...`.
const bench10MBFixturePath = "testdata/benchmark-10mb.xml"

// bench10MBTargetSize is the minimum acceptable fixture size in bytes.
// The generator below overshoots slightly (~10.5MB) so the on-disk
// file comfortably clears this threshold across Go versions and
// platform line-ending conventions.
const bench10MBTargetSize = 10 * 1024 * 1024 // 10 MB

// ensureBenchmark10MBFixture lazily materializes the 10MB fixture at
// bench10MBFixturePath. If the file already exists and is at least
// bench10MBTargetSize bytes, it is reused as-is. Otherwise the fixture
// is regenerated and written to disk. The file is excluded from git
// (see .gitignore) because committing 10MB of synthetic XML would
// bloat the repo well beyond project norms.
//
// The generator is deterministic — repeated runs produce byte-identical
// output — so benchmark results remain comparable across invocations.
func ensureBenchmark10MBFixture(tb testing.TB) {
	tb.Helper()

	if info, err := os.Stat(bench10MBFixturePath); err == nil && info.Size() >= bench10MBTargetSize {
		return
	}

	if err := os.MkdirAll("testdata", 0o750); err != nil {
		tb.Fatalf("creating testdata dir: %v", err)
	}

	data := buildBenchmark10MBFixture()
	if len(data) < bench10MBTargetSize {
		tb.Fatalf("generated fixture too small: got %d bytes, want >= %d", len(data), bench10MBTargetSize)
	}

	// 0o600: the fixture is synthetic test data and contains no real
	// secrets, but gosec G306 requires <=0o600 for WriteFile regardless.
	// The bench owner is the only reader, so 0o600 is sufficient.
	if err := os.WriteFile(bench10MBFixturePath, data, 0o600); err != nil {
		tb.Fatalf("writing benchmark fixture: %v", err)
	}
}

// buildBenchmark10MBFixture returns a ~10MB synthetic OPNsense
// config.xml. The content is designed to exercise every major
// redaction rule in builtinRules() while keeping the structure
// recognizable as OPNsense config.xml:
//
//   - ~5000 firewall rules (filter/rule, nat/rule).
//   - ~50 interfaces (opt1..opt50) with IPv4/IPv6 + description.
//   - ~200 users with passwords, emails, SSH authorized keys,
//     and verbose descriptions.
//   - ~500 certificates with synthetic PEM bodies + private keys.
//   - ~1000 DHCP host-overrides (hostname, MAC, static IP).
//   - SNMP community strings, OpenVPN client configs, IPsec PSKs.
//
// The output is deterministic — no random sources — so benchmarks
// are reproducible and gaps in coverage surface as regressions.
func buildBenchmark10MBFixture() []byte {
	var sb strings.Builder
	// Pre-size to avoid repeated reallocation; we target ~11MB, so
	// allocate 12MB upfront.
	sb.Grow(12 * 1024 * 1024)

	sb.WriteString(`<?xml version="1.0"?>` + "\n")
	sb.WriteString("<opnsense>\n")

	writeBenchSystem(&sb)
	writeBenchInterfaces(&sb)
	writeBenchFirewallRules(&sb)
	writeBenchNATRules(&sb)
	writeBenchDHCPDHostOverrides(&sb)
	writeBenchCerts(&sb)
	writeBenchOpenVPN(&sb)
	writeBenchIPsec(&sb)
	writeBenchSNMP(&sb)

	sb.WriteString("</opnsense>\n")

	return []byte(sb.String())
}

// writeBenchSystem emits ~200 users and a verbose SNMP/SSH preamble.
// Each user carries a password, email, SSH authorized_keys blob, and
// a bulky description to inflate the field count without straying
// from a plausible OPNsense shape.
func writeBenchSystem(sb *strings.Builder) {
	sb.WriteString("  <system>\n")
	sb.WriteString("    <hostname>fw-benchmark</hostname>\n")
	sb.WriteString("    <domain>corp.example.com</domain>\n")
	sb.WriteString("    <ssh>\n")
	sb.WriteString("      <enabled>yes</enabled>\n")
	sb.WriteString("      <port>22</port>\n")
	sb.WriteString("    </ssh>\n")

	// Realistic-looking SSH public key body (not a real key). Kept
	// consistent across users so the sanitizer sees repeated input
	// and exercises the ssh_authorized_keys rule path.
	sshKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC" + strings.Repeat("X", 372) + " user@example.com"

	for i := range 200 {
		n := strconv.Itoa(i)
		sb.WriteString("    <user>\n")
		sb.WriteString("      <name>user-" + n + "</name>\n")
		sb.WriteString("      <descr>Automation service account number " + n +
			" used by the orchestration layer for scheduled audits across the fleet." +
			" Contact the platform team before deactivating." +
			" Escalation path: ops-oncall@corp.example.com.</descr>\n")
		sb.WriteString("      <scope>user</scope>\n")
		sb.WriteString("      <password>P@ssw0rd-" + n + "-ThisIsNotARealSecret!</password>\n")
		sb.WriteString("      <bcrypt-hash>$2y$10$abcdefghijklmnopqrstuv" + n +
			"1234567890abcdefghijklmnopqrstuv</bcrypt-hash>\n")
		sb.WriteString("      <email>user-" + n + "@corp.example.com</email>\n")
		sb.WriteString("      <uid>" + strconv.Itoa(1000+i) + "</uid>\n")
		sb.WriteString("      <groupname>admins</groupname>\n")
		sb.WriteString("      <authorizedkeys>" + sshKey + "</authorizedkeys>\n")
		sb.WriteString("      <ipsecpsk>psk-shared-secret-" + n + "-abcdef0123456789</ipsecpsk>\n")
		sb.WriteString("      <otp_seed>JBSWY3DPEHPK3PXP" + n + "</otp_seed>\n")
		sb.WriteString("    </user>\n")
	}

	sb.WriteString("  </system>\n")
}

// writeBenchInterfaces emits ~50 opt interfaces plus wan/lan, each
// with IPv4 + IPv6 addressing and a description.
func writeBenchInterfaces(sb *strings.Builder) {
	sb.WriteString("  <interfaces>\n")
	sb.WriteString("    <wan>\n")
	sb.WriteString("      <if>igb0</if>\n")
	sb.WriteString("      <ipaddr>203.0.113.10</ipaddr>\n")
	sb.WriteString("      <subnet>24</subnet>\n")
	sb.WriteString("      <gateway>WAN_GW</gateway>\n")
	sb.WriteString("      <descr>Public uplink to upstream provider</descr>\n")
	sb.WriteString("    </wan>\n")
	sb.WriteString("    <lan>\n")
	sb.WriteString("      <if>igb1</if>\n")
	sb.WriteString("      <ipaddr>10.0.0.1</ipaddr>\n")
	sb.WriteString("      <subnet>16</subnet>\n")
	sb.WriteString("      <descr>Primary corporate LAN</descr>\n")
	sb.WriteString("    </lan>\n")

	for i := range 50 {
		n := strconv.Itoa(i)
		sb.WriteString("    <opt" + n + ">\n")
		sb.WriteString("      <if>igb" + strconv.Itoa(i+2) + "</if>\n")
		sb.WriteString("      <enable>1</enable>\n")
		sb.WriteString("      <ipaddr>10." + strconv.Itoa(i+1) + ".0.1</ipaddr>\n")
		sb.WriteString("      <subnet>24</subnet>\n")
		sb.WriteString("      <ipaddrv6>fd00:dead:beef:" + n + "::1</ipaddrv6>\n")
		sb.WriteString("      <subnetv6>64</subnetv6>\n")
		sb.WriteString("      <descr>Segment VLAN-" + n +
			" for tenant workloads; traffic egresses through WAN_GW after NAT." +
			" Contact netops@corp.example.com.</descr>\n")
		sb.WriteString("      <spoofmac>02:00:00:00:00:" + fmt.Sprintf("%02x", i) + "</spoofmac>\n")
		sb.WriteString("    </opt" + n + ">\n")
	}

	sb.WriteString("  </interfaces>\n")
}

// writeBenchFirewallRules emits ~5000 filter/rule entries. Each rule
// carries enough context (descriptions, source/dest, interface,
// gateway, schedule) that the average serialized size approaches ~1.5KB,
// driving the bulk of the ~10MB target.
func writeBenchFirewallRules(sb *strings.Builder) {
	sb.WriteString("  <filter>\n")

	// Bulky reusable description templates so repeated-rule content
	// averages a realistic size without relying on random padding.
	//
	// Keep these as literal strings (not strings.Repeat at runtime)
	// so the fixture stays deterministic and readable in diffs.
	// Target rule serialized size: ~2KB so 5000 rules ≈ 10MB.
	descPrefix := "Allow egress from tenant segment to upstream provider. " +
		"Ticket JIRA-12345 tracks the change request. " +
		"Reviewed by netsec-team@corp.example.com on 2026-01-15. " +
		"Rollback: remove this rule and re-apply default deny. " +
		"Business justification: service mesh nodes require outbound connectivity " +
		"to the regional egress proxy for health checks, telemetry, and tracing. " +
		"Tags applied: env=prod, tier=data, owner=platform-eng, severity=high. " +
		"Associated monitors: grafana.corp.example.com/d/svc-mesh-egress, " +
		"pagerduty service 'service-mesh-egress'. Runbook: " +
		"https://runbooks.corp.example.com/services/service-mesh/egress-failure. " +
		"Change control: CAB-2026-Q1-017 approved 2026-01-14; effective window " +
		"2026-01-15 02:00 UTC through 2026-01-15 06:00 UTC; no customer impact expected. " +
		"Security review: cleared by appsec on 2026-01-13, tracking ticket SEC-88421. " +
		"Compliance notes: SOC2 CC6.6 network segmentation controls satisfied by " +
		"explicit source/destination CIDR restrictions and TLS 1.2+ requirement. "

	for i := range 5000 {
		n := strconv.Itoa(i)
		ifaceIdx := i % 52 // wan/lan + 50 opts
		var iface string
		switch ifaceIdx {
		case 0:
			iface = "wan"
		case 1:
			iface = "lan"
		default:
			iface = "opt" + strconv.Itoa(ifaceIdx-2)
		}

		sb.WriteString("    <rule>\n")
		sb.WriteString("      <type>pass</type>\n")
		sb.WriteString("      <interface>" + iface + "</interface>\n")
		sb.WriteString("      <ipprotocol>inet</ipprotocol>\n")
		sb.WriteString("      <protocol>tcp</protocol>\n")
		sb.WriteString("      <descr>" + descPrefix + "Rule number " + n +
			" covers internal service mesh traffic on port " +
			strconv.Itoa(8000+(i%2000)) + ".</descr>\n")
		sb.WriteString("      <source>\n")
		sb.WriteString("        <address>10." + strconv.Itoa(i%256) + "." +
			strconv.Itoa((i/256)%256) + ".0/24</address>\n")
		sb.WriteString("      </source>\n")
		sb.WriteString("      <destination>\n")
		sb.WriteString("        <address>172.16." + strconv.Itoa(i%256) + "." +
			strconv.Itoa((i/256)%256) + ".0/24</address>\n")
		sb.WriteString("        <port>" + strconv.Itoa(8000+(i%2000)) + "</port>\n")
		sb.WriteString("      </destination>\n")
		sb.WriteString("      <gateway>WAN_GW</gateway>\n")
		sb.WriteString("      <log>1</log>\n")
		sb.WriteString("      <statetype>keep state</statetype>\n")
		sb.WriteString("      <direction>out</direction>\n")
		sb.WriteString("      <floating>no</floating>\n")
		sb.WriteString("      <quick>1</quick>\n")
		sb.WriteString("      <tcpflags1>syn</tcpflags1>\n")
		sb.WriteString("      <tcpflags2>syn,ack,fin,rst</tcpflags2>\n")
		sb.WriteString("      <category>tenant-egress," + strconv.Itoa(i%20) + "</category>\n")
		sb.WriteString("      <tag>scheduled-" + strconv.Itoa(i%10) + "</tag>\n")
		sb.WriteString("      <tagged>src-tagged-" + strconv.Itoa(i%5) + "</tagged>\n")
		sb.WriteString("      <updated>\n")
		sb.WriteString("        <username>admin@10.0.0.5</username>\n")
		sb.WriteString("        <time>1705300000</time>\n")
		sb.WriteString("      </updated>\n")
		sb.WriteString("      <created>\n")
		sb.WriteString("        <username>admin@10.0.0.5</username>\n")
		sb.WriteString("        <time>1704000000</time>\n")
		sb.WriteString("      </created>\n")
		sb.WriteString("    </rule>\n")
	}

	sb.WriteString("  </filter>\n")
}

// writeBenchNATRules emits ~500 NAT redirect rules with external and
// internal IP endpoints to exercise the ip_address_field rule.
func writeBenchNATRules(sb *strings.Builder) {
	sb.WriteString("  <nat>\n")
	for i := range 500 {
		n := strconv.Itoa(i)
		sb.WriteString("    <rule>\n")
		sb.WriteString("      <source>\n")
		sb.WriteString("        <any>1</any>\n")
		sb.WriteString("      </source>\n")
		sb.WriteString("      <destination>\n")
		sb.WriteString("        <address>203.0.113." + strconv.Itoa(i%256) + "</address>\n")
		sb.WriteString("        <port>" + strconv.Itoa(10000+i) + "</port>\n")
		sb.WriteString("      </destination>\n")
		sb.WriteString("      <target>10.50." + strconv.Itoa(i%256) + "." +
			strconv.Itoa((i/256)%256) + "</target>\n")
		sb.WriteString("      <local-port>" + strconv.Itoa(10000+i) + "</local-port>\n")
		sb.WriteString("      <interface>wan</interface>\n")
		sb.WriteString("      <descr>Port forward number " + n + " for tenant ingress</descr>\n")
		sb.WriteString("    </rule>\n")
	}
	sb.WriteString("  </nat>\n")
}

// writeBenchDHCPDHostOverrides emits ~1000 host-override entries with
// hostnames, MACs, and static IPs — exercising hostname, mac_address,
// and ip_address_field rules.
func writeBenchDHCPDHostOverrides(sb *strings.Builder) {
	sb.WriteString("  <dhcpd>\n")
	sb.WriteString("    <lan>\n")
	sb.WriteString("      <enable>1</enable>\n")
	sb.WriteString("      <range>\n")
	sb.WriteString("        <from>10.0.10.10</from>\n")
	sb.WriteString("        <to>10.0.10.200</to>\n")
	sb.WriteString("      </range>\n")
	for i := range 1000 {
		n := strconv.Itoa(i)
		sb.WriteString("      <staticmap>\n")
		sb.WriteString("        <mac>02:aa:bb:" +
			fmt.Sprintf("%02x:%02x:%02x", (i>>16)&0xff, (i>>8)&0xff, i&0xff) +
			"</mac>\n")
		sb.WriteString("        <ipaddr>10.20." + strconv.Itoa(i/256) + "." +
			strconv.Itoa(i%256) + "</ipaddr>\n")
		sb.WriteString("        <hostname>host-" + n + ".corp.example.com</hostname>\n")
		sb.WriteString("        <descr>Managed endpoint for workstation " + n +
			" assigned to team-" + strconv.Itoa(i%20) + "</descr>\n")
		sb.WriteString("      </staticmap>\n")
	}
	sb.WriteString("    </lan>\n")
	sb.WriteString("  </dhcpd>\n")
}

// writeBenchCerts emits ~500 certificate entries with synthetic PEM
// bodies. Each cert has both a public certificate blob and a private
// key blob (base64-ish padding), exercising the certificate and
// private_key rules.
func writeBenchCerts(sb *strings.Builder) {
	// Padding resembles base64 content but is not a real key — safe
	// to ship as test data. Length tuned to make each cert entry
	// ~1.5KB so 500 entries contribute ~750KB.
	certBody := strings.Repeat("MIIFakeCertBytesForBenchmarkingOnly0123456789+/=", 20)
	keyBody := strings.Repeat("MIIFakePrivKeyBytesForBenchmarkingOnly012345+/=", 18)

	sb.WriteString("  <cert>\n")
	for i := range 500 {
		n := strconv.Itoa(i)
		sb.WriteString("    <entry>\n")
		sb.WriteString("      <refid>cert-" + n + "</refid>\n")
		sb.WriteString("      <descr>Server certificate for service-" + n + "</descr>\n")
		sb.WriteString("      <crt>-----BEGIN CERTIFICATE-----\n" +
			certBody + "\n-----END CERTIFICATE-----</crt>\n")
		sb.WriteString("      <prv>-----BEGIN RSA PRIVATE KEY-----\n" +
			keyBody + "\n-----END RSA PRIVATE KEY-----</prv>\n")
		sb.WriteString("    </entry>\n")
	}
	sb.WriteString("  </cert>\n")
}

// writeBenchOpenVPN emits OpenVPN server + client configs with shared
// keys and TLS auth material.
func writeBenchOpenVPN(sb *strings.Builder) {
	sb.WriteString("  <openvpn>\n")
	tlsBody := strings.Repeat("TLSAuthKeyBenchmarkPaddingBytes", 40)
	for i := range 20 {
		n := strconv.Itoa(i)
		sb.WriteString("    <openvpn-server>\n")
		sb.WriteString("      <vpnid>" + n + "</vpnid>\n")
		sb.WriteString("      <description>VPN server " + n + "</description>\n")
		sb.WriteString("      <mode>server_tls</mode>\n")
		sb.WriteString("      <tls>\n" + tlsBody + "\n</tls>\n")
		sb.WriteString("      <shared_key>" + tlsBody + "</shared_key>\n")
		sb.WriteString("      <tunnel_network>10.100." + n + ".0/24</tunnel_network>\n")
		sb.WriteString("    </openvpn-server>\n")
	}
	for i := range 100 {
		n := strconv.Itoa(i)
		sb.WriteString("    <openvpn-client>\n")
		sb.WriteString("      <vpnid>" + n + "</vpnid>\n")
		sb.WriteString("      <description>Remote client " + n + "</description>\n")
		sb.WriteString("      <server_addr>vpn-" + n + ".corp.example.com</server_addr>\n")
		sb.WriteString("      <server_port>1194</server_port>\n")
		sb.WriteString("      <auth_user>client-" + n + "</auth_user>\n")
		sb.WriteString("      <auth_pass>OvpnClientPassword-" + n + "-NotReal</auth_pass>\n")
		sb.WriteString("      <tls>" + tlsBody + "</tls>\n")
		sb.WriteString("    </openvpn-client>\n")
	}
	sb.WriteString("  </openvpn>\n")
}

// writeBenchIPsec emits IPsec phase1/phase2 entries with PSKs.
func writeBenchIPsec(sb *strings.Builder) {
	sb.WriteString("  <ipsec>\n")
	for i := range 50 {
		n := strconv.Itoa(i)
		sb.WriteString("    <phase1>\n")
		sb.WriteString("      <ikeid>" + n + "</ikeid>\n")
		sb.WriteString("      <descr>Site-to-site tunnel " + n + "</descr>\n")
		sb.WriteString("      <remote-gateway>198.51.100." + strconv.Itoa(i%256) + "</remote-gateway>\n")
		sb.WriteString("      <pre-shared-key>PSK-Tunnel-" + n +
			"-VeryLongButNotRealSecretString</pre-shared-key>\n")
		sb.WriteString("    </phase1>\n")
	}
	sb.WriteString("  </ipsec>\n")
}

// writeBenchSNMP emits SNMP community strings.
func writeBenchSNMP(sb *strings.Builder) {
	sb.WriteString("  <snmpd>\n")
	sb.WriteString("    <syslocation>Rack 42, Row B, DC-East</syslocation>\n")
	sb.WriteString("    <syscontact>netops@corp.example.com</syscontact>\n")
	sb.WriteString("    <rocommunity>public-ro-community-" + strings.Repeat("X", 32) + "</rocommunity>\n")
	sb.WriteString("    <rwcommunity>private-rw-community-" + strings.Repeat("Y", 32) + "</rwcommunity>\n")
	sb.WriteString("  </snmpd>\n")
}
