package pfsense

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// convertDHCP maps doc.Dhcpd.Items to []common.DHCPScope.
func (c *converter) convertDHCP(doc *pfsense.Document) []common.DHCPScope {
	items := doc.Dhcpd.Items
	if len(items) == 0 {
		return nil
	}

	result := make([]common.DHCPScope, 0, len(items))
	for _, key := range slices.Sorted(maps.Keys(items)) {
		d := items[key]
		scope := common.DHCPScope{
			Interface:  key,
			Source:     common.DHCPSourceISC,
			Enabled:    d.Enable.Bool(),
			Range:      common.DHCPRange{From: d.Range.From, To: d.Range.To},
			Gateway:    d.Gateway,
			DNSServer:  d.Dnsserver,
			NTPServer:  d.Ntpserver,
			WINSServer: d.Winsserver,
		}

		scope.StaticLeases = c.convertStaticLeases(d.Staticmap)
		scope.NumberOptions = c.convertNumberOptions(d.NumberOptions)

		result = append(result, scope)
	}

	return result
}

// convertStaticLeases maps []opnsense.DHCPStaticLease to []common.DHCPStaticLease.
func (c *converter) convertStaticLeases(leases []opnsense.DHCPStaticLease) []common.DHCPStaticLease {
	if len(leases) == 0 {
		return nil
	}

	result := make([]common.DHCPStaticLease, 0, len(leases))
	for _, l := range leases {
		result = append(result, common.DHCPStaticLease{
			MAC:              l.Mac,
			CID:              l.Cid,
			IPAddress:        l.IPAddr,
			Hostname:         l.Hostname,
			Description:      l.Descr,
			Filename:         l.Filename,
			Rootpath:         l.Rootpath,
			DefaultLeaseTime: l.Defaultleasetime,
			MaxLeaseTime:     l.Maxleasetime,
		})
	}

	return result
}

// convertNumberOptions maps []opnsense.DHCPNumberOption to []common.DHCPNumberOption.
func (c *converter) convertNumberOptions(opts []opnsense.DHCPNumberOption) []common.DHCPNumberOption {
	if len(opts) == 0 {
		return nil
	}

	result := make([]common.DHCPNumberOption, 0, len(opts))
	for _, o := range opts {
		result = append(result, common.DHCPNumberOption{
			Number: o.Number,
			Type:   o.Type,
			Value:  o.Value,
		})
	}

	return result
}

// convertDNS maps pfSense Unbound and system DNS to common.DNSConfig.
func (c *converter) convertDNS(doc *pfsense.Document) common.DNSConfig {
	return common.DNSConfig{
		Servers: doc.System.DNSServers,
		Unbound: common.UnboundConfig{
			Enabled:        bool(doc.Unbound.Enable),
			DNSSEC:         bool(doc.Unbound.DNSSEC),
			DNSSECStripped: bool(doc.Unbound.DNSSECStripped),
		},
	}
}

// convertSNMP maps doc.Snmpd to common.SNMPConfig.
func (c *converter) convertSNMP(doc *pfsense.Document) common.SNMPConfig {
	return common.SNMPConfig{
		ROCommunity: doc.Snmpd.ROCommunity,
		SysLocation: doc.Snmpd.SysLocation,
		SysContact:  doc.Snmpd.SysContact,
	}
}

// convertLoadBalancer maps doc.LoadBalancer.MonitorType to common.LoadBalancerConfig.
func (c *converter) convertLoadBalancer(doc *pfsense.Document) common.LoadBalancerConfig {
	monitors := doc.LoadBalancer.MonitorType
	if len(monitors) == 0 {
		return common.LoadBalancerConfig{}
	}

	result := make([]common.MonitorType, 0, len(monitors))
	for _, m := range monitors {
		result = append(result, common.MonitorType{
			Name:        m.Name,
			Type:        m.Type,
			Description: m.Descr,
			Options: common.MonitorOptions{
				Path:   m.Options.Path,
				Host:   m.Options.Host,
				Code:   m.Options.Code,
				Send:   m.Options.Send,
				Expect: m.Options.Expect,
			},
		})
	}

	return common.LoadBalancerConfig{MonitorTypes: result}
}

// convertVPN maps OpenVPN and IPsec sections to common.VPN.
func (c *converter) convertVPN(doc *pfsense.Document) common.VPN {
	return common.VPN{
		OpenVPN: common.OpenVPNConfig{
			Servers:               c.convertOpenVPNServers(doc.OpenVPN.Servers),
			Clients:               c.convertOpenVPNClients(doc.OpenVPN.Clients),
			ClientSpecificConfigs: c.convertOpenVPNCSCs(doc.OpenVPN.CSC),
		},
		IPsec: c.convertIPsec(doc),
	}
}

// convertIPsec maps doc.IPsec to common.IPsecConfig.
// IPsec is considered enabled only when Phase 1 (IKE SA) entries exist. Phase 2 tunnels and
// mobile client settings hang off Phase 1 in pfSense — without Phase 1 entries they are orphaned
// and functionally inactive. Orphan Phase 2 or mobile client data emits conversion warnings.
// The Logging section is intentionally excluded — it contains daemon tuning, not security-relevant config.
func (c *converter) convertIPsec(doc *pfsense.Document) common.IPsecConfig {
	ipsec := doc.IPsec
	if len(ipsec.Phase1) == 0 {
		c.warnOrphanIPsecData(ipsec)

		return common.IPsecConfig{}
	}

	return common.IPsecConfig{
		Enabled:       true,
		Phase1Tunnels: c.convertIPsecPhase1Tunnels(ipsec.Phase1),
		Phase2Tunnels: c.convertIPsecPhase2Tunnels(ipsec.Phase2),
		MobileClient:  c.convertIPsecMobileClient(ipsec.Client),
	}
}

// warnOrphanIPsecData emits conversion warnings for Phase 2 tunnels or mobile client
// configuration that exist without any Phase 1 entries. These are orphaned and functionally
// inactive in pfSense because Phase 2 and mobile client settings depend on Phase 1.
func (c *converter) warnOrphanIPsecData(ipsec pfsense.IPsec) {
	if len(ipsec.Phase2) > 0 {
		c.addWarning(
			"IPsec.Phase2",
			fmt.Sprintf("%d entries", len(ipsec.Phase2)),
			"orphan Phase 2 tunnels without Phase 1 entries are functionally inactive",
			common.SeverityMedium,
		)
	}

	if ipsec.Client.Enable.Bool() {
		c.addWarning(
			"IPsec.Client",
			"enabled",
			"orphan mobile client configuration without Phase 1 entries is functionally inactive",
			common.SeverityMedium,
		)
	}
}

// convertIPsecPhase1Tunnels maps []pfsense.IPsecPhase1 to []common.IPsecPhase1Tunnel.
func (c *converter) convertIPsecPhase1Tunnels(phases []pfsense.IPsecPhase1) []common.IPsecPhase1Tunnel {
	if len(phases) == 0 {
		return nil
	}

	result := make([]common.IPsecPhase1Tunnel, 0, len(phases))
	for i, p1 := range phases {
		c.validateIPsecPhase1Fields(i, p1)

		if p1.PreSharedKey != "" {
			c.addWarning(
				fmt.Sprintf("IPsec.Phase1[%d].PreSharedKey", i),
				"[present]",
				"pre-shared key intentionally excluded from export model for security",
				common.SeverityLow,
			)
		}

		result = append(result, common.IPsecPhase1Tunnel{
			IKEID:         p1.IKEId,
			IKEType:       p1.IKEType,
			Interface:     p1.Interface,
			RemoteGateway: p1.RemoteGW,
			Protocol:      p1.Protocol,
			AuthMethod:    p1.AuthMethod,
			MyIDType:      p1.MyIDType,
			MyIDData:      p1.MyIDData,
			PeerIDType:    p1.PeerIDType,
			PeerIDData:    p1.PeerIDData,
			Mode:          p1.Mode,
			Lifetime:      p1.Lifetime,
			RekeyTime:     p1.RekeyTime,
			ReauthTime:    p1.ReauthTime,
			RandTime:      p1.RandTime,
			NATTraversal:  p1.NATTraversal,
			MOBIKE:        p1.Mobike,
			DPDDelay:      p1.DPDDelay,
			DPDMaxFail:    p1.DPDMaxFail,
			StartAction:   p1.StartAction,
			CloseAction:   p1.CloseAction,
			CertRef:       p1.CertRef,
			CARef:         p1.CARef,
			IKEPort:       p1.IKEPort,
			NATTPort:      p1.NATTPort,
			SplitConn:     p1.SplitConn,
			Description:   p1.Descr,
			Disabled:      p1.Disabled.Bool(),
			Mobile:        p1.Mobile.Bool(),
			EncryptionAlgorithms: c.convertIPsecEncryptionAlgorithms(
				fmt.Sprintf("IPsec.Phase1[%d]", i),
				p1.Encryption.Algorithms,
			),
		})
	}

	return result
}

// validIPsecPhase1IKETypes contains recognized IKE version values for Phase 1.
var validIPsecPhase1IKETypes = []string{"ikev1", "ikev2", "auto"}

// validIPsecPhase1Modes contains recognized negotiation modes for Phase 1.
var validIPsecPhase1Modes = []string{"main", "aggressive"}

// validIPsecPhase1Protocols contains recognized address family values for Phase 1.
var validIPsecPhase1Protocols = []string{"inet", "inet6", "both"}

// validIPsecPhase2Modes contains recognized tunnel modes for Phase 2.
var validIPsecPhase2Modes = []string{"tunnel", "tunnel6", "transport", "vti"}

// validIPsecPhase2Protocols contains recognized IPsec protocols for Phase 2.
var validIPsecPhase2Protocols = []string{"esp", "ah"}

// validateIPsecPhase1Fields emits conversion warnings for unrecognized enum-like field values.
func (c *converter) validateIPsecPhase1Fields(idx int, p1 pfsense.IPsecPhase1) {
	prefix := fmt.Sprintf("IPsec.Phase1[%d]", idx)

	if p1.IKEType != "" && !containsString(validIPsecPhase1IKETypes, p1.IKEType) {
		c.addWarning(prefix+".IKEType", p1.IKEType, "unrecognized IKE version", common.SeverityMedium)
	}

	if p1.Mode != "" && !containsString(validIPsecPhase1Modes, p1.Mode) {
		c.addWarning(prefix+".Mode", p1.Mode, "unrecognized negotiation mode", common.SeverityMedium)
	}

	if p1.Protocol != "" && !containsString(validIPsecPhase1Protocols, p1.Protocol) {
		c.addWarning(prefix+".Protocol", p1.Protocol, "unrecognized address family", common.SeverityMedium)
	}
}

// validateIPsecPhase2Fields emits conversion warnings for unrecognized enum-like field values.
func (c *converter) validateIPsecPhase2Fields(idx int, p2 pfsense.IPsecPhase2) {
	prefix := fmt.Sprintf("IPsec.Phase2[%d]", idx)

	if p2.Mode != "" && !containsString(validIPsecPhase2Modes, p2.Mode) {
		c.addWarning(prefix+".Mode", p2.Mode, "unrecognized tunnel mode", common.SeverityMedium)
	}

	if p2.Protocol != "" && !containsString(validIPsecPhase2Protocols, p2.Protocol) {
		c.addWarning(prefix+".Protocol", p2.Protocol, "unrecognized IPsec protocol", common.SeverityMedium)
	}
}

// containsString reports whether needle is in haystack (case-sensitive).
func containsString(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}

// convertIPsecEncryptionAlgorithms extracts algorithm names with optional key lengths.
// Shared by Phase 1 and Phase 2 — both use []IPsecEncryptionAlgorithm, though Phase 1
// nests them inside an <encryption> wrapper element.
// Entries with empty names are skipped with a conversion warning.
func (c *converter) convertIPsecEncryptionAlgorithms(
	parentPath string,
	algs []pfsense.IPsecEncryptionAlgorithm,
) []string {
	if len(algs) == 0 {
		return nil
	}

	result := make([]string, 0, len(algs))
	for i, alg := range algs {
		if alg.Name == "" {
			c.addWarning(
				fmt.Sprintf("%s.EncryptionAlgorithms[%d].Name", parentPath, i),
				"",
				"encryption algorithm has empty name, skipping",
				common.SeverityMedium,
			)

			continue
		}

		name := alg.Name
		if alg.KeyLen != "" {
			name = name + "-" + alg.KeyLen
		}

		result = append(result, name)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// convertIPsecPhase2Tunnels maps []pfsense.IPsecPhase2 to []common.IPsecPhase2Tunnel.
func (c *converter) convertIPsecPhase2Tunnels(phases []pfsense.IPsecPhase2) []common.IPsecPhase2Tunnel {
	if len(phases) == 0 {
		return nil
	}

	result := make([]common.IPsecPhase2Tunnel, 0, len(phases))
	for i, p2 := range phases {
		c.validateIPsecPhase2Fields(i, p2)

		result = append(result, common.IPsecPhase2Tunnel{
			IKEID:             p2.IKEId,
			UniqID:            p2.UniqID,
			ReqID:             p2.ReqID,
			Mode:              p2.Mode,
			Disabled:          p2.Disabled.Bool(),
			Protocol:          p2.Protocol,
			LocalIDType:       p2.LocalID.Type,
			LocalIDAddress:    p2.LocalID.Address,
			LocalIDNetbits:    p2.LocalID.Netbits,
			RemoteIDType:      p2.RemoteID.Type,
			RemoteIDAddress:   p2.RemoteID.Address,
			RemoteIDNetbits:   p2.RemoteID.Netbits,
			NATLocalIDType:    p2.NATLocalID.Type,
			NATLocalIDAddress: p2.NATLocalID.Address,
			NATLocalIDNetbits: p2.NATLocalID.Netbits,
			PFSGroup:          p2.PFSGroup,
			Lifetime:          p2.Lifetime,
			PingHost:          p2.PingHost,
			Description:       p2.Descr,
			EncryptionAlgorithms: c.convertIPsecEncryptionAlgorithms(
				fmt.Sprintf("IPsec.Phase2[%d]", i),
				p2.EncryptionAlgorithms,
			),
			HashAlgorithms: c.convertIPsecHashAlgorithms(fmt.Sprintf("IPsec.Phase2[%d]", i), p2.HashAlgorithms),
		})
	}

	return result
}

// convertIPsecHashAlgorithms extracts hash algorithm names from Phase 2 entries.
// Entries with empty names are skipped with a conversion warning.
func (c *converter) convertIPsecHashAlgorithms(parentPath string, algs []pfsense.IPsecHashAlgorithm) []string {
	if len(algs) == 0 {
		return nil
	}

	result := make([]string, 0, len(algs))
	for i, alg := range algs {
		if alg.Name == "" {
			c.addWarning(
				fmt.Sprintf("%s.HashAlgorithms[%d].Name", parentPath, i),
				"",
				"hash algorithm has empty name, skipping",
				common.SeverityMedium,
			)

			continue
		}

		result = append(result, alg.Name)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// convertIPsecMobileClient maps pfsense.IPsecClient to common.IPsecMobileClient.
func (c *converter) convertIPsecMobileClient(client pfsense.IPsecClient) common.IPsecMobileClient {
	return common.IPsecMobileClient{
		Enabled:       client.Enable.Bool(),
		UserSource:    client.UserSource,
		GroupSource:   client.GroupSource,
		PoolAddress:   client.PoolAddress,
		PoolNetbits:   client.PoolNetbits,
		PoolAddressV6: client.PoolAddrV6,
		PoolNetbitsV6: client.PoolNetV6,
		DNSServers:    collectNonEmpty(client.DNSServer1, client.DNSServer2, client.DNSServer3, client.DNSServer4),
		WINSServers:   collectNonEmpty(client.WINSServer1, client.WINSServer2),
		DNSDomain:     client.DNSDomain,
		DNSSplit:      client.DNSSplit,
		LoginBanner:   client.LoginBanner,
		SavePassword:  client.SavePasswd.Bool(),
	}
}

// convertOpenVPNServers maps []opnsense.OpenVPNServer to []common.OpenVPNServer.
func (c *converter) convertOpenVPNServers(servers []opnsense.OpenVPNServer) []common.OpenVPNServer {
	if len(servers) == 0 {
		return nil
	}

	result := make([]common.OpenVPNServer, 0, len(servers))
	for _, s := range servers {
		result = append(result, common.OpenVPNServer{
			VPNID:            s.VPN_ID,
			Mode:             s.Mode,
			Protocol:         s.Protocol,
			DevMode:          s.Dev_mode,
			Interface:        s.Interface,
			LocalPort:        s.Local_port,
			Description:      s.Description,
			TunnelNetwork:    s.Tunnel_network,
			TunnelNetworkV6:  s.Tunnel_networkv6,
			RemoteNetwork:    s.Remote_network,
			RemoteNetworkV6:  s.Remote_networkv6,
			LocalNetwork:     s.Local_network,
			LocalNetworkV6:   s.Local_networkv6,
			MaxClients:       s.Maxclients,
			Compression:      s.Compression,
			DNSServers:       collectNonEmpty(s.DNS_server1, s.DNS_server2, s.DNS_server3, s.DNS_server4),
			NTPServers:       collectNonEmpty(s.NTP_server1, s.NTP_server2),
			CertRef:          s.Cert_ref,
			CARef:            s.CA_ref,
			CRLRef:           s.CRL_ref,
			DHLength:         s.DH_length,
			ECDHCurve:        s.Ecdh_curve,
			CertDepth:        s.Cert_depth,
			TLSType:          s.TLS_type,
			VerbosityLevel:   s.Verbosity_level,
			Topology:         s.Topology,
			StrictUserCN:     bool(s.Strictusercn),
			GWRedir:          bool(s.Gwredir),
			DynamicIP:        bool(s.Dynamic_ip),
			ServerBridgeDHCP: bool(s.Serverbridge_dhcp),
			DNSDomain:        s.DNS_domain,
			NetBIOSEnable:    bool(s.Netbios_enable),
			NetBIOSNType:     s.Netbios_ntype,
			NetBIOSScope:     s.Netbios_scope,
		})
	}

	return result
}

// convertOpenVPNClients maps []opnsense.OpenVPNClient to []common.OpenVPNClient.
func (c *converter) convertOpenVPNClients(clients []opnsense.OpenVPNClient) []common.OpenVPNClient {
	if len(clients) == 0 {
		return nil
	}

	result := make([]common.OpenVPNClient, 0, len(clients))
	for _, cl := range clients {
		result = append(result, common.OpenVPNClient{
			VPNID:          cl.VPN_ID,
			Mode:           cl.Mode,
			Protocol:       cl.Protocol,
			DevMode:        cl.Dev_mode,
			Interface:      cl.Interface,
			ServerAddr:     cl.Server_addr,
			ServerPort:     cl.Server_port,
			Description:    cl.Description,
			CertRef:        cl.Cert_ref,
			CARef:          cl.CA_ref,
			Compression:    cl.Compression,
			VerbosityLevel: cl.Verbosity_level,
		})
	}

	return result
}

// convertOpenVPNCSCs maps []opnsense.OpenVPNCSC to []common.OpenVPNCSC.
func (c *converter) convertOpenVPNCSCs(cscs []opnsense.OpenVPNCSC) []common.OpenVPNCSC {
	if len(cscs) == 0 {
		return nil
	}

	result := make([]common.OpenVPNCSC, 0, len(cscs))
	for _, csc := range cscs {
		result = append(result, common.OpenVPNCSC{
			CommonName:      csc.Common_name,
			Block:           bool(csc.Block),
			TunnelNetwork:   csc.Tunnel_network,
			TunnelNetworkV6: csc.Tunnel_networkv6,
			LocalNetwork:    csc.Local_network,
			LocalNetworkV6:  csc.Local_networkv6,
			RemoteNetwork:   csc.Remote_network,
			RemoteNetworkV6: csc.Remote_networkv6,
			GWRedir:         bool(csc.Gwredir),
			PushReset:       bool(csc.Push_reset),
			RemoveRoute:     bool(csc.Remove_route),
			DNSDomain:       csc.DNS_domain,
			DNSServers:      collectNonEmpty(csc.DNS_server1, csc.DNS_server2, csc.DNS_server3, csc.DNS_server4),
			NTPServers:      collectNonEmpty(csc.NTP_server1, csc.NTP_server2),
		})
	}

	return result
}

// convertSyslog maps pfSense syslog to common.SyslogConfig.
// pfSense SyslogConfig only has FilterDescriptions which has no counterpart
// in common.SyslogConfig, so this returns a zero-value config. Unconverted
// fields are documented in pkg/schema/pfsense/README.md.
func (c *converter) convertSyslog(_ *pfsense.Document) common.SyslogConfig {
	return common.SyslogConfig{}
}

// convertRevision maps doc.Revision to common.Revision.
func (c *converter) convertRevision(doc *pfsense.Document) common.Revision {
	return common.Revision{
		Username:    doc.Revision.Username,
		Time:        doc.Revision.Time,
		Description: doc.Revision.Description,
	}
}

// convertCron maps doc.Cron.Items to *common.CronConfig.
// Returns nil if no cron jobs are configured.
func (c *converter) convertCron(doc *pfsense.Document) *common.CronConfig {
	if len(doc.Cron.Items) == 0 {
		return nil
	}

	commands := make([]string, 0, len(doc.Cron.Items))
	for i, item := range doc.Cron.Items {
		if item.Command == "" {
			c.addWarning(
				fmt.Sprintf("Cron.Items[%d].Command", i),
				"",
				"cron job has empty command",
				common.SeverityLow,
			)

			continue
		}

		commands = append(commands, item.Command)
	}

	if len(commands) == 0 {
		return nil
	}

	return &common.CronConfig{
		Jobs: strings.Join(commands, ","),
	}
}
