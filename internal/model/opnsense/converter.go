package opnsense

import (
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// Converter transforms a schema.OpnSenseDocument into a common.CommonDevice.
type Converter struct{}

// NewConverter returns a new Converter.
func NewConverter() *Converter {
	return &Converter{}
}

// ToCommonDevice converts an OPNsense schema document into a platform-agnostic CommonDevice.
// A nil doc returns an empty device with DeviceType set to OPNsense.
func (c *Converter) ToCommonDevice(doc *schema.OpnSenseDocument) (*common.CommonDevice, error) {
	if doc == nil {
		return &common.CommonDevice{
			DeviceType: common.DeviceTypeOPNsense,
		}, nil
	}

	device := &common.CommonDevice{
		DeviceType:       common.DeviceTypeOPNsense,
		Version:          doc.Version,
		Theme:            doc.Theme,
		System:           c.convertSystem(doc),
		Interfaces:       c.convertInterfaces(doc),
		VLANs:            c.convertVLANs(doc),
		FirewallRules:    c.convertFirewallRules(doc),
		NAT:              c.convertNAT(doc),
		DHCP:             c.convertDHCP(doc),
		DNS:              c.convertDNS(doc),
		NTP:              c.convertNTP(doc),
		SNMP:             c.convertSNMP(doc),
		LoadBalancer:     c.convertLoadBalancer(doc),
		VPN:              c.convertVPN(doc),
		Routing:          c.convertRouting(doc),
		HighAvailability: c.convertHA(doc),
		IDS:              c.convertIDs(doc),
		Syslog:           c.convertSyslog(doc),
		Users:            c.convertUsers(doc),
		Groups:           c.convertGroups(doc),
		Sysctl:           c.convertSysctl(doc),
		Revision:         c.convertRevision(doc),
	}

	return device, nil
}

// convertSystem maps doc.System to common.System.
func (c *Converter) convertSystem(doc *schema.OpnSenseDocument) common.System {
	sys := doc.System

	return common.System{
		Hostname:                      sys.Hostname,
		Domain:                        sys.Domain,
		Optimization:                  sys.Optimization,
		Language:                      sys.Language,
		Timezone:                      sys.Timezone,
		DNSServers:                    strings.Fields(sys.DNSServer),
		TimeServers:                   strings.Fields(sys.TimeServers),
		DNSAllowOverride:              sys.DNSAllowOverride != 0,
		DisableNATReflection:          strings.EqualFold(sys.DisableNATReflection, "yes"),
		DisableConsoleMenu:            bool(sys.DisableConsoleMenu),
		DisableVLANHWFilter:           sys.DisableVLANHWFilter != 0,
		DisableChecksumOffloading:     sys.DisableChecksumOffloading != 0,
		DisableSegmentationOffloading: sys.DisableSegmentationOffloading != 0,
		DisableLargeReceiveOffloading: sys.DisableLargeReceiveOffloading != 0,
		IPv6Allow:                     sys.IPv6Allow != "",
		PfShareForward:                sys.PfShareForward != 0,
		LbUseSticky:                   sys.LbUseSticky != 0,
		RrdBackup:                     sys.RrdBackup != 0,
		NetflowBackup:                 sys.NetflowBackup != 0,
		UseVirtualTerminal:            sys.UseVirtualTerminal != 0,
		NextUID:                       sys.NextUID,
		NextGID:                       sys.NextGID,
		PowerdACMode:                  sys.PowerdACMode,
		PowerdBatteryMode:             sys.PowerdBatteryMode,
		PowerdNormalMode:              sys.PowerdNormalMode,
		Bogons:                        common.Bogons{Interval: sys.Bogons.Interval},
		Notes:                         sys.Notes,
		WebGUI: common.WebGUI{
			Protocol:   sys.WebGUI.Protocol,
			SSLCertRef: sys.WebGUI.SSLCertRef,
		},
		SSH: common.SSH{
			Group: sys.SSH.Group,
		},
		Firmware: common.Firmware{
			Version: sys.Firmware.Version,
			Mirror:  sys.Firmware.Mirror,
			Flavour: sys.Firmware.Flavour,
			Plugins: sys.Firmware.Plugins,
		},
	}
}

// convertInterfaces maps doc.Interfaces.Items to []common.Interface.
func (c *Converter) convertInterfaces(doc *schema.OpnSenseDocument) []common.Interface {
	items := doc.Interfaces.Items
	if len(items) == 0 {
		return nil
	}

	result := make([]common.Interface, 0, len(items))
	for _, key := range slices.Sorted(maps.Keys(items)) {
		iface := items[key]
		result = append(result, common.Interface{
			Name:         key,
			PhysicalIf:   iface.If,
			Description:  iface.Descr,
			Enabled:      iface.Enable == "1",
			IPAddress:    iface.IPAddr,
			IPv6Address:  iface.IPAddrv6,
			Subnet:       iface.Subnet,
			SubnetV6:     iface.Subnetv6,
			Gateway:      iface.Gateway,
			GatewayV6:    iface.Gatewayv6,
			BlockPrivate: iface.BlockPriv == "1",
			BlockBogons:  iface.BlockBogons == "1",
			Type:         iface.Type,
			MTU:          iface.MTU,
			SpoofMAC:     iface.Spoofmac,
			DHCPHostname: iface.DHCPHostname,
			Media:        iface.Media,
			MediaOpt:     iface.MediaOpt,
			Virtual:      iface.Virtual != 0,
			Lock:         iface.Lock != 0,
		})
	}

	return result
}

// convertVLANs maps doc.VLANs.VLAN to []common.VLAN.
func (c *Converter) convertVLANs(doc *schema.OpnSenseDocument) []common.VLAN {
	if len(doc.VLANs.VLAN) == 0 {
		return nil
	}

	result := make([]common.VLAN, 0, len(doc.VLANs.VLAN))
	for _, v := range doc.VLANs.VLAN {
		result = append(result, common.VLAN{
			PhysicalIf:  v.If,
			Tag:         v.Tag,
			Description: v.Descr,
			VLANIf:      v.Vlanif,
			Created:     v.Created,
			Updated:     v.Updated,
		})
	}

	return result
}

// convertFirewallRules maps doc.Filter.Rule to []common.FirewallRule.
func (c *Converter) convertFirewallRules(doc *schema.OpnSenseDocument) []common.FirewallRule {
	if len(doc.Filter.Rule) == 0 {
		return nil
	}

	result := make([]common.FirewallRule, 0, len(doc.Filter.Rule))
	for _, rule := range doc.Filter.Rule {
		result = append(result, common.FirewallRule{
			UUID:        rule.UUID,
			Type:        rule.Type,
			Description: rule.Descr,
			Interfaces:  []string(rule.Interface),
			IPProtocol:  rule.IPProtocol,
			StateType:   rule.StateType,
			Direction:   rule.Direction,
			Floating:    rule.Floating == "yes",
			Quick:       bool(rule.Quick),
			Protocol:    rule.Protocol,
			Source: common.RuleEndpoint{
				Address: rule.Source.EffectiveAddress(),
				Port:    rule.Source.Port,
				Negated: bool(rule.Source.Not),
			},
			Destination: common.RuleEndpoint{
				Address: rule.Destination.EffectiveAddress(),
				Port:    rule.Destination.Port,
				Negated: bool(rule.Destination.Not),
			},
			Target:          rule.Target,
			Gateway:         rule.Gateway,
			Log:             bool(rule.Log),
			Disabled:        bool(rule.Disabled),
			Tracker:         rule.Tracker,
			MaxSrcNodes:     rule.MaxSrcNodes,
			MaxSrcConn:      rule.MaxSrcConn,
			MaxSrcConnRate:  rule.MaxSrcConnRate,
			MaxSrcConnRates: rule.MaxSrcConnRates,
			TCPFlags1:       rule.TCPFlags1,
			TCPFlags2:       rule.TCPFlags2,
			TCPFlagsAny:     bool(rule.TCPFlagsAny),
			ICMPType:        rule.ICMPType,
			ICMP6Type:       rule.ICMP6Type,
			StateTimeout:    rule.StateTimeout,
			AllowOpts:       bool(rule.AllowOpts),
			DisableReplyTo:  bool(rule.DisableReplyTo),
			NoPfSync:        bool(rule.NoPfSync),
			NoSync:          bool(rule.NoSync),
		})
	}

	return result
}

// convertNAT maps doc.Nat and system fields to common.NATConfig.
func (c *Converter) convertNAT(doc *schema.OpnSenseDocument) common.NATConfig {
	nat := common.NATConfig{
		OutboundMode:       doc.Nat.Outbound.Mode,
		ReflectionDisabled: strings.EqualFold(doc.System.DisableNATReflection, "yes"),
		PfShareForward:     doc.System.PfShareForward != 0,
		OutboundRules:      c.convertOutboundNATRules(doc.Nat.Outbound.Rule),
		InboundRules:       c.convertInboundNATRules(doc.Nat.Inbound),
	}

	return nat
}

// convertOutboundNATRules maps []schema.NATRule to []common.NATRule.
func (c *Converter) convertOutboundNATRules(rules []schema.NATRule) []common.NATRule {
	if len(rules) == 0 {
		return nil
	}

	result := make([]common.NATRule, 0, len(rules))
	for _, r := range rules {
		result = append(result, common.NATRule{
			UUID:       r.UUID,
			Interfaces: []string(r.Interface),
			IPProtocol: r.IPProtocol,
			Protocol:   r.Protocol,
			Source: common.RuleEndpoint{
				Address: r.Source.EffectiveAddress(),
				Port:    r.Source.Port,
			},
			Destination: common.RuleEndpoint{
				Address: r.Destination.EffectiveAddress(),
				Port:    r.Destination.Port,
			},
			Target:        r.Target,
			SourcePort:    r.SourcePort,
			NatPort:       r.NatPort,
			PoolOpts:      r.PoolOpts,
			StaticNatPort: bool(r.StaticNatPort),
			NoNat:         bool(r.NoNat),
			Disabled:      bool(r.Disabled),
			Log:           bool(r.Log),
			Description:   r.Descr,
			Category:      r.Category,
			Tag:           r.Tag,
			Tagged:        r.Tagged,
		})
	}

	return result
}

// convertInboundNATRules maps []schema.InboundRule to []common.InboundNATRule.
func (c *Converter) convertInboundNATRules(rules []schema.InboundRule) []common.InboundNATRule {
	if len(rules) == 0 {
		return nil
	}

	result := make([]common.InboundNATRule, 0, len(rules))
	for _, r := range rules {
		result = append(result, common.InboundNATRule{
			UUID:       r.UUID,
			Interfaces: []string(r.Interface),
			IPProtocol: r.IPProtocol,
			Protocol:   r.Protocol,
			Source: common.RuleEndpoint{
				Address: r.Source.EffectiveAddress(),
				Port:    r.Source.Port,
			},
			Destination: common.RuleEndpoint{
				Address: r.Destination.EffectiveAddress(),
				Port:    r.Destination.Port,
			},
			ExternalPort:     r.ExternalPort,
			InternalIP:       r.InternalIP,
			InternalPort:     r.InternalPort,
			LocalPort:        r.LocalPort,
			Reflection:       r.Reflection,
			NATReflection:    r.NATReflection,
			AssociatedRuleID: r.AssociatedRuleID,
			Priority:         r.Priority,
			NoRDR:            bool(r.NoRDR),
			NoSync:           bool(r.NoSync),
			Disabled:         bool(r.Disabled),
			Log:              bool(r.Log),
			Description:      r.Descr,
		})
	}

	return result
}

// convertDHCP maps doc.Dhcpd.Items to []common.DHCPScope.
func (c *Converter) convertDHCP(doc *schema.OpnSenseDocument) []common.DHCPScope {
	items := doc.Dhcpd.Items
	if len(items) == 0 {
		return nil
	}

	result := make([]common.DHCPScope, 0, len(items))
	for _, key := range slices.Sorted(maps.Keys(items)) {
		d := items[key]
		scope := common.DHCPScope{
			Interface:  key,
			Enabled:    d.Enable == "1",
			Range:      common.DHCPRange{From: d.Range.From, To: d.Range.To},
			Gateway:    d.Gateway,
			DNSServer:  d.Dnsserver,
			NTPServer:  d.Ntpserver,
			WINSServer: d.Winsserver,

			// Advanced DHCP fields
			AliasAddress:   d.AliasAddress,
			AliasSubnet:    d.AliasSubnet,
			DHCPRejectFrom: d.DHCPRejectFrom,

			// Advanced DHCPv4 protocol timing fields
			AdvDHCPPTTimeout:         d.AdvDHCPPTTimeout,
			AdvDHCPPTRetry:           d.AdvDHCPPTRetry,
			AdvDHCPPTSelectTimeout:   d.AdvDHCPPTSelectTimeout,
			AdvDHCPPTReboot:          d.AdvDHCPPTReboot,
			AdvDHCPPTBackoffCutoff:   d.AdvDHCPPTBackoffCutoff,
			AdvDHCPPTInitialInterval: d.AdvDHCPPTInitialInterval,
			AdvDHCPPTValues:          d.AdvDHCPPTValues,

			// Advanced DHCPv4 option fields
			AdvDHCPSendOptions:            d.AdvDHCPSendOptions,
			AdvDHCPRequestOptions:         d.AdvDHCPRequestOptions,
			AdvDHCPRequiredOptions:        d.AdvDHCPRequiredOptions,
			AdvDHCPOptionModifiers:        d.AdvDHCPOptionModifiers,
			AdvDHCPConfigAdvanced:         d.AdvDHCPConfigAdvanced,
			AdvDHCPConfigFileOverride:     d.AdvDHCPConfigFileOverride,
			AdvDHCPConfigFileOverridePath: d.AdvDHCPConfigFileOverridePath,

			// Advanced DHCPv6 fields
			Track6Interface: d.Track6Interface,
			Track6PrefixID:  d.Track6PrefixID,

			AdvDHCP6InterfaceStatementSendOptions:           d.AdvDHCP6InterfaceStatementSendOptions,
			AdvDHCP6InterfaceStatementRequestOptions:        d.AdvDHCP6InterfaceStatementRequestOptions,
			AdvDHCP6InterfaceStatementInformationOnlyEnable: d.AdvDHCP6InterfaceStatementInformationOnlyEnable,
			AdvDHCP6InterfaceStatementScript:                d.AdvDHCP6InterfaceStatementScript,
			AdvDHCP6IDAssocStatementAddressEnable:           d.AdvDHCP6IDAssocStatementAddressEnable,
			AdvDHCP6IDAssocStatementAddress:                 d.AdvDHCP6IDAssocStatementAddress,
			AdvDHCP6IDAssocStatementAddressID:               d.AdvDHCP6IDAssocStatementAddressID,
			AdvDHCP6IDAssocStatementAddressPLTime:           d.AdvDHCP6IDAssocStatementAddressPLTime,
			AdvDHCP6IDAssocStatementAddressVLTime:           d.AdvDHCP6IDAssocStatementAddressVLTime,
			AdvDHCP6IDAssocStatementPrefixEnable:            d.AdvDHCP6IDAssocStatementPrefixEnable,
			AdvDHCP6IDAssocStatementPrefix:                  d.AdvDHCP6IDAssocStatementPrefix,
			AdvDHCP6IDAssocStatementPrefixID:                d.AdvDHCP6IDAssocStatementPrefixID,
			AdvDHCP6IDAssocStatementPrefixPLTime:            d.AdvDHCP6IDAssocStatementPrefixPLTime,
			AdvDHCP6IDAssocStatementPrefixVLTime:            d.AdvDHCP6IDAssocStatementPrefixVLTime,
			AdvDHCP6PrefixInterfaceStatementSLALen:          d.AdvDHCP6PrefixInterfaceStatementSLALen,
			AdvDHCP6AuthenticationStatementAuthName:         d.AdvDHCP6AuthenticationStatementAuthName,
			AdvDHCP6AuthenticationStatementProtocol:         d.AdvDHCP6AuthenticationStatementProtocol,
			AdvDHCP6AuthenticationStatementAlgorithm:        d.AdvDHCP6AuthenticationStatementAlgorithm,
			AdvDHCP6AuthenticationStatementRDM:              d.AdvDHCP6AuthenticationStatementRDM,
			AdvDHCP6KeyInfoStatementKeyName:                 d.AdvDHCP6KeyInfoStatementKeyName,
			AdvDHCP6KeyInfoStatementRealm:                   d.AdvDHCP6KeyInfoStatementRealm,
			AdvDHCP6KeyInfoStatementKeyID:                   d.AdvDHCP6KeyInfoStatementKeyID,
			AdvDHCP6KeyInfoStatementSecret:                  d.AdvDHCP6KeyInfoStatementSecret,
			AdvDHCP6KeyInfoStatementExpire:                  d.AdvDHCP6KeyInfoStatementExpire,
			AdvDHCP6ConfigAdvanced:                          d.AdvDHCP6ConfigAdvanced,
			AdvDHCP6ConfigFileOverride:                      d.AdvDHCP6ConfigFileOverride,
			AdvDHCP6ConfigFileOverridePath:                  d.AdvDHCP6ConfigFileOverridePath,
		}

		scope.StaticLeases = c.convertStaticLeases(d.Staticmap)
		scope.NumberOptions = c.convertNumberOptions(d.NumberOptions)

		result = append(result, scope)
	}

	return result
}

// convertStaticLeases maps []schema.DHCPStaticLease to []common.DHCPStaticLease.
func (c *Converter) convertStaticLeases(leases []schema.DHCPStaticLease) []common.DHCPStaticLease {
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

// convertNumberOptions maps []schema.DHCPNumberOption to []common.DHCPNumberOption.
func (c *Converter) convertNumberOptions(opts []schema.DHCPNumberOption) []common.DHCPNumberOption {
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

// convertDNS maps doc.Unbound, doc.DNSMasquerade, and system DNS to common.DNSConfig.
func (c *Converter) convertDNS(doc *schema.OpnSenseDocument) common.DNSConfig {
	return common.DNSConfig{
		Servers: strings.Fields(doc.System.DNSServer),
		Unbound: common.UnboundConfig{
			Enabled:        doc.Unbound.Enable == "1",
			DNSSEC:         doc.Unbound.Dnssec == "1",
			DNSSECStripped: doc.Unbound.Dnssecstripped == "1",
		},
		DNSMasq: common.DNSMasqConfig{
			Enabled:         bool(doc.DNSMasquerade.Enable),
			Hosts:           c.convertDNSMasqHosts(doc.DNSMasquerade.Hosts),
			DomainOverrides: c.convertDomainOverrides(doc.DNSMasquerade.DomainOverrides),
			Forwarders:      c.convertForwarders(doc.DNSMasquerade.Forwarders),
		},
	}
}

// convertDNSMasqHosts maps []schema.DNSMasqHost to []common.DNSMasqHost.
func (c *Converter) convertDNSMasqHosts(hosts []schema.DNSMasqHost) []common.DNSMasqHost {
	if len(hosts) == 0 {
		return nil
	}

	result := make([]common.DNSMasqHost, 0, len(hosts))
	for _, h := range hosts {
		result = append(result, common.DNSMasqHost{
			Host:        h.Host,
			Domain:      h.Domain,
			IP:          h.IP,
			Description: h.Descr,
			Aliases:     h.Aliases,
		})
	}

	return result
}

// convertDomainOverrides maps []schema.DomainOverride to []common.DomainOverride.
func (c *Converter) convertDomainOverrides(overrides []schema.DomainOverride) []common.DomainOverride {
	if len(overrides) == 0 {
		return nil
	}

	result := make([]common.DomainOverride, 0, len(overrides))
	for _, o := range overrides {
		result = append(result, common.DomainOverride{
			Domain:      o.Domain,
			IP:          o.IP,
			Description: o.Descr,
		})
	}

	return result
}

// convertForwarders maps []schema.ForwarderGroup to []common.ForwarderGroup.
func (c *Converter) convertForwarders(fwds []schema.ForwarderGroup) []common.ForwarderGroup {
	if len(fwds) == 0 {
		return nil
	}

	result := make([]common.ForwarderGroup, 0, len(fwds))
	for _, f := range fwds {
		result = append(result, common.ForwarderGroup{
			IP:          f.IP,
			Port:        f.Port,
			Description: f.Descr,
		})
	}

	return result
}

// convertVPN maps OpenVPN, WireGuard, and IPsec sections to common.VPN.
func (c *Converter) convertVPN(doc *schema.OpnSenseDocument) common.VPN {
	vpn := common.VPN{
		OpenVPN: common.OpenVPNConfig{
			Servers: c.convertOpenVPNServers(doc.OpenVPN.Servers),
			Clients: c.convertOpenVPNClients(doc.OpenVPN.Clients),
		},
	}

	if doc.OPNsense.Wireguard != nil {
		vpn.WireGuard = c.convertWireGuard(doc.OPNsense.Wireguard)
	}

	if doc.OPNsense.IPsec != nil {
		vpn.IPsec = common.IPsecConfig{
			Enabled: doc.OPNsense.IPsec.General.Enabled == "1",
		}
	}

	return vpn
}

// convertOpenVPNServers maps []schema.OpenVPNServer to []common.OpenVPNServer.
func (c *Converter) convertOpenVPNServers(servers []schema.OpenVPNServer) []common.OpenVPNServer {
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

// convertOpenVPNClients maps []schema.OpenVPNClient to []common.OpenVPNClient.
func (c *Converter) convertOpenVPNClients(clients []schema.OpenVPNClient) []common.OpenVPNClient {
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

// convertWireGuard maps *schema.WireGuard to common.WireGuardConfig.
func (c *Converter) convertWireGuard(wg *schema.WireGuard) common.WireGuardConfig {
	cfg := common.WireGuardConfig{
		Enabled: wg.General.Enabled == "1",
	}

	for _, s := range wg.Server.Servers.Server {
		cfg.Servers = append(cfg.Servers, common.WireGuardServer{
			UUID:          s.UUID,
			Enabled:       s.Enabled == "1",
			Name:          s.Name,
			PublicKey:     s.Pubkey,
			Port:          s.Port,
			MTU:           s.MTU,
			TunnelAddress: s.Tunneladdress,
			DNS:           s.DNS,
			Gateway:       s.Gateway,
		})
	}

	for _, cl := range wg.Client.Clients.Client {
		cfg.Clients = append(cfg.Clients, common.WireGuardClient{
			UUID:          cl.UUID,
			Enabled:       cl.Enabled == "1",
			Name:          cl.Name,
			PublicKey:     cl.Pubkey,
			PSK:           cl.PSK,
			TunnelAddress: cl.Tunneladdress,
			ServerAddress: cl.Serveraddress,
			ServerPort:    cl.Serverport,
			Keepalive:     cl.Keepalive,
		})
	}

	return cfg
}

// convertRouting maps doc.Gateways and doc.StaticRoutes to common.Routing.
func (c *Converter) convertRouting(doc *schema.OpnSenseDocument) common.Routing {
	return common.Routing{
		Gateways:      c.convertGateways(doc.Gateways.Gateway),
		GatewayGroups: c.convertGatewayGroups(doc.Gateways.Groups),
		StaticRoutes:  c.convertStaticRoutes(doc.StaticRoutes.Route),
	}
}

// convertGateways maps []schema.Gateway to []common.Gateway.
func (c *Converter) convertGateways(gws []schema.Gateway) []common.Gateway {
	if len(gws) == 0 {
		return nil
	}

	result := make([]common.Gateway, 0, len(gws))
	for _, gw := range gws {
		result = append(result, common.Gateway{
			Interface:      gw.Interface,
			Address:        gw.Gateway,
			Name:           gw.Name,
			Weight:         gw.Weight,
			IPProtocol:     gw.IPProtocol,
			Interval:       gw.Interval,
			Description:    gw.Descr,
			Monitor:        gw.Monitor,
			Disabled:       bool(gw.Disabled),
			DefaultGW:      gw.DefaultGW,
			MonitorDisable: gw.MonitorDisable,
			FarGW:          gw.FarGW == "1",
		})
	}

	return result
}

// convertGatewayGroups maps []schema.GatewayGroup to []common.GatewayGroup.
func (c *Converter) convertGatewayGroups(groups []schema.GatewayGroup) []common.GatewayGroup {
	if len(groups) == 0 {
		return nil
	}

	result := make([]common.GatewayGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, common.GatewayGroup{
			Name:        g.Name,
			Items:       g.Item,
			Trigger:     g.Trigger,
			Description: g.Descr,
		})
	}

	return result
}

// convertStaticRoutes maps []schema.StaticRoute to []common.StaticRoute.
func (c *Converter) convertStaticRoutes(routes []schema.StaticRoute) []common.StaticRoute {
	if len(routes) == 0 {
		return nil
	}

	result := make([]common.StaticRoute, 0, len(routes))
	for _, r := range routes {
		result = append(result, common.StaticRoute{
			Network:     r.Network,
			Gateway:     r.Gateway,
			Description: r.Descr,
			Disabled:    bool(r.Disabled),
			Created:     r.Created,
			Updated:     r.Updated,
		})
	}

	return result
}

// convertHA maps doc.HighAvailabilitySync to common.HighAvailability.
func (c *Converter) convertHA(doc *schema.OpnSenseDocument) common.HighAvailability {
	ha := doc.HighAvailabilitySync

	return common.HighAvailability{
		DisablePreempt:  ha.Disablepreempt != "",
		DisconnectPPPs:  ha.Disconnectppps != "",
		PfsyncInterface: ha.Pfsyncinterface,
		PfsyncPeerIP:    ha.Pfsyncpeerip,
		PfsyncVersion:   ha.Pfsyncversion,
		SynchronizeToIP: ha.Synchronizetoip,
		Username:        ha.Username,
		Password:        ha.Password,
		SyncItems:       ha.Syncitems,
	}
}

// convertIDs maps doc.OPNsense.IntrusionDetectionSystem to *common.IDSConfig.
func (c *Converter) convertIDs(doc *schema.OpnSenseDocument) *common.IDSConfig {
	ids := doc.OPNsense.IntrusionDetectionSystem
	if ids == nil {
		return nil
	}

	return &common.IDSConfig{
		Enabled:           ids.IsEnabled(),
		IPSMode:           ids.IsIPSMode(),
		Promiscuous:       ids.IsPromiscuousMode(),
		Interfaces:        ids.GetMonitoredInterfaces(),
		HomeNetworks:      ids.GetHomeNetworks(),
		SyslogEnabled:     ids.IsSyslogEnabled(),
		SyslogEveEnabled:  ids.IsSyslogEveEnabled(),
		MPMAlgo:           ids.General.MPMAlgo,
		DefaultPacketSize: ids.General.DefaultPacketSize,
		LogPayload:        ids.General.LogPayload,
		Verbosity:         ids.General.Verbosity,
		AlertLogrotate:    ids.General.AlertLogrotate,
		AlertSaveLogs:     ids.General.AlertSaveLogs,
		UpdateCron:        ids.General.UpdateCron,
		Detect: common.IDSDetect{
			Profile:        ids.General.Detect.Profile,
			ToclientGroups: ids.General.Detect.ToclientGroups,
			ToserverGroups: ids.General.Detect.ToserverGroups,
		},
	}
}

// convertSyslog maps doc.Syslog to common.SyslogConfig.
func (c *Converter) convertSyslog(doc *schema.OpnSenseDocument) common.SyslogConfig {
	sl := doc.Syslog

	return common.SyslogConfig{
		Enabled:       bool(sl.Enable),
		SystemLogging: bool(sl.System),
		AuthLogging:   bool(sl.Auth),
		FilterLogging: bool(sl.Filter),
		DHCPLogging:   bool(sl.Dhcp),
		VPNLogging:    bool(sl.VPN),
		RemoteServer:  sl.Remoteserver,
		RemoteServer2: sl.Remoteserver2,
		RemoteServer3: sl.Remoteserver3,
		SourceIP:      sl.Sourceip,
		IPProtocol:    sl.IPProtocol,
		LogFileSize:   sl.LogFilesize,
		RotateCount:   sl.RotateCount,
		Format:        sl.Format,
	}
}

// convertUsers maps doc.System.User to []common.User.
func (c *Converter) convertUsers(doc *schema.OpnSenseDocument) []common.User {
	if len(doc.System.User) == 0 {
		return nil
	}

	result := make([]common.User, 0, len(doc.System.User))
	for _, u := range doc.System.User {
		user := common.User{
			Name:        u.Name,
			Disabled:    bool(u.Disabled),
			Description: u.Descr,
			Scope:       u.Scope,
			GroupName:   u.Groupname,
			UID:         u.UID,
		}

		if len(u.APIKeys) > 0 {
			user.APIKeys = make([]common.APIKey, 0, len(u.APIKeys))
			for _, k := range u.APIKeys {
				user.APIKeys = append(user.APIKeys, common.APIKey{
					Key:         k.Key,
					Secret:      k.Secret,
					Privileges:  k.Privileges,
					Scope:       k.Scope,
					UID:         k.UID,
					GID:         k.GID,
					Description: k.Description,
				})
			}
		}

		result = append(result, user)
	}

	return result
}

// convertGroups maps doc.System.Group to []common.Group.
func (c *Converter) convertGroups(doc *schema.OpnSenseDocument) []common.Group {
	if len(doc.System.Group) == 0 {
		return nil
	}

	result := make([]common.Group, 0, len(doc.System.Group))
	for _, g := range doc.System.Group {
		result = append(result, common.Group{
			Name:        g.Name,
			Description: g.Description,
			Scope:       g.Scope,
			GID:         g.Gid,
			Member:      g.Member,
			Privileges:  g.Priv,
		})
	}

	return result
}

// convertSysctl maps doc.Sysctl to []common.SysctlItem.
func (c *Converter) convertSysctl(doc *schema.OpnSenseDocument) []common.SysctlItem {
	if len(doc.Sysctl) == 0 {
		return nil
	}

	result := make([]common.SysctlItem, 0, len(doc.Sysctl))
	for _, s := range doc.Sysctl {
		result = append(result, common.SysctlItem{
			Tunable:     s.Tunable,
			Value:       s.Value,
			Description: s.Descr,
		})
	}

	return result
}

// convertRevision maps doc.Revision to common.Revision.
func (c *Converter) convertRevision(doc *schema.OpnSenseDocument) common.Revision {
	return common.Revision{
		Username:    doc.Revision.Username,
		Time:        doc.Revision.Time,
		Description: doc.Revision.Description,
	}
}

// convertNTP maps doc.Ntpd to common.NTPConfig.
func (c *Converter) convertNTP(doc *schema.OpnSenseDocument) common.NTPConfig {
	return common.NTPConfig{
		PreferredServer: doc.Ntpd.Prefer,
	}
}

// convertSNMP maps doc.Snmpd to common.SNMPConfig.
func (c *Converter) convertSNMP(doc *schema.OpnSenseDocument) common.SNMPConfig {
	return common.SNMPConfig{
		ROCommunity: doc.Snmpd.ROCommunity,
		SysLocation: doc.Snmpd.SysLocation,
		SysContact:  doc.Snmpd.SysContact,
	}
}

// convertLoadBalancer maps doc.LoadBalancer.MonitorType to common.LoadBalancerConfig.
func (c *Converter) convertLoadBalancer(doc *schema.OpnSenseDocument) common.LoadBalancerConfig {
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

// collectNonEmpty returns a slice containing only non-empty strings from the input.
func collectNonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			result = append(result, v)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}
