package opnsense

import (
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

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
