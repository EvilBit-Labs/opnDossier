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

// convertVPN maps OpenVPN sections to common.VPN.
// pfSense Document does not include WireGuard or IPsec subsystems.
func (c *converter) convertVPN(doc *pfsense.Document) common.VPN {
	return common.VPN{
		OpenVPN: common.OpenVPNConfig{
			Servers:               c.convertOpenVPNServers(doc.OpenVPN.Servers),
			Clients:               c.convertOpenVPNClients(doc.OpenVPN.Clients),
			ClientSpecificConfigs: c.convertOpenVPNCSCs(doc.OpenVPN.CSC),
		},
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
