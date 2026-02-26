package opnsense

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// ErrNilDocument is returned when ToCommonDevice receives a nil document.
var ErrNilDocument = errors.New("opnsense converter: received nil document")

// Converter transforms a schema.OpnSenseDocument into a common.CommonDevice.
type Converter struct{}

// NewConverter returns a new Converter.
func NewConverter() *Converter {
	return &Converter{}
}

// ToCommonDevice converts an OPNsense schema document into a platform-agnostic CommonDevice.
// Returns ErrNilDocument if doc is nil.
func (c *Converter) ToCommonDevice(doc *schema.OpnSenseDocument) (*common.CommonDevice, error) {
	if doc == nil {
		return nil, fmt.Errorf("ToCommonDevice: %w", ErrNilDocument)
	}

	device := &common.CommonDevice{
		DeviceType:       common.DeviceTypeOPNsense,
		Version:          doc.Version,
		Theme:            doc.Theme,
		System:           c.convertSystem(doc),
		Interfaces:       c.convertInterfaces(doc),
		VLANs:            c.convertVLANs(doc),
		Bridges:          c.convertBridges(doc),
		PPPs:             c.convertPPPs(doc),
		GIFs:             c.convertGIFs(doc),
		GREs:             c.convertGREs(doc),
		LAGGs:            c.convertLAGGs(doc),
		VirtualIPs:       c.convertVirtualIPs(doc),
		InterfaceGroups:  c.convertInterfaceGroups(doc),
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
		Certificates:     c.convertCertificates(doc),
		CAs:              c.convertCAs(doc),
		Packages:         c.convertPackages(doc),
		Monit:            c.convertMonit(doc),
		Netflow:          c.convertNetflow(doc),
		TrafficShaper:    c.convertTrafficShaper(doc),
		CaptivePortal:    c.convertCaptivePortal(doc),
		Cron:             c.convertCron(doc),
		Trust:            c.convertTrust(doc),
		KeaDHCP:          c.convertKeaDHCP(doc),
	}

	return device, nil
}

// convertSystem maps doc.System to common.System.
// NOTE: SSH and WebGUI sub-structs are partially mapped; some fields
// (SSH.Enabled, SSH.Port, WebGUI.LoginAutocomplete, etc.) are not yet populated.
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
			Protocol:          sys.WebGUI.Protocol,
			SSLCertRef:        sys.WebGUI.SSLCertRef,
			LoginAutocomplete: bool(sys.WebGUI.LoginAutocomplete),
			MaxProcesses:      sys.WebGUI.MaxProcesses,
		},
		SSH: common.SSH{
			Enabled: bool(sys.SSH.Enabled),
			Port:    sys.SSH.Port,
			Group:   sys.SSH.Group,
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
