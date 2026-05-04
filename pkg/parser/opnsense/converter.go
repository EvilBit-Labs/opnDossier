package opnsense

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
)

// ErrNilDocument is returned when ToCommonDevice receives a nil document.
var ErrNilDocument = errors.New("opnsense converter: received nil document")

// converter transforms a schema.OpnSenseDocument into a common.CommonDevice.
// A converter is stateful (it accumulates warnings) and is NOT safe for
// concurrent use. Create a new instance per conversion via newConverter().
type converter struct {
	warnings []common.ConversionWarning
}

// newConverter returns a new converter.
func newConverter() *converter {
	return &converter{}
}

// ConvertDocument transforms a parsed OpnSenseDocument into a platform-agnostic
// CommonDevice along with any non-fatal conversion warnings. This is a
// convenience function that creates a fresh converter internally.
func ConvertDocument(doc *schema.OpnSenseDocument) (*common.CommonDevice, []common.ConversionWarning, error) {
	return newConverter().ToCommonDevice(doc)
}

// addWarning records a non-fatal conversion issue.
func (c *converter) addWarning(field, value, message string, severity common.Severity) {
	c.warnings = append(c.warnings, common.ConversionWarning{
		Field:    field,
		Value:    value,
		Message:  message,
		Severity: severity,
	})
}

// ToCommonDevice converts an OPNsense schema document into a platform-agnostic CommonDevice.
// Returns ErrNilDocument if doc is nil.
func (c *converter) ToCommonDevice(
	doc *schema.OpnSenseDocument,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	c.warnings = nil

	if doc == nil {
		return nil, nil, fmt.Errorf("ToCommonDevice: %w", ErrNilDocument)
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
		DHCP:             append(c.convertDHCP(doc), c.convertKeaDHCPScopes(doc)...),
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

	return device, c.warnings, nil
}

// convertSystem maps doc.System to common.System.
// NOTE: SSH and WebGUI sub-structs are partially mapped; some fields
// (SSH.Enabled, SSH.Port, WebGUI.LoginAutocomplete, etc.) are not yet populated.
func (c *converter) convertSystem(doc *schema.OpnSenseDocument) common.System {
	sys := doc.System

	return common.System{
		Hostname:                      sys.Hostname,
		Domain:                        sys.Domain,
		Optimization:                  sys.Optimization,
		Language:                      sys.Language,
		Timezone:                      sys.Timezone,
		DNSServers:                    strings.Fields(sys.DNSServer),
		TimeServers:                   strings.Fields(sys.TimeServers),
		DNSAllowOverride:              bool(sys.DNSAllowOverride),
		DisableNATReflection:          shared.IsValueTrue(sys.DisableNATReflection),
		DisableConsoleMenu:            bool(sys.DisableConsoleMenu),
		DisableVLANHWFilter:           bool(sys.DisableVLANHWFilter),
		DisableChecksumOffloading:     bool(sys.DisableChecksumOffloading),
		DisableSegmentationOffloading: bool(sys.DisableSegmentationOffloading),
		DisableLargeReceiveOffloading: bool(sys.DisableLargeReceiveOffloading),
		IPv6Allow:                     sys.IPv6Allow != "",
		PfShareForward:                bool(sys.PfShareForward),
		LbUseSticky:                   bool(sys.LbUseSticky),
		RrdBackup:                     bool(sys.RrdBackup),
		NetflowBackup:                 bool(sys.NetflowBackup),
		UseVirtualTerminal:            bool(sys.UseVirtualTerminal),
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
func (c *converter) convertInterfaces(doc *schema.OpnSenseDocument) []common.Interface {
	items := doc.Interfaces.Items
	if len(items) == 0 {
		return nil
	}

	// Collect-then-sort uses a single allocation. slices.Sorted(maps.Keys)
	// allocates the iter.Seq closure plus grows the result slice during
	// collect — measured 7-11 allocs vs 1 across 8-128 entry maps.
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	result := make([]common.Interface, 0, len(items))
	for _, key := range keys {
		iface := items[key]
		result = append(result, common.Interface{
			Name:         key,
			PhysicalIf:   iface.If,
			Description:  iface.Descr,
			Enabled:      iface.Enable == xmlBoolTrue,
			IPAddress:    iface.IPAddr,
			IPv6Address:  iface.IPAddrv6,
			Subnet:       iface.Subnet,
			SubnetV6:     iface.Subnetv6,
			Gateway:      iface.Gateway,
			GatewayV6:    iface.Gatewayv6,
			BlockPrivate: iface.BlockPriv == xmlBoolTrue,
			BlockBogons:  iface.BlockBogons == xmlBoolTrue,
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
func (c *converter) convertVLANs(doc *schema.OpnSenseDocument) []common.VLAN {
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
func (c *converter) convertFirewallRules(doc *schema.OpnSenseDocument) []common.FirewallRule {
	if len(doc.Filter.Rule) == 0 {
		return nil
	}

	result := make([]common.FirewallRule, 0, len(doc.Filter.Rule))
	for i, rule := range doc.Filter.Rule {
		if rule.Type == "" {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].Type", i),
				rule.UUID,
				"firewall rule has empty type",
				common.SeverityHigh,
			)
		}
		if rule.Source.EffectiveAddress() == "" {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].Source", i),
				rule.UUID,
				"firewall rule has no source address",
				common.SeverityMedium,
			)
		}
		if rule.Destination.EffectiveAddress() == "" {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].Destination", i),
				rule.UUID,
				"firewall rule has no destination address",
				common.SeverityMedium,
			)
		}
		if rule.Interface.IsEmpty() {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].Interface", i),
				rule.UUID,
				"firewall rule has no interface assigned",
				common.SeverityMedium,
			)
		}

		ruleType := common.FirewallRuleType(rule.Type)
		if rule.Type != "" && !ruleType.IsValid() {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].Type", i),
				rule.Type,
				"unrecognized firewall rule type",
				common.SeverityLow,
			)
		}
		direction := common.FirewallDirection(rule.Direction)
		if rule.Direction != "" && !direction.IsValid() {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].Direction", i),
				rule.Direction,
				"unrecognized firewall direction",
				common.SeverityLow,
			)
		}
		ipProto := common.IPProtocol(rule.IPProtocol)
		if rule.IPProtocol != "" && !ipProto.IsValid() {
			c.addWarning(
				fmt.Sprintf("FirewallRules[%d].IPProtocol", i),
				rule.IPProtocol,
				"unrecognized IP protocol family",
				common.SeverityLow,
			)
		}

		result = append(result, common.FirewallRule{
			UUID:        rule.UUID,
			Type:        ruleType,
			Description: rule.Descr,
			Interfaces:  []string(rule.Interface),
			IPProtocol:  ipProto,
			StateType:   rule.StateType,
			Direction:   direction,
			Floating:    rule.Floating == xmlBoolYes,
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
func (c *converter) convertNAT(doc *schema.OpnSenseDocument) common.NATConfig {
	outboundMode := common.NATOutboundMode(doc.Nat.Outbound.Mode)
	if doc.Nat.Outbound.Mode != "" && !outboundMode.IsValid() {
		c.addWarning(
			"NAT.OutboundMode",
			doc.Nat.Outbound.Mode,
			"unrecognized NAT outbound mode",
			common.SeverityLow,
		)
	}

	nat := common.NATConfig{
		OutboundMode:       outboundMode,
		ReflectionDisabled: shared.IsValueTrue(doc.System.DisableNATReflection),
		PfShareForward:     bool(doc.System.PfShareForward),
		OutboundRules:      c.convertOutboundNATRules(doc.Nat.Outbound.Rule),
		InboundRules:       c.convertInboundNATRules(doc.Nat.Inbound),
	}

	return nat
}

// convertOutboundNATRules maps []schema.NATRule to []common.NATRule.
func (c *converter) convertOutboundNATRules(rules []schema.NATRule) []common.NATRule {
	if len(rules) == 0 {
		return nil
	}

	result := make([]common.NATRule, 0, len(rules))
	for i, r := range rules {
		if r.Interface.IsEmpty() {
			c.addWarning(
				fmt.Sprintf("NAT.OutboundRules[%d].Interface", i),
				r.UUID,
				"outbound NAT rule has no interface assigned",
				common.SeverityMedium,
			)
		}

		ipProto := common.IPProtocol(r.IPProtocol)
		if r.IPProtocol != "" && !ipProto.IsValid() {
			c.addWarning(
				fmt.Sprintf("NAT.OutboundRules[%d].IPProtocol", i),
				r.IPProtocol,
				"unrecognized IP protocol family",
				common.SeverityLow,
			)
		}

		result = append(result, common.NATRule{
			UUID:       r.UUID,
			Interfaces: []string(r.Interface),
			IPProtocol: ipProto,
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
func (c *converter) convertInboundNATRules(rules []schema.InboundRule) []common.InboundNATRule {
	if len(rules) == 0 {
		return nil
	}

	result := make([]common.InboundNATRule, 0, len(rules))
	for i, r := range rules {
		if r.InternalIP == "" {
			c.addWarning(
				fmt.Sprintf("NAT.InboundRules[%d].InternalIP", i),
				r.UUID,
				"inbound NAT rule has no internal IP",
				common.SeverityHigh,
			)
		}
		if r.Interface.IsEmpty() {
			c.addWarning(
				fmt.Sprintf("NAT.InboundRules[%d].Interface", i),
				r.UUID,
				"inbound NAT rule has no interface assigned",
				common.SeverityMedium,
			)
		}

		ipProto := common.IPProtocol(r.IPProtocol)
		if r.IPProtocol != "" && !ipProto.IsValid() {
			c.addWarning(
				fmt.Sprintf("NAT.InboundRules[%d].IPProtocol", i),
				r.IPProtocol,
				"unrecognized IP protocol family",
				common.SeverityLow,
			)
		}

		result = append(result, common.InboundNATRule{
			UUID:       r.UUID,
			Interfaces: []string(r.Interface),
			IPProtocol: ipProto,
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
