package pfsense

import (
	"fmt"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// convertFirewallRules maps doc.Filter.Rule to []common.FirewallRule.
func (c *converter) convertFirewallRules(doc *pfsense.Document) []common.FirewallRule {
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
func (c *converter) convertNAT(doc *pfsense.Document) common.NATConfig {
	outboundMode := common.NATOutboundMode(doc.Nat.Outbound.Mode)
	if doc.Nat.Outbound.Mode != "" && !outboundMode.IsValid() {
		c.addWarning(
			"NAT.OutboundMode",
			doc.Nat.Outbound.Mode,
			"unrecognized NAT outbound mode",
			common.SeverityLow,
		)
	}

	return common.NATConfig{
		OutboundMode:       outboundMode,
		ReflectionDisabled: strings.EqualFold(doc.System.DisableNATReflection, xmlBoolYes),
		OutboundRules:      c.convertOutboundNATRules(doc.Nat.Outbound.Rule),
		InboundRules:       c.convertInboundNATRules(doc.Nat.Inbound),
	}
}

// convertOutboundNATRules maps []opnsense.NATRule to []common.NATRule.
func (c *converter) convertOutboundNATRules(rules []opnsense.NATRule) []common.NATRule {
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

// convertInboundNATRules maps []pfsense.InboundRule to []common.InboundNATRule.
// pfSense uses <target> for the internal redirect IP, with fallback to <internalip>.
func (c *converter) convertInboundNATRules(rules []pfsense.InboundRule) []common.InboundNATRule {
	if len(rules) == 0 {
		return nil
	}

	result := make([]common.InboundNATRule, 0, len(rules))
	for i, r := range rules {
		internalIP := r.Target
		if internalIP == "" {
			internalIP = r.InternalIP
		}

		if internalIP == "" {
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
			InternalIP:       internalIP,
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

// convertCertificates maps doc.Certs to []common.Certificate.
func (c *converter) convertCertificates(doc *pfsense.Document) []common.Certificate {
	if len(doc.Certs) == 0 {
		return nil
	}

	result := make([]common.Certificate, 0, len(doc.Certs))
	for i, cert := range doc.Certs {
		if cert.Crt == "" {
			c.addWarning(
				fmt.Sprintf("Certificates[%d].Certificate", i),
				cert.Descr,
				"certificate has empty PEM data",
				common.SeverityHigh,
			)
		}

		result = append(result, common.Certificate{
			RefID:       cert.Refid,
			Description: cert.Descr,
			Certificate: cert.Crt,
			PrivateKey:  cert.Prv,
		})
	}

	return result
}

// convertCAs maps doc.CAs to []common.CertificateAuthority.
func (c *converter) convertCAs(doc *pfsense.Document) []common.CertificateAuthority {
	if len(doc.CAs) == 0 {
		return nil
	}

	result := make([]common.CertificateAuthority, 0, len(doc.CAs))
	for _, ca := range doc.CAs {
		result = append(result, common.CertificateAuthority{
			RefID:       ca.Refid,
			Description: ca.Descr,
			Certificate: ca.Crt,
			PrivateKey:  ca.Prv,
			Serial:      ca.Serial,
		})
	}

	return result
}
