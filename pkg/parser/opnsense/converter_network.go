package opnsense

import (
	"fmt"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// convertBridges maps doc.Bridges.Bridge to []common.Bridge.
// Bridge members are stored as a comma-separated string in OPNsense XML and
// split into individual interface names for the platform-agnostic model.
//
// Empty <bridged/> placeholders are skipped so they neither surface as blank
// bridges in exported output nor inflate Statistics.TotalBridges. The result is
// grown on demand rather than preallocated because the loop may skip entries.
func (c *converter) convertBridges(doc *schema.OpnSenseDocument) []common.Bridge {
	var result []common.Bridge

	for _, b := range doc.Bridges.Bridge {
		if b.IsPlaceholder() {
			continue
		}

		result = append(result, common.Bridge{
			BridgeIf:    b.Bridgeif,
			Members:     splitNonEmpty(b.Members, ","),
			Description: b.Descr,
			STP:         bool(b.STP),
			Created:     b.Created,
			Updated:     b.Updated,
		})
	}

	return result
}

// convertPPPs maps doc.PPPInterfaces.Ppp to []common.PPP.
// PPP entries represent point-to-point protocol connections (PPPoE, PPTP, L2TP).
//
// Empty <ppp/> placeholders are skipped so they do not surface as blank PPP
// links in exported output. The result is grown on demand rather than
// preallocated because the loop may skip entries.
func (c *converter) convertPPPs(doc *schema.OpnSenseDocument) []common.PPP {
	var result []common.PPP

	for _, p := range doc.PPPInterfaces.Ppp {
		if p.IsPlaceholder() {
			continue
		}

		result = append(result, common.PPP{
			Interface:   p.If,
			Type:        p.Type,
			Description: p.Descr,
		})
	}

	return result
}

// convertGIFs maps doc.GIFInterfaces.Gif to []common.GIF.
// GIF (Generic Tunnel Interface) entries encapsulate IPv4-in-IPv4 or IPv6-in-IPv4
// tunnels. The Gifif field is the tunnel interface name (e.g., "gif0"), while If
// is the parent physical interface.
//
// Empty <gif/> placeholders are skipped; see GOTCHAS.md section 3.4. The result
// is grown on demand rather than preallocated because the loop may skip entries.
func (c *converter) convertGIFs(doc *schema.OpnSenseDocument) []common.GIF {
	var result []common.GIF

	for _, g := range doc.GIFInterfaces.Gif {
		if g.IsPlaceholder() {
			continue
		}

		result = append(result, common.GIF{
			Interface:   g.Gifif,
			Local:       g.If,
			Remote:      g.Remote,
			Description: g.Descr,
			Created:     g.Created,
			Updated:     g.Updated,
		})
	}

	return result
}

// convertGREs maps doc.GREInterfaces.Gre to []common.GRE.
// GRE (Generic Routing Encapsulation) entries define point-to-point tunnel
// interfaces. The Greif field is the tunnel interface name (e.g., "gre0"), while
// If is the parent physical interface.
//
// Empty <gre/> placeholders are skipped; see GOTCHAS.md section 3.4. The result
// is grown on demand rather than preallocated because the loop may skip entries.
func (c *converter) convertGREs(doc *schema.OpnSenseDocument) []common.GRE {
	var result []common.GRE

	for _, g := range doc.GREInterfaces.Gre {
		if g.IsPlaceholder() {
			continue
		}

		result = append(result, common.GRE{
			Interface:   g.Greif,
			Local:       g.If,
			Remote:      g.Remote,
			Description: g.Descr,
			Created:     g.Created,
			Updated:     g.Updated,
		})
	}

	return result
}

// convertLAGGs maps doc.LAGGInterfaces.Lagg to []common.LAGG.
// LAGG (Link Aggregation) entries bond multiple physical interfaces under
// a single logical interface. Members are comma-separated in the XML.
//
// Empty <lagg/> placeholders are skipped; see GOTCHAS.md section 3.4. The result
// is grown on demand rather than preallocated because the loop may skip entries.
func (c *converter) convertLAGGs(doc *schema.OpnSenseDocument) []common.LAGG {
	var result []common.LAGG

	for _, l := range doc.LAGGInterfaces.Lagg {
		if l.IsPlaceholder() {
			continue
		}

		proto := common.LAGGProtocol(l.Proto)
		if l.Proto != "" && !proto.IsValid() {
			// len(result) is the index this entry will occupy in the output.
			// The raw loop index would drift once a placeholder is skipped.
			c.addWarning(
				fmt.Sprintf("LAGGs[%d].Protocol", len(result)),
				l.Proto,
				"unrecognized LAGG protocol",
				common.SeverityLow,
			)
		}
		result = append(result, common.LAGG{
			Interface:   l.Laggif,
			Members:     splitNonEmpty(l.Members, ","),
			Protocol:    proto,
			Description: l.Descr,
			Created:     l.Created,
			Updated:     l.Updated,
		})
	}

	return result
}

// convertVirtualIPs maps doc.VirtualIP.Vip to []common.VirtualIP.
// Virtual IP modes include "carp" (HA failover), "ipalias" (additional addresses),
// and "proxyarp" (ARP proxying for downstream hosts).
//
// Empty <vip/> placeholders are skipped; see GOTCHAS.md section 3.4. The result
// is grown on demand rather than preallocated because the loop may skip entries.
func (c *converter) convertVirtualIPs(doc *schema.OpnSenseDocument) []common.VirtualIP {
	var result []common.VirtualIP

	for _, v := range doc.VirtualIP.Vip {
		if v.IsPlaceholder() {
			continue
		}

		mode := common.VIPMode(v.Mode)
		if v.Mode != "" && !mode.IsValid() {
			// len(result) is the index this entry will occupy in the output.
			// The raw loop index would drift once a placeholder is skipped.
			c.addWarning(
				fmt.Sprintf("VirtualIPs[%d].Mode", len(result)),
				v.Mode,
				"unrecognized virtual IP mode",
				common.SeverityLow,
			)
		}
		result = append(result, common.VirtualIP{
			Mode:        mode,
			Interface:   v.Interface,
			Subnet:      v.Subnet,
			Description: v.Descr,
		})
	}

	return result
}

// convertInterfaceGroups maps doc.InterfaceGroups.IfGroupEntry to []common.InterfaceGroup.
// Interface group members are space-separated in OPNsense XML, unlike bridge and
// LAGG members which use commas.
func (c *converter) convertInterfaceGroups(doc *schema.OpnSenseDocument) []common.InterfaceGroup {
	if len(doc.InterfaceGroups.IfGroupEntry) == 0 {
		return nil
	}

	result := make([]common.InterfaceGroup, 0, len(doc.InterfaceGroups.IfGroupEntry))
	for _, e := range doc.InterfaceGroups.IfGroupEntry {
		result = append(result, common.InterfaceGroup{
			Name:    e.IfName,
			Members: splitNonEmpty(e.Members, " "),
		})
	}

	return result
}

// buildInterfaceDHCPAdvancedV4 constructs a DHCPAdvancedV4 from the advanced DHCPv4
// *client* elements stored on the interface itself. Real config.xml files put these
// under <interfaces><wan>, not under <dhcpd>.
// Returns nil when all fields are empty, so the pointer is omitted during serialization.
func (c *converter) buildInterfaceDHCPAdvancedV4(iface schema.Interface) *common.InterfaceDHCPAdvancedV4 {
	v4 := common.InterfaceDHCPAdvancedV4{
		AliasAddress:                  iface.AliasAddress,
		AliasSubnet:                   iface.AliasSubnet,
		DHCPRejectFrom:                iface.DHCPRejectFrom,
		AdvDHCPPTTimeout:              iface.AdvDHCPPTTimeout,
		AdvDHCPPTRetry:                iface.AdvDHCPPTRetry,
		AdvDHCPPTSelectTimeout:        iface.AdvDHCPPTSelectTimeout,
		AdvDHCPPTReboot:               iface.AdvDHCPPTReboot,
		AdvDHCPPTBackoffCutoff:        iface.AdvDHCPPTBackoffCutoff,
		AdvDHCPPTInitialInterval:      iface.AdvDHCPPTInitialInterval,
		AdvDHCPPTValues:               iface.AdvDHCPPTValues,
		AdvDHCPSendOptions:            iface.AdvDHCPSendOptions,
		AdvDHCPRequestOptions:         iface.AdvDHCPRequestOptions,
		AdvDHCPRequiredOptions:        iface.AdvDHCPRequiredOptions,
		AdvDHCPOptionModifiers:        iface.AdvDHCPOptionModifiers,
		AdvDHCPConfigAdvanced:         iface.AdvDHCPConfigAdvanced,
		AdvDHCPConfigFileOverride:     iface.AdvDHCPConfigFileOverride,
		AdvDHCPConfigFileOverridePath: iface.AdvDHCPConfigFileOverridePath,
	}

	if (v4 == common.InterfaceDHCPAdvancedV4{}) {
		return nil
	}

	return &v4
}

// buildInterfaceDHCPAdvancedV6 constructs a DHCPAdvancedV6 from the advanced DHCPv6
// client elements stored on the interface itself.
// Returns nil when all fields are empty, so the pointer is omitted during serialization.
func (c *converter) buildInterfaceDHCPAdvancedV6(iface schema.Interface) *common.InterfaceDHCPAdvancedV6 {
	v6 := common.InterfaceDHCPAdvancedV6{
		Track6Interface:                                 iface.Track6Interface,
		Track6PrefixID:                                  iface.Track6PrefixID,
		AdvDHCP6InterfaceStatementSendOptions:           iface.AdvDHCP6InterfaceStatementSendOptions,
		AdvDHCP6InterfaceStatementRequestOptions:        iface.AdvDHCP6InterfaceStatementRequestOptions,
		AdvDHCP6InterfaceStatementInformationOnlyEnable: iface.AdvDHCP6InterfaceStatementInformationOnlyEnable != "",
		AdvDHCP6InterfaceStatementScript:                iface.AdvDHCP6InterfaceStatementScript,
		AdvDHCP6IDAssocStatementAddressEnable:           iface.AdvDHCP6IDAssocStatementAddressEnable != "",
		AdvDHCP6IDAssocStatementAddress:                 iface.AdvDHCP6IDAssocStatementAddress,
		AdvDHCP6IDAssocStatementAddressID:               iface.AdvDHCP6IDAssocStatementAddressID,
		AdvDHCP6IDAssocStatementAddressPLTime:           iface.AdvDHCP6IDAssocStatementAddressPLTime,
		AdvDHCP6IDAssocStatementAddressVLTime:           iface.AdvDHCP6IDAssocStatementAddressVLTime,
		AdvDHCP6IDAssocStatementPrefixEnable:            iface.AdvDHCP6IDAssocStatementPrefixEnable != "",
		AdvDHCP6IDAssocStatementPrefix:                  iface.AdvDHCP6IDAssocStatementPrefix,
		AdvDHCP6IDAssocStatementPrefixID:                iface.AdvDHCP6IDAssocStatementPrefixID,
		AdvDHCP6IDAssocStatementPrefixPLTime:            iface.AdvDHCP6IDAssocStatementPrefixPLTime,
		AdvDHCP6IDAssocStatementPrefixVLTime:            iface.AdvDHCP6IDAssocStatementPrefixVLTime,
		AdvDHCP6PrefixInterfaceStatementSLALen:          iface.AdvDHCP6PrefixInterfaceStatementSLALen,
		AdvDHCP6AuthenticationStatementAuthName:         iface.AdvDHCP6AuthenticationStatementAuthName,
		AdvDHCP6AuthenticationStatementProtocol:         iface.AdvDHCP6AuthenticationStatementProtocol,
		AdvDHCP6AuthenticationStatementAlgorithm:        iface.AdvDHCP6AuthenticationStatementAlgorithm,
		AdvDHCP6AuthenticationStatementRDM:              iface.AdvDHCP6AuthenticationStatementRDM,
		AdvDHCP6KeyInfoStatementKeyName:                 iface.AdvDHCP6KeyInfoStatementKeyName,
		AdvDHCP6KeyInfoStatementRealm:                   iface.AdvDHCP6KeyInfoStatementRealm,
		AdvDHCP6KeyInfoStatementKeyID:                   iface.AdvDHCP6KeyInfoStatementKeyID,
		AdvDHCP6KeyInfoStatementSecret:                  iface.AdvDHCP6KeyInfoStatementSecret,
		AdvDHCP6KeyInfoStatementExpire:                  iface.AdvDHCP6KeyInfoStatementExpire,
		AdvDHCP6ConfigAdvanced:                          iface.AdvDHCP6ConfigAdvanced,
		AdvDHCP6ConfigFileOverride:                      iface.AdvDHCP6ConfigFileOverride,
		AdvDHCP6ConfigFileOverridePath:                  iface.AdvDHCP6ConfigFileOverridePath,
	}

	if (v6 == common.InterfaceDHCPAdvancedV6{}) {
		return nil
	}

	return &v6
}
