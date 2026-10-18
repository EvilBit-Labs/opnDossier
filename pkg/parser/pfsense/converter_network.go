package pfsense

import (
	"fmt"
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/shared"
)

// convertInterfaces maps doc.Interfaces.Items to []common.Interface.
func (c *converter) convertInterfaces(doc *pfsense.Document) []common.Interface {
	items := doc.Interfaces.Items
	if len(items) == 0 {
		return nil
	}

	// Single-allocation sorted-keys idiom; see opnsense convertInterfaces.
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	result := make([]common.Interface, 0, len(items))
	for _, key := range keys {
		iface := items[key]
		result = append(result, common.Interface{
			Name:           key,
			PhysicalIf:     iface.If,
			Description:    iface.Descr,
			Enabled:        iface.Enable.Bool(),
			IPAddress:      iface.IPAddr,
			IPv6Address:    iface.IPAddrv6,
			Subnet:         iface.Subnet,
			SubnetV6:       iface.Subnetv6,
			Gateway:        iface.Gateway,
			GatewayV6:      iface.Gatewayv6,
			BlockPrivate:   shared.IsValueTrue(iface.BlockPriv),
			BlockBogons:    shared.IsValueTrue(iface.BlockBogons),
			Type:           iface.Type,
			MTU:            iface.MTU,
			SpoofMAC:       iface.Spoofmac,
			DHCPHostname:   iface.DHCPHostname,
			Media:          iface.Media,
			MediaOpt:       iface.MediaOpt,
			Virtual:        iface.Virtual != 0,
			Lock:           iface.Lock != 0,
			DHCPAdvancedV4: c.buildInterfaceDHCPAdvancedV4(iface),
			DHCPAdvancedV6: c.buildInterfaceDHCPAdvancedV6(iface),
		})
	}

	return result
}

// convertVLANs maps doc.VLANs.VLAN to []common.VLAN.
//
// Empty <vlan/> placeholders are skipped; see GOTCHAS.md section 3.4. The result
// is grown on demand rather than preallocated because the loop may skip entries.
func (c *converter) convertVLANs(doc *pfsense.Document) []common.VLAN {
	var result []common.VLAN

	for _, v := range doc.VLANs.VLAN {
		if v.IsPlaceholder() {
			continue
		}

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

// convertPPPs maps doc.PPPs.Ppp to []common.PPP.
//
// Empty <ppp/> placeholders are skipped so they do not surface as blank PPP
// links in exported output. The result is grown on demand rather than
// preallocated because the loop may skip entries.
func (c *converter) convertPPPs(doc *pfsense.Document) []common.PPP {
	var result []common.PPP

	for _, p := range doc.PPPs.Ppp {
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

// convertRouting maps doc.Gateways and doc.StaticRoutes to common.Routing.
func (c *converter) convertRouting(doc *pfsense.Document) common.Routing {
	return common.Routing{
		Gateways:      c.convertGateways(doc),
		GatewayGroups: c.convertGatewayGroups(doc),
		StaticRoutes:  c.convertStaticRoutes(doc),
	}
}

// convertGateways maps doc.Gateways.Gateway to []common.Gateway.
func (c *converter) convertGateways(doc *pfsense.Document) []common.Gateway {
	gws := doc.Gateways.Gateway
	if len(gws) == 0 {
		return nil
	}

	result := make([]common.Gateway, 0, len(gws))
	for i, gw := range gws {
		if gw.Gateway == "" {
			c.addWarning(
				fmt.Sprintf("Routing.Gateways[%d].Address", i),
				gw.Name,
				"gateway has empty address",
				common.SeverityHigh,
			)
		}
		if gw.Name == "" {
			c.addWarning(
				fmt.Sprintf("Routing.Gateways[%d].Name", i),
				gw.Interface,
				"gateway has empty name",
				common.SeverityHigh,
			)
		}

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
			FarGW:          shared.IsValueTrue(gw.FarGW),
		})
	}

	return result
}

// convertGatewayGroups maps doc.Gateways.Groups to []common.GatewayGroup.
func (c *converter) convertGatewayGroups(doc *pfsense.Document) []common.GatewayGroup {
	groups := doc.Gateways.Groups
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

// convertStaticRoutes maps doc.StaticRoutes.Route to []common.StaticRoute.
//
// Empty <route/> placeholders are skipped so they neither surface as blank
// routes in exported output nor flip CommonDevice.HasRoutes to true for a
// device with no routing configuration. The result is grown on demand rather
// than preallocated because the loop may skip entries.
func (c *converter) convertStaticRoutes(doc *pfsense.Document) []common.StaticRoute {
	routes := doc.StaticRoutes.Route

	var result []common.StaticRoute

	for _, r := range routes {
		if r.IsPlaceholder() {
			continue
		}

		result = append(result, common.StaticRoute{
			Network:     r.Network,
			NetworkRef:  c.namedObjects.Ref(r.Network),
			Gateway:     r.Gateway,
			Description: r.Descr,
			Disabled:    bool(r.Disabled),
			Created:     r.Created,
			Updated:     r.Updated,
		})
	}

	return result
}

// buildInterfaceDHCPAdvancedV4 constructs a DHCPAdvancedV4 from the advanced DHCPv4
// *client* elements stored on the interface itself. Real config.xml files put these
// under <interfaces><wan>, not under <dhcpd>.
// Returns nil when all fields are empty, so the pointer is omitted during serialization.
func (c *converter) buildInterfaceDHCPAdvancedV4(iface pfsense.Interface) *common.InterfaceDHCPAdvancedV4 {
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
func (c *converter) buildInterfaceDHCPAdvancedV6(iface pfsense.Interface) *common.InterfaceDHCPAdvancedV6 {
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
