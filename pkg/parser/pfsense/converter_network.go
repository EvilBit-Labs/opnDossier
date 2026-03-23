package pfsense

import (
	"fmt"
	"maps"
	"slices"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// convertInterfaces maps doc.Interfaces.Items to []common.Interface.
func (c *converter) convertInterfaces(doc *pfsense.Document) []common.Interface {
	items := doc.Interfaces.Items
	if len(items) == 0 {
		return nil
	}

	result := make([]common.Interface, 0, len(items))
	for _, key := range slices.Sorted(maps.Keys(items)) {
		iface := items[key]
		result = append(result, common.Interface{
			Name:        key,
			PhysicalIf:  iface.If,
			Description: iface.Descr,
			// TODO(#461): iface.Enable is presence-based in pfSense (<enable/> = enabled,
			// absent = disabled) but the shared opnsense.Interface type uses string,
			// which cannot distinguish presence from absence. Fork Interface type to
			// use BoolFlag for Enable. For now, fall back to the value-based check.
			Enabled:      isPfSenseValueTrue(iface.Enable),
			IPAddress:    iface.IPAddr,
			IPv6Address:  iface.IPAddrv6,
			Subnet:       iface.Subnet,
			SubnetV6:     iface.Subnetv6,
			Gateway:      iface.Gateway,
			GatewayV6:    iface.Gatewayv6,
			BlockPrivate: isPfSenseValueTrue(iface.BlockPriv),
			BlockBogons:  isPfSenseValueTrue(iface.BlockBogons),
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
func (c *converter) convertVLANs(doc *pfsense.Document) []common.VLAN {
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

// convertPPPs maps doc.PPPs.Ppp to []common.PPP.
func (c *converter) convertPPPs(doc *pfsense.Document) []common.PPP {
	if len(doc.PPPs.Ppp) == 0 {
		return nil
	}

	result := make([]common.PPP, 0, len(doc.PPPs.Ppp))
	for _, p := range doc.PPPs.Ppp {
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
			FarGW:          isPfSenseValueTrue(gw.FarGW),
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
func (c *converter) convertStaticRoutes(doc *pfsense.Document) []common.StaticRoute {
	routes := doc.StaticRoutes.Route
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
