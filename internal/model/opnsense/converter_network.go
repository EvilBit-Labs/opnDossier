package opnsense

import (
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// convertBridges maps doc.Bridges.Bridge to []common.Bridge.
// Bridge members are stored as a comma-separated string in OPNsense XML and
// split into individual interface names for the platform-agnostic model.
func (c *Converter) convertBridges(doc *schema.OpnSenseDocument) []common.Bridge {
	if len(doc.Bridges.Bridge) == 0 {
		return nil
	}

	result := make([]common.Bridge, 0, len(doc.Bridges.Bridge))
	for _, b := range doc.Bridges.Bridge {
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
func (c *Converter) convertPPPs(doc *schema.OpnSenseDocument) []common.PPP {
	if len(doc.PPPInterfaces.Ppp) == 0 {
		return nil
	}

	result := make([]common.PPP, 0, len(doc.PPPInterfaces.Ppp))
	for _, p := range doc.PPPInterfaces.Ppp {
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
func (c *Converter) convertGIFs(doc *schema.OpnSenseDocument) []common.GIF {
	if len(doc.GIFInterfaces.Gif) == 0 {
		return nil
	}

	result := make([]common.GIF, 0, len(doc.GIFInterfaces.Gif))
	for _, g := range doc.GIFInterfaces.Gif {
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
func (c *Converter) convertGREs(doc *schema.OpnSenseDocument) []common.GRE {
	if len(doc.GREInterfaces.Gre) == 0 {
		return nil
	}

	result := make([]common.GRE, 0, len(doc.GREInterfaces.Gre))
	for _, g := range doc.GREInterfaces.Gre {
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
func (c *Converter) convertLAGGs(doc *schema.OpnSenseDocument) []common.LAGG {
	if len(doc.LAGGInterfaces.Lagg) == 0 {
		return nil
	}

	result := make([]common.LAGG, 0, len(doc.LAGGInterfaces.Lagg))
	for _, l := range doc.LAGGInterfaces.Lagg {
		result = append(result, common.LAGG{
			Interface:   l.Laggif,
			Members:     splitNonEmpty(l.Members, ","),
			Protocol:    l.Proto,
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
func (c *Converter) convertVirtualIPs(doc *schema.OpnSenseDocument) []common.VirtualIP {
	if len(doc.VirtualIP.Vip) == 0 {
		return nil
	}

	result := make([]common.VirtualIP, 0, len(doc.VirtualIP.Vip))
	for _, v := range doc.VirtualIP.Vip {
		result = append(result, common.VirtualIP{
			Mode:        v.Mode,
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
func (c *Converter) convertInterfaceGroups(doc *schema.OpnSenseDocument) []common.InterfaceGroup {
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
