package opnsense

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

const (
	// gatewayModelVersion is the <OPNsense><Gateways> model version OPNsense
	// writes from 24.1.
	gatewayModelVersion = "1.0.0"

	// gatewayModelItemsPath addresses a warning about a <gateway_item> of the
	// gateway model, and legacyGatewayItemsPath one under <gateways>.
	gatewayModelItemsPath  = "OPNsense.Gateways.Items"
	legacyGatewayItemsPath = "Gateways.GatewayItem"
)

// knownGatewayModelVersions lists the <OPNsense><Gateways version="...">
// values this converter has been checked against. 23.7 wrote an empty model at
// 0.0.1 with the same gateway_item element.
var knownGatewayModelVersions = map[string]struct{}{
	"":                  {},
	"0.0.1":             {},
	gatewayModelVersion: {},
}

// convertRouting maps the gateways, doc.Gateways.Groups and doc.StaticRoutes
// to common.Routing.
func (c *converter) convertRouting(doc *schema.OpnSenseDocument) common.Routing {
	return common.Routing{
		Gateways:      c.convertGatewayItems(doc),
		GatewayGroups: c.convertGatewayGroups(doc.Gateways.Groups),
		StaticRoutes:  c.convertStaticRoutes(doc.StaticRoutes),
	}
}

// convertGatewayItems reads the gateways from the <OPNsense><Gateways> model
// when it holds any, and from <gateways> otherwise, as the vendor's
// gatewayIterator does. A <gateway_item> with no child element does not count
// in either store, as on current releases (24.1.3 and later under <gateways>),
// and one with any child element does, whatever it holds
// (schema.Gateway.IsPlaceholder). OPNsense 24.1 migration M1_0_0 copies the
// <gateways><gateway_item> entries into the model and, once one is stored,
// deletes all of them. Legacy gateways left beside a model that holds one, as
// after a failed migration or a hand edit, are ignored with a warning.
func (c *converter) convertGatewayItems(doc *schema.OpnSenseDocument) []common.Gateway {
	model := doc.OPNsense.Gateways
	items := c.modelGateways(model.Items)
	legacy := configuredGateways(doc.Gateways.Gateway)
	c.checkGatewayModelVersion(model.Version, len(items), len(legacy))
	if len(items) == 0 {
		return c.convertGateways(legacy)
	}

	if len(legacy) > 0 {
		names := make([]string, 0, len(legacy))
		for _, gw := range legacy {
			names = append(names, gw.Name)
		}

		c.addWarning(
			legacyGatewayItemsPath,
			strings.Join(names, ", "),
			"the gateway model holds a gateway, so OPNsense ignores every <gateways><gateway_item>; these are left out",
			common.SeverityMedium,
		)
	}

	for i := range items {
		// The migration rewrites "dynamic" to an empty address, and the model
		// reads both as a gateway that takes its address from the interface.
		if items[i].Gateway == "" {
			items[i].Gateway = gatewayDynamic
		}

		// An item that omits the element takes the model's default, which
		// turns monitoring off. The vendor fills in 0 for a legacy gateway.
		if items[i].MonitorDisable == nil {
			items[i].MonitorDisable = new(xmlBoolTrue)
		}

		// An item that omits the element takes the model's default of wan.
		// An empty <interface/> stays empty on the firewall; opnDossier cannot
		// tell it from an absent one, and OPNsense never writes one, as the
		// field is required. The vendor fills in no interface for a legacy
		// gateway.
		if items[i].Interface == "" {
			items[i].Interface = gatewayDefaultInterface
		}
	}

	return c.convertGateways(items)
}

// modelGateways returns the gateways OPNsense loads from the model. The result
// is a new slice, because convertGatewayItems rewrites its items and
// ConvertDocument takes a document the caller owns.
//
// The model keeps its items by uuid, so an item replaces an earlier one with the
// same uuid and takes its place in the list. An item with no uuid attribute gets
// a fresh one on every release. An empty uuid or 0 depends on the release: from
// 25.7 OPNsense gives such an item a fresh uuid, because empty() holds for both,
// and through 25.1.12 it uses the attribute as it stands, so two such items
// collide and the firewall holds the later. The model version does not tell the
// two apart, so both items are kept with a warning, which over-reports on the
// older releases.
//
// An item with no child element is skipped before its uuid is read. Only a
// hand edit or a generator repeats a uuid; OPNsense does not.
func (c *converter) modelGateways(items []schema.GatewayModelItem) []schema.Gateway {
	var kept []schema.Gateway

	places := make(map[string]int, len(items))

	for _, item := range items {
		if item.IsPlaceholder() {
			continue
		}

		// The model's disabled flag is read as the firewall reads it, with
		// !empty(); absent, it takes the model's default of 0. The shadowed
		// Gateway.Disabled is never decoded or encoded for a model item, so
		// neither this nor IsPlaceholder reads it.
		gw := item.Gateway
		gw.Disabled = schema.BoolFlag(item.Disabled != nil && modelFlagSet(*item.Disabled))

		if item.UUID == nil {
			kept = append(kept, gw)

			continue
		}

		uuid := *item.UUID

		place, repeated := places[uuid]

		// modelFlagSet is !empty(), the test OPNsense applies from 25.7.
		if repeated && modelFlagSet(uuid) {
			c.addWarning(
				gatewayModelItemsPath,
				uuid,
				fmt.Sprintf(
					"a later gateway has the same uuid and replaces this one on the firewall, so it is left out (name %q, description %q)",
					kept[place].Name,
					kept[place].Descr,
				),
				common.SeverityMedium,
			)

			kept[place] = gw

			continue
		}

		if repeated {
			c.addWarning(
				gatewayModelItemsPath,
				uuid,
				fmt.Sprintf(
					"a later gateway has the same empty or 0 uuid: through 25.1.12 it replaces this one on the firewall, from 25.7 both load, and the model version does not tell the two apart, so both are reported (name %q, description %q)",
					kept[place].Name,
					kept[place].Descr,
				),
				common.SeverityMedium,
			)
		}

		places[uuid] = len(kept)
		kept = append(kept, gw)
	}

	return kept
}

// configuredGateways returns a copy of the legacy gateways without the
// <gateway_item> elements that hold no child element. It is a copy because
// slices.DeleteFunc writes into the slice it is given, and ConvertDocument takes
// a document the caller owns.
func configuredGateways(gws []schema.Gateway) []schema.Gateway {
	return slices.DeleteFunc(slices.Clone(gws), schema.Gateway.IsPlaceholder)
}

// gatewayFlag returns a gateway flag the common model keeps as text: 1 when the
// firewall reads it as set, and empty otherwise. From 24.1 the firewall reads
// both flags with !empty() in either store. The model writes 0 where the 23.7
// page left the element out, and a consumer testing the export for presence
// would read that 0 as set.
func gatewayFlag(value string) string {
	if modelFlagSet(value) {
		return xmlBoolTrue
	}

	return ""
}

// checkGatewayModelVersion warns when the gateway model carries a version this
// converter has not been checked against, as checkFilterModelVersion does. With
// no gateways decoded from the model the item element may have been renamed
// (§18.1). The legacy fallback is then usually empty, because the migration
// deleted it, and the export holds no gateway at all, which is the Medium case;
// any gateways the fallback still holds are exported, and the warning is Low.
func (c *converter) checkGatewayModelVersion(version string, modelItems, legacyItems int) {
	if _, known := knownGatewayModelVersions[version]; known {
		return
	}

	if modelItems == 0 && legacyItems == 0 {
		c.addWarning(
			"OPNsense.Gateways.Version",
			version,
			"unrecognized OPNsense gateway model version and no gateways decoded from either store; "+
				"the gateway element may have been renamed",
			common.SeverityMedium,
		)

		return
	}

	if modelItems == 0 {
		c.addWarning(
			"OPNsense.Gateways.Version",
			version,
			"unrecognized OPNsense gateway model version and no gateways decoded from the model; "+
				"the gateway element may have been renamed",
			common.SeverityLow,
		)

		return
	}

	c.addWarning("OPNsense.Gateways.Version", version,
		"unrecognized OPNsense gateway model version; element mapping may be stale",
		common.SeverityMedium)
}

// convertGateways maps []schema.Gateway to []common.Gateway.
func (c *converter) convertGateways(gws []schema.Gateway) []common.Gateway {
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

		// The firewall reads an absent address family as inet in either
		// store, and an empty one as inet under <gateways>: the model defaults
		// it, and OPNsense fills it in for a legacy gateway from 20.1.7. It
		// reads an absent or empty weight as 1 in either store: the model
		// defaults it, and the gateway groups read an empty one as 1 from
		// 19.7. On earlier releases a legacy gateway with no address family
		// had none, and an empty weight stayed empty; the export shows inet
		// and 1 for those too. An empty <ipprotocol/> in the model stays empty
		// on the firewall; opnDossier cannot tell it from an absent one, and
		// OPNsense never writes one, as the field is required.
		result = append(result, common.Gateway{
			Interface:      gw.Interface,
			Address:        gw.Gateway,
			Name:           gw.Name,
			Weight:         cmp.Or(gw.Weight, gatewayDefaultWeight),
			IPProtocol:     cmp.Or(gw.IPProtocol, string(common.IPProtocolInet)),
			Interval:       gw.Interval,
			Description:    gw.Descr,
			Monitor:        gw.Monitor,
			Disabled:       bool(gw.Disabled),
			DefaultGW:      gatewayFlag(gw.DefaultGW),
			MonitorDisable: gatewayFlag(gw.MonitorDisableValue()),
			FarGW:          modelFlagSet(gw.FarGW),
		})
	}

	return result
}

// convertGatewayGroups maps []schema.GatewayGroup to []common.GatewayGroup.
func (c *converter) convertGatewayGroups(groups []schema.GatewayGroup) []common.GatewayGroup {
	if len(groups) == 0 {
		return nil
	}

	result := make([]common.GatewayGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, common.GatewayGroup{
			Name:        g.Name,
			Items:       gatewayGroupItems(g),
			Trigger:     g.Trigger,
			Description: g.Descr,
		})
	}

	return result
}
