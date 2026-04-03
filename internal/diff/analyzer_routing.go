package diff

import (
	"fmt"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareRoutes compares routing configuration between two configs.
func (a *Analyzer) CompareRoutes(old, newCfg common.Routing) []Change {
	oldHas := len(old.StaticRoutes) > 0 || len(old.Gateways) > 0 || len(old.GatewayGroups) > 0
	newHas := len(newCfg.StaticRoutes) > 0 || len(newCfg.Gateways) > 0 || len(newCfg.GatewayGroups) > 0

	if !oldHas && !newHas {
		return nil
	}
	if !oldHas && newHas {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionRouting,
			Path:        "routing",
			Description: "Routing configuration section added",
		}}
	}
	if oldHas && !newHas {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionRouting,
			Path:        "routing",
			Description: "Routing configuration section removed",
		}}
	}

	var changes []Change

	if len(old.StaticRoutes) != len(newCfg.StaticRoutes) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "staticroutes.route",
			Description: "Static route count changed",
			OldValue:    fmt.Sprintf("%d routes", len(old.StaticRoutes)),
			NewValue:    fmt.Sprintf("%d routes", len(newCfg.StaticRoutes)),
		})
	}

	if len(old.Gateways) != len(newCfg.Gateways) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "gateways.gateway_item",
			Description: "Gateway count changed",
			OldValue:    fmt.Sprintf("%d gateways", len(old.Gateways)),
			NewValue:    fmt.Sprintf("%d gateways", len(newCfg.Gateways)),
		})
	}

	if len(old.GatewayGroups) != len(newCfg.GatewayGroups) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionRouting,
			Path:        "gateway_group",
			Description: "Gateway group count changed",
			OldValue:    fmt.Sprintf("%d groups", len(old.GatewayGroups)),
			NewValue:    fmt.Sprintf("%d groups", len(newCfg.GatewayGroups)),
		})
	}

	return changes
}
