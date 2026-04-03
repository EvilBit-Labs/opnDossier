package diff

import (
	"fmt"
	"strconv"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// CompareNAT compares NAT configuration between two configs.
func (a *Analyzer) CompareNAT(old, newCfg common.NATConfig) []Change {
	oldHas := old.HasData()
	newHas := newCfg.HasData()

	if !oldHas && !newHas {
		return nil
	}
	if !oldHas && newHas {
		return []Change{{
			Type:        ChangeAdded,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section added",
		}}
	}
	if oldHas && !newHas {
		return []Change{{
			Type:        ChangeRemoved,
			Section:     SectionNAT,
			Path:        "nat",
			Description: "NAT configuration section removed",
		}}
	}

	var changes []Change

	// Compare outbound NAT mode
	if old.OutboundMode != newCfg.OutboundMode {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.outbound.mode",
			Description:    "Outbound NAT mode changed",
			OldValue:       string(old.OutboundMode),
			NewValue:       string(newCfg.OutboundMode),
			SecurityImpact: "medium",
		})
	}

	// Compare outbound rule counts
	if len(old.OutboundRules) != len(newCfg.OutboundRules) {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.outbound.rules",
			Description: "Outbound NAT rule count changed",
			OldValue:    fmt.Sprintf("%d rules", len(old.OutboundRules)),
			NewValue:    fmt.Sprintf("%d rules", len(newCfg.OutboundRules)),
		})
	}

	// Compare inbound (port forward) rule counts
	if len(old.InboundRules) != len(newCfg.InboundRules) {
		changes = append(changes, Change{
			Type:           ChangeModified,
			Section:        SectionNAT,
			Path:           "nat.inbound.rules",
			Description:    "Port forward rule count changed",
			OldValue:       fmt.Sprintf("%d rules", len(old.InboundRules)),
			NewValue:       fmt.Sprintf("%d rules", len(newCfg.InboundRules)),
			SecurityImpact: "medium",
		})
	}

	// Compare NAT boolean settings
	if old.ReflectionDisabled != newCfg.ReflectionDisabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.reflectionDisabled",
			Description: "NAT reflection setting changed",
			OldValue:    strconv.FormatBool(old.ReflectionDisabled),
			NewValue:    strconv.FormatBool(newCfg.ReflectionDisabled),
		})
	}
	if old.PfShareForward != newCfg.PfShareForward {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.pfShareForward",
			Description: "pf share-forward setting changed",
			OldValue:    strconv.FormatBool(old.PfShareForward),
			NewValue:    strconv.FormatBool(newCfg.PfShareForward),
		})
	}
	if old.BiNATEnabled != newCfg.BiNATEnabled {
		changes = append(changes, Change{
			Type:        ChangeModified,
			Section:     SectionNAT,
			Path:        "nat.biNatEnabled",
			Description: "BiNAT setting changed",
			OldValue:    strconv.FormatBool(old.BiNATEnabled),
			NewValue:    strconv.FormatBool(newCfg.BiNATEnabled),
		})
	}

	return changes
}
