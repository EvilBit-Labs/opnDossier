package diff

import (
	"strconv"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// compareGlobalNATReflection reports a change to <system><disablenatreflection>
// itself, in the NAT section.
//
// nat.reflectionDisabled is false whenever an enabled, redirecting port
// forward sets purenat or enable, whatever the global flag says, so a toggle
// of the flag on such a firewall leaves it unchanged. The flag still decides
// what every forward on the system default does, and CompareSystem does not
// compare it, so it gets its own entry.
func compareGlobalNATReflection(old, newCfg *common.System) []Change {
	if old == nil || newCfg == nil || old.DisableNATReflection == newCfg.DisableNATReflection {
		return nil
	}

	return []Change{{
		Type:        ChangeModified,
		Section:     SectionNAT,
		Path:        "system.disableNatReflection",
		Description: "Global NAT reflection setting changed",
		OldValue:    strconv.FormatBool(old.DisableNATReflection),
		NewValue:    strconv.FormatBool(newCfg.DisableNATReflection),
	}}
}
