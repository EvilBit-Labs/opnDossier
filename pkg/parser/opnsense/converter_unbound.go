package opnsense

import (
	"strconv"
	"strings"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Unbound model versions whose migrations moved a setting out of the legacy
// <unbound> element. M1_0_3 moved dnssecstripped into <advanced>, M1_0_5 (23.7)
// moved enable and dnssec into <general> as enabled and dnssec, and both
// unset the legacy keys after the move.
const (
	unboundAdvancedSincePatch = 3
	unboundGeneralSincePatch  = 5

	// modelVersionParts is the major.minor.patch shape of a model version.
	modelVersionParts = 3
)

// unboundServiceFlags is what the running firewall reads for whether Unbound is
// enabled, validates DNSSEC and strips DNSSEC records. A config whose model has
// been migrated holds them only in <OPNsense><unboundplus>, so reading the
// legacy <unbound> element alone reports Unbound as off on every config written
// by 23.7 or later.
type unboundServiceFlags struct {
	enabled  bool
	dnssec   bool
	stripped bool
}

// readUnboundServiceFlags picks, for each setting, the store the release that
// wrote the config reads. From model 1.0.5 OPNsense tests <general><enabled>
// with isEmpty() and <general><dnssec> with !empty() (unbound.inc), which
// modelFlagSet mirrors; an absent element takes the model default, which is
// off for both. Before it, unbound.inc tested <unbound><enable> and
// <unbound><dnssec> with isset(), so any element with a body counts. An empty
// legacy element cannot be told from an absent one here; no OPNsense page
// writes one.
func readUnboundServiceFlags(doc *schema.OpnSenseDocument) unboundServiceFlags {
	plus := doc.OPNsense.UnboundPlus
	legacy := doc.Unbound

	var flags unboundServiceFlags
	if unboundModelHolds(plus.Version, unboundGeneralSincePatch, plus.General.Enabled != "") {
		flags.enabled = modelFlagSet(plus.General.Enabled)
		flags.dnssec = modelFlagSet(plus.General.Dnssec)
	} else {
		flags.enabled = legacy.Enable != ""
		flags.dnssec = legacy.Dnssec != ""
	}

	// M1_0_3 carried dnssecstripped over with empty(), so the legacy value
	// reads the same way as the model's.
	if unboundModelHolds(plus.Version, unboundAdvancedSincePatch, plus.Advanced.Dnssecstripped != "") {
		flags.stripped = modelFlagSet(plus.Advanced.Dnssecstripped)
	} else {
		flags.stripped = modelFlagSet(legacy.Dnssecstripped)
	}

	return flags
}

// unboundModelHolds reports whether a model at version holds a setting that
// migration 1.0.<sincePatch> moved into it. A version that does not parse,
// including an absent attribute, says nothing about the release, so the
// setting is read from the model only when the model carries it.
func unboundModelHolds(version string, sincePatch int, modelHasValue bool) bool {
	parts := strings.Split(version, ".")
	if len(parts) != modelVersionParts {
		return modelHasValue
	}

	nums := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return modelHasValue
		}

		nums = append(nums, n)
	}

	if nums[0] != 1 || nums[1] != 0 {
		return nums[0] > 1 || (nums[0] == 1 && nums[1] > 0)
	}

	return nums[2] >= sincePatch
}
