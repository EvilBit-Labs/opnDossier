package compliance_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestFailWhenPacketFilterDisabled pins the helper's contract: nothing changes
// while pf is on, and with pf off every listed control is evaluated and has
// exactly one finding, which is the one its own check raised when there was one.
func TestFailWhenPacketFilterDisabled(t *testing.T) {
	t.Parallel()

	newFinding := func(id string) compliance.Finding {
		return compliance.Finding{Component: compliance.PacketFilterComponent, References: []string{id}}
	}

	own := compliance.Finding{Component: "firewall-rules", References: []string{"B"}}

	for _, disabled := range []bool{false, true} {
		device := &common.CommonDevice{System: common.System{PacketFilterDisabled: disabled}}

		findings, evaluated := compliance.FailWhenPacketFilterDisabled(
			device, []compliance.Finding{own}, []string{"B", "Z"}, []string{"A", "B"}, newFinding)

		if !disabled {
			if len(findings) != 1 || !slices.Equal(evaluated, []string{"B", "Z"}) {
				t.Errorf("filtering on changed the results: %+v %v", findings, evaluated)
			}

			continue
		}

		if !slices.Equal(evaluated, []string{"B", "Z", "A"}) {
			t.Errorf("evaluated = %v, want [B Z A]", evaluated)
		}

		for _, id := range []string{"A", "B"} {
			count := 0

			for _, f := range findings {
				if slices.Contains(f.References, id) {
					count++
				}
			}

			if count != 1 {
				t.Errorf("%s has %d findings, want 1: %+v", id, count, findings)
			}
		}

		if findings[0].Component != own.Component {
			t.Errorf("the control's own finding was replaced: %+v", findings[0])
		}
	}

	findings, _ := compliance.FailWhenPacketFilterDisabled(nil, nil, nil, []string{"A"}, newFinding)
	if findings != nil {
		t.Errorf("nil device produced findings: %+v", findings)
	}
}
