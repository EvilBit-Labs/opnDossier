package analysis

import (
	"fmt"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// benchUnusedDevice builds a device with n aliases chained head-to-tail (deep
// nesting) plus one firewall rule referencing the head, so the whole chain is
// reachable — the worst case for the reachability BFS depth.
func benchUnusedDevice(n int) *common.CommonDevice {
	objs := make(common.NamedObjects, n)

	for i := range n {
		members := []string{"10.0.0.1"}
		if i+1 < n {
			members = []string{fmt.Sprintf("alias-%d", i+1)}
		}

		objs[fmt.Sprintf("alias-%d", i)] = common.NamedObject{
			Type:    common.NamedObjectTypeHost,
			Members: members,
		}
	}

	return &common.CommonDevice{
		NamedObjects: objs,
		FirewallRules: []common.FirewallRule{{
			Source: common.RuleEndpoint{AddressRef: &common.ObjectRef{Name: "alias-0"}},
		}},
	}
}

// BenchmarkDetectUnusedObjects pins the linear-time reachability claim over a
// ~1,000-object deeply-nested graph. Standalone target only — not wired into CI
// or ci-check, and with no pass/fail budget (project convention).
func BenchmarkDetectUnusedObjects(b *testing.B) {
	cfg := benchUnusedDevice(1000)

	for b.Loop() {
		_ = DetectUnusedObjects(cfg)
	}
}
