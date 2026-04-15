package analysis

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

func baseHashRule() common.FirewallRule {
	return common.FirewallRule{
		Type:       common.RuleTypePass,
		IPProtocol: common.IPProtocolInet,
		Interfaces: []string{"wan", "lan"},
		StateType:  "keep state",
		Direction:  common.DirectionIn,
		Protocol:   "tcp",
		Quick:      true,
		Source: common.RuleEndpoint{
			Address: "192.168.1.0/24",
			Port:    "443",
		},
		Destination: common.RuleEndpoint{
			Address: "10.0.0.0/8",
			Port:    "80",
		},
	}
}

func TestHashRule_EquivalentRulesHashSame(t *testing.T) {
	t.Parallel()

	a := baseHashRule()
	b := baseHashRule()
	b.Interfaces = []string{"lan", "wan"} // reversed order — RulesEquivalent ignores order

	if !RulesEquivalent(a, b) {
		t.Fatalf("precondition failed: rules should be equivalent")
	}
	if hashRule(a) != hashRule(b) {
		t.Errorf("equivalent rules produced different hashes: %d vs %d", hashRule(a), hashRule(b))
	}
}

func TestHashRule_DistinctRulesHashDifferently(t *testing.T) {
	t.Parallel()

	base := baseHashRule()
	h0 := hashRule(base)

	mutations := map[string]func(r *common.FirewallRule){
		"Disabled":            func(r *common.FirewallRule) { r.Disabled = true },
		"Type":                func(r *common.FirewallRule) { r.Type = common.RuleTypeBlock },
		"IPProtocol":          func(r *common.FirewallRule) { r.IPProtocol = common.IPProtocolInet6 },
		"Interfaces":          func(r *common.FirewallRule) { r.Interfaces = []string{"opt1"} },
		"StateType":           func(r *common.FirewallRule) { r.StateType = "no state" },
		"Direction":           func(r *common.FirewallRule) { r.Direction = common.DirectionOut },
		"Protocol":            func(r *common.FirewallRule) { r.Protocol = "udp" },
		"Quick":               func(r *common.FirewallRule) { r.Quick = false },
		"Source.Address":      func(r *common.FirewallRule) { r.Source.Address = "any" },
		"Source.Port":         func(r *common.FirewallRule) { r.Source.Port = "22" },
		"Source.Negated":      func(r *common.FirewallRule) { r.Source.Negated = true },
		"Destination.Address": func(r *common.FirewallRule) { r.Destination.Address = "any" },
		"Destination.Port":    func(r *common.FirewallRule) { r.Destination.Port = "8080" },
		"Destination.Negated": func(r *common.FirewallRule) { r.Destination.Negated = true },
	}

	for name, mutate := range mutations {
		mutated := base
		mutated.Interfaces = append([]string(nil), base.Interfaces...)
		mutate(&mutated)
		if hashRule(mutated) == h0 {
			t.Errorf("mutation %q produced identical hash; field not covered by hashRule", name)
		}
	}
}

// TestHashRule_InterfaceBoundary guards against collisions where rules with
// interfaces ["a","bc"] could hash the same as ["ab","c"] if segments were
// concatenated without a separator.
func TestHashRule_InterfaceBoundary(t *testing.T) {
	t.Parallel()

	r1 := baseHashRule()
	r1.Interfaces = []string{"a", "bc"}
	r2 := baseHashRule()
	r2.Interfaces = []string{"ab", "c"}

	if hashRule(r1) == hashRule(r2) {
		t.Errorf("interface segmentation collision: hashRule did not preserve field boundaries")
	}
}
