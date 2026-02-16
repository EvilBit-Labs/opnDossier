package processor

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestNormalize_DoesNotMutateOriginal(t *testing.T) {
	t.Parallel()

	original := &model.OpnSenseDocument{
		Filter: model.Filter{
			Rule: []model.Rule{
				{Type: "pass", Descr: "rule-b"},
				{Type: "block", Descr: "rule-a"},
			},
		},
		System: model.System{
			User: []model.User{
				{Name: "zoe"},
				{Name: "alice"},
			},
			Group: []model.Group{
				{Name: "staff"},
				{Name: "admins"},
			},
		},
		Sysctl: []model.SysctlItem{
			{Tunable: "z.tunable"},
			{Tunable: "a.tunable"},
		},
	}

	// Save original order
	origRuleDescr := original.Filter.Rule[0].Descr
	origUserName := original.System.User[0].Name
	origGroupName := original.System.Group[0].Name
	origSysctl := original.Sysctl[0].Tunable

	p := &CoreProcessor{}
	normalized := p.normalize(original)

	// Normalized should be sorted
	assert.NotNil(t, normalized)

	// Original should be unmodified
	assert.Equal(t, origRuleDescr, original.Filter.Rule[0].Descr, "original rules should not be reordered")
	assert.Equal(t, origUserName, original.System.User[0].Name, "original users should not be reordered")
	assert.Equal(t, origGroupName, original.System.Group[0].Name, "original groups should not be reordered")
	assert.Equal(t, origSysctl, original.Sysctl[0].Tunable, "original sysctl should not be reordered")
}

func TestCanonicalizeIPField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"any keyword", "any", "any"},
		{"lan keyword", "lan", "lan"},
		{"wan keyword", "wan", "wan"},
		{"bare IPv4", "192.168.1.1", "192.168.1.1/32"},
		{"IPv4 CIDR", "10.0.0.0/8", "10.0.0.0/8"},
		{"non-canonical CIDR", "192.168.1.100/24", "192.168.1.0/24"},
		{"bare IPv6", "::1", "::1/128"},
		{"alias name", "LAN_SUBNET", "LAN_SUBNET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			field := tt.input
			canonicalizeIPField(&field)
			assert.Equal(t, tt.want, field)
		})
	}
}
