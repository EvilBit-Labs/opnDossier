package model_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestFirewallRuleType_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.FirewallRuleType
		want bool
	}{
		{"pass is valid", common.RuleTypePass, true},
		{"block is valid", common.RuleTypeBlock, true},
		{"reject is valid", common.RuleTypeReject, true},
		{"match is invalid", common.FirewallRuleType("match"), false},
		{"deny is invalid", common.FirewallRuleType("deny"), false},
		{"empty is invalid", common.FirewallRuleType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}

func TestFirewallDirection_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.FirewallDirection
		want bool
	}{
		{"in is valid", common.DirectionIn, true},
		{"out is valid", common.DirectionOut, true},
		{"any is valid", common.DirectionAny, true},
		{"both is invalid", common.FirewallDirection("both"), false},
		{"empty is invalid", common.FirewallDirection(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}

func TestIPProtocol_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.IPProtocol
		want bool
	}{
		{"inet is valid", common.IPProtocolInet, true},
		{"inet6 is valid", common.IPProtocolInet6, true},
		{"inet46 is invalid", common.IPProtocol("inet46"), false},
		{"empty is invalid", common.IPProtocol(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}

func TestNATOutboundMode_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.NATOutboundMode
		want bool
	}{
		{"automatic is valid", common.OutboundAutomatic, true},
		{"hybrid is valid", common.OutboundHybrid, true},
		{"advanced is valid", common.OutboundAdvanced, true},
		{"disabled is valid", common.OutboundDisabled, true},
		{"manual is invalid", common.NATOutboundMode("manual"), false},
		{"empty is invalid", common.NATOutboundMode(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}
