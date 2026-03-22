package model_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestLAGGProtocol_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.LAGGProtocol
		want bool
	}{
		{"lacp is valid", common.LAGGProtocolLACP, true},
		{"failover is valid", common.LAGGProtocolFailover, true},
		{"loadbalance is valid", common.LAGGProtocolLoadBalance, true},
		{"roundrobin is valid", common.LAGGProtocolRoundRobin, true},
		{"none is invalid", common.LAGGProtocol("none"), false},
		{"empty is invalid", common.LAGGProtocol(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}

func TestVIPMode_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.VIPMode
		want bool
	}{
		{"carp is valid", common.VIPModeCarp, true},
		{"ipalias is valid", common.VIPModeIPAlias, true},
		{"proxyarp is valid", common.VIPModeProxyARP, true},
		{"other is invalid", common.VIPMode("other"), false},
		{"empty is invalid", common.VIPMode(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}
