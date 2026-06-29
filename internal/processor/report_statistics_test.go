package processor

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func snmpServiceEntry(t *testing.T, stats *Statistics) *ServiceStatistics {
	t.Helper()
	for i := range stats.ServiceDetails {
		if stats.ServiceDetails[i].Name == analysis.ServiceNameSNMP {
			return &stats.ServiceDetails[i]
		}
	}
	return nil
}

func TestGenerateStatistics_RedactsSNMPCommunity(t *testing.T) {
	t.Parallel()

	cfg := &common.CommonDevice{
		SNMP: common.SNMPConfig{
			ROCommunity: "super-secret-community",
			SysLocation: "datacenter-1",
			SysContact:  "admin@example.com",
		},
	}

	stats := generateStatistics(cfg)

	snmp := snmpServiceEntry(t, stats)
	require.NotNil(t, snmp, "expected an SNMP service entry")
	assert.Equal(t, "[REDACTED]", snmp.Details["community"])
	assert.NotContains(t, snmp.Details["community"], "super-secret")
	// Non-sensitive details survive.
	assert.Equal(t, "datacenter-1", snmp.Details["location"])
}

func TestGenerateStatistics_NoSNMPService(t *testing.T) {
	t.Parallel()

	stats := generateStatistics(&common.CommonDevice{})

	assert.Nil(t, snmpServiceEntry(t, stats), "no SNMP entry expected when ROCommunity is empty")
}

func TestGenerateStatistics_IDSFieldsPopulatedAlongsideRedaction(t *testing.T) {
	t.Parallel()

	// Guards the reorder in U3: redaction now happens before translate, IDS
	// fields are still added after translate.
	cfg := &common.CommonDevice{
		SNMP: common.SNMPConfig{ROCommunity: "secret"},
		IDS: &common.IDSConfig{
			Enabled:    true,
			IPSMode:    true,
			Interfaces: []string{"wan"},
		},
	}

	stats := generateStatistics(cfg)

	assert.True(t, stats.IDSEnabled)
	assert.Equal(t, "IPS (Prevention)", stats.IDSMode)
	assert.Equal(t, []string{"wan"}, stats.IDSMonitoredInterfaces)
	snmp := snmpServiceEntry(t, stats)
	require.NotNil(t, snmp)
	assert.Equal(t, "[REDACTED]", snmp.Details["community"])
}
