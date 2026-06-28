package analysis_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/analysis"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const redactedMarker = "[REDACTED]"

func snmpEntry(community string) common.ServiceStatistics {
	return common.ServiceStatistics{
		Name:    analysis.ServiceNameSNMP,
		Enabled: true,
		Details: map[string]string{
			"location":  "datacenter-1",
			"contact":   "admin@example.com",
			"community": community,
		},
	}
}

func TestRedactServiceDetails_RedactsCommunityWithoutMutatingInput(t *testing.T) {
	t.Parallel()

	input := []common.ServiceStatistics{snmpEntry("s3cr3t-community")}

	out, changed := analysis.RedactServiceDetails(input)

	require.True(t, changed)
	assert.Equal(t, redactedMarker, out[0].Details["community"])
	// Non-mutation: the original input map is untouched.
	assert.Equal(t, "s3cr3t-community", input[0].Details["community"])
	// Other detail keys are preserved on the redacted copy.
	assert.Equal(t, "datacenter-1", out[0].Details["location"])
	assert.Equal(t, "admin@example.com", out[0].Details["contact"])
}

func TestRedactServiceDetails_EmptyCommunityNotFlipped(t *testing.T) {
	t.Parallel()

	input := []common.ServiceStatistics{snmpEntry("")}

	out, changed := analysis.RedactServiceDetails(input)

	require.False(t, changed)
	assert.Empty(t, out[0].Details["community"])
	assert.NotEqual(t, redactedMarker, out[0].Details["community"])
}

func TestRedactServiceDetails_NoSNMPEntry(t *testing.T) {
	t.Parallel()

	input := []common.ServiceStatistics{
		{Name: "SSH Daemon", Enabled: true, Details: map[string]string{"group": "admins"}},
	}

	out, changed := analysis.RedactServiceDetails(input)

	require.False(t, changed)
	assert.Equal(t, "admins", out[0].Details["group"])
}

func TestRedactServiceDetails_NilDetails(t *testing.T) {
	t.Parallel()

	input := []common.ServiceStatistics{
		{Name: analysis.ServiceNameSNMP, Enabled: true, Details: nil},
	}

	out, changed := analysis.RedactServiceDetails(input)

	require.False(t, changed)
	assert.Nil(t, out[0].Details)
}

func TestRedactServiceDetails_MultipleSNMPEntriesAllRedacted(t *testing.T) {
	t.Parallel()

	input := []common.ServiceStatistics{
		snmpEntry("first-community"),
		{Name: "SSH Daemon", Enabled: true, Details: map[string]string{"group": "admins"}},
		snmpEntry("second-community"),
	}

	out, changed := analysis.RedactServiceDetails(input)

	require.True(t, changed)
	assert.Equal(t, redactedMarker, out[0].Details["community"])
	assert.Equal(t, redactedMarker, out[2].Details["community"])
	assert.Equal(t, "admins", out[1].Details["group"])
}

func TestRedactServiceDetails_NonSNMPCommunityKeyUntouched(t *testing.T) {
	t.Parallel()

	// A non-SNMP service that happens to carry a "community" key must not be
	// redacted — the name gate protects it.
	input := []common.ServiceStatistics{
		{Name: "Some Other Service", Enabled: true, Details: map[string]string{"community": "not-secret"}},
	}

	out, changed := analysis.RedactServiceDetails(input)

	require.False(t, changed)
	assert.Equal(t, "not-secret", out[0].Details["community"])
}

func TestRedactServiceDetails_NilInput(t *testing.T) {
	t.Parallel()

	out, changed := analysis.RedactServiceDetails(nil)

	require.False(t, changed)
	assert.Empty(t, out)
}
