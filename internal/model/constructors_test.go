package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModel_NewOpnSenseDocument(t *testing.T) {
	t.Parallel()

	doc := NewOpnSenseDocument()
	require.NotNil(t, doc)

	// Verify slices are initialized
	assert.NotNil(t, doc.Sysctl)
	assert.Empty(t, doc.Sysctl)
	assert.NotNil(t, doc.Filter.Rule)
	assert.Empty(t, doc.Filter.Rule)

	// Verify maps are initialized
	assert.NotNil(t, doc.Interfaces.Items)
	assert.Empty(t, doc.Interfaces.Items)
	assert.NotNil(t, doc.Dhcpd.Items)
	assert.Empty(t, doc.Dhcpd.Items)
}

func TestModel_NewPackage(t *testing.T) {
	t.Parallel()

	pkg := NewPackage()

	assert.False(t, pkg.Installed)
	assert.False(t, pkg.Locked)
	assert.False(t, pkg.Automatic)
	assert.Empty(t, pkg.Name)
}

func TestModel_NewService(t *testing.T) {
	t.Parallel()

	svc := NewService()

	assert.Equal(t, "stopped", svc.Status)
	assert.False(t, svc.Enabled)
	assert.Equal(t, 0, svc.PID)
}

func TestModel_NewSecurityConfig(t *testing.T) {
	t.Parallel()

	sc := NewSecurityConfig()

	assert.NotNil(t, sc.Filter.Rule)
	assert.Empty(t, sc.Filter.Rule)
}

func TestModel_NewFirewall(t *testing.T) {
	t.Parallel()

	fw := NewFirewall()
	require.NotNil(t, fw)
}

func TestModel_NewIDS(t *testing.T) {
	t.Parallel()

	ids := NewIDS()
	require.NotNil(t, ids)
}

func TestModel_NewIPsec(t *testing.T) {
	t.Parallel()

	ipsec := NewIPsec()
	require.NotNil(t, ipsec)
}

func TestModel_NewSwanctl(t *testing.T) {
	t.Parallel()

	sw := NewSwanctl()
	require.NotNil(t, sw)
}

func TestModel_StringPtr(t *testing.T) {
	t.Parallel()

	s := StringPtr("hello")
	require.NotNil(t, s)
	assert.Equal(t, "hello", *s)

	empty := StringPtr("")
	require.NotNil(t, empty)
	assert.Empty(t, *empty)
}

func TestModel_EnrichDocument(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		t.Parallel()
		result := EnrichDocument(nil)
		assert.Nil(t, result)
	})

	t.Run("valid document returns enriched", func(t *testing.T) {
		t.Parallel()
		doc := NewOpnSenseDocument()
		doc.System.Hostname = "test-host"
		doc.System.Domain = "test.local"

		result := EnrichDocument(doc)
		require.NotNil(t, result)
		assert.Equal(t, "test-host", result.System.Hostname)
	})
}
