package validator

import (
	"testing"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
)

// TestValidateSysctl_EmptyValueIsValid covers a tunable left at its default.
// From OPNsense 25.1.3 on the value is empty, and the name checks still apply.
func TestValidateSysctl_EmptyValueIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		items      []schema.SysctlItem
		wantFields []string
	}{
		{
			name: "empty and keyword values",
			items: []schema.SysctlItem{
				{Tunable: "net.inet.ip.accept_sourceroute", Value: "default"},
				{Tunable: "net.inet.ip.sourceroute", Value: ""},
			},
		},
		{
			name: "empty value with a duplicate name",
			items: []schema.SysctlItem{
				{Tunable: "net.inet.tcp.syncookies", Value: "1"},
				{Tunable: "net.inet.tcp.syncookies", Value: ""},
			},
			wantFields: []string{"sysctl[1].tunable"},
		},
		{
			name: "empty value with no name",
			items: []schema.SysctlItem{
				{Tunable: "net.inet.tcp.syncookies", Value: "1"},
				{Descr: "orphan", Value: ""},
			},
			wantFields: []string{"sysctl[1].tunable"},
		},
		{
			name: "empty value with a malformed name",
			items: []schema.SysctlItem{
				{Tunable: "net.inet.tcp.syncookies", Value: "1"},
				{Tunable: "syncookies", Value: ""},
			},
			wantFields: []string{"sysctl[1].tunable"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var fields []string
			for _, err := range validateSysctl(tt.items) {
				fields = append(fields, err.Field)
			}

			assert.Equal(t, tt.wantFields, fields)
		})
	}
}
