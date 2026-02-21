package opnsense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{name: "empty string", s: "", sep: ",", want: nil},
		{name: "single value", s: "dhcpd", sep: ",", want: []string{"dhcpd"}},
		{name: "multiple values", s: "virtualip,certs,dhcpd", sep: ",", want: []string{"virtualip", "certs", "dhcpd"}},
		{name: "trailing separator", s: "virtualip,certs,", sep: ",", want: []string{"virtualip", "certs"}},
		{name: "leading separator", s: ",virtualip,certs", sep: ",", want: []string{"virtualip", "certs"}},
		{name: "whitespace-only parts", s: "virtualip, , ,certs", sep: ",", want: []string{"virtualip", "certs"}},
		{
			name: "spaces around values",
			s:    " virtualip , certs , dhcpd ",
			sep:  ",",
			want: []string{"virtualip", "certs", "dhcpd"},
		},
		{name: "only separators", s: ",,,", sep: ",", want: nil},
		{name: "different separator", s: "a;b;c", sep: ";", want: []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := splitNonEmpty(tt.s, tt.sep)
			assert.Equal(t, tt.want, got)
		})
	}
}
