package opnsense_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUser_ValueFields_DecodeAsStrings reads the root user from a generated
// config that carries <expires>, <authorizedkeys>, <ipsecpsk> and <otp_seed>
// as empty elements, the form an unset one can take, then sets a value in
// each. BoolFlag read each empty element as true, and read a set value as
// false unless it happened to be a truthy word.
func TestUser_ValueFields_DecodeAsStrings(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "sample.config.2.xml"))
	require.NoError(t, err)

	set := map[string]string{
		"expires":        "12/31/2027",
		"authorizedkeys": "c3NoLWVkMjU1MTkgZXhhbXBsZQ==",
		"ipsecpsk":       "example-psk",
		"otp_seed":       "JBSWY3DPEHPK3PXP",
	}

	withValues := raw
	for tag, value := range set {
		empty := []byte("<" + tag + "/>")
		require.Equalf(t, 1, bytes.Count(raw, empty),
			"fixture no longer carries an empty <%s>; this test is vacuous", tag)

		withValues = bytes.Replace(withValues, empty, []byte("<"+tag+">"+value+"</"+tag+">"), 1)
	}

	tests := []struct {
		name string
		cfg  []byte
		want map[string]string
	}{
		{
			name: "unset",
			cfg:  raw,
			want: map[string]string{"expires": "", "authorizedkeys": "", "ipsecpsk": "", "otp_seed": ""},
		},
		{name: "set", cfg: withValues, want: set},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := cfgparser.NewXMLParser().Parse(context.Background(), bytes.NewReader(tt.cfg))
			require.NoError(t, err)
			require.Len(t, doc.System.User, 1)

			user := doc.System.User[0]
			require.Equal(t, "root", user.Name)

			assert.Equal(t, tt.want, map[string]string{
				"expires":        user.Expires,
				"authorizedkeys": user.AuthorizedKeys,
				"ipsecpsk":       user.IPSecPSK,
				"otp_seed":       user.OTPSeed,
			})
		})
	}
}
