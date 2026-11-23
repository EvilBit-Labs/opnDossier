package pfsense_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_SSHEnabled_VendorShapes drives each way a pfSense config can
// carry the SSH switch through parse and convert. The page writes
// <ssh><enable>enabled</enable> and deletes it when unticked, and sshd starts
// when config_path_enabled('system/ssh') holds, which is isset() on <enable>,
// so any body counts. Configs older than version 18.9 keep the switch in
// <system><enablesshd>, which pfSense moves there on upgrade. <enabled> is the
// OPNsense spelling; pfSense does not read it, so on its own it leaves SSH off.
func TestConverter_SSHEnabled_VendorShapes(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../../testdata/pfsense/config-pfSense.xml")
	require.NoError(t, err)

	anchor := []byte("<nextgid>2000</nextgid>")
	require.Equal(t, 1, bytes.Count(raw, anchor), "fixture no longer carries the anchor")
	require.Equal(t, 0, bytes.Count(raw, []byte("<ssh")), "fixture now carries an SSH element of its own")
	require.Equal(t, 0, bytes.Count(raw, []byte("<enablesshd")), "fixture now carries the legacy SSH switch")

	tests := []struct {
		name     string
		element  string
		want     bool
		wantPort string
	}{
		{name: "no SSH element", element: "", want: false},
		{
			name: "page value", element: "<ssh><enable>enabled</enable><port>2222</port></ssh>",
			want: true, wantPort: "2222",
		},
		{name: "empty element", element: "<ssh><enable/></ssh>", want: true},
		{name: "false-looking body", element: "<ssh><enable>0</enable></ssh>", want: true},
		{
			name: "unticked, port kept", element: "<ssh><port>2222</port><group>admins</group></ssh>",
			want: false, wantPort: "2222",
		},
		{name: "OPNsense empty element alone", element: "<ssh><enabled/><group>admins</group></ssh>", want: false},
		{name: "OPNsense page value alone", element: "<ssh><enabled>enabled</enabled></ssh>", want: false},
		{name: "legacy empty element", element: "<enablesshd/>", want: true},
		{name: "legacy with a body", element: "<enablesshd>enabled</enablesshd>", want: true},
		{
			name: "legacy beside a port", element: "<enablesshd/><ssh><port>2222</port></ssh>",
			want: true, wantPort: "2222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := bytes.Replace(raw, anchor, append(append([]byte{}, anchor...), tt.element...), 1)

			device, _, err := pfsense.NewParser(nil).Parse(context.Background(), bytes.NewReader(config))
			require.NoError(t, err)
			assert.Equal(t, tt.want, device.System.SSH.Enabled)
			assert.Equal(t, tt.wantPort, device.System.SSH.Port)
		})
	}
}
