// Package pfsense defines the data structures for pfSense configurations.
package pfsense

import (
	"encoding/xml"
	"testing"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIPsecPhase1MarshalXML_BoolFlagProducesPresenceElement verifies that BoolFlag fields
// on IPsecPhase1 marshal as presence-based XML elements, not textual booleans.
func TestIPsecPhase1MarshalXML_BoolFlagProducesPresenceElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		phase        IPsecPhase1
		wantDisabled bool
		wantMobile   bool
	}{
		{
			name: "disabled and mobile present",
			phase: IPsecPhase1{
				IKEId:    "1",
				Disabled: opnsense.BoolFlag(true),
				Mobile:   opnsense.BoolFlag(true),
			},
			wantDisabled: true,
			wantMobile:   true,
		},
		{
			name: "disabled and mobile absent",
			phase: IPsecPhase1{
				IKEId:    "1",
				Disabled: opnsense.BoolFlag(false),
				Mobile:   opnsense.BoolFlag(false),
			},
			wantDisabled: false,
			wantMobile:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := xml.Marshal(tt.phase)
			require.NoError(t, err)

			xmlStr := string(out)

			if tt.wantDisabled {
				assert.Contains(t, xmlStr, "<disabled>", "disabled must produce presence element")
				assert.NotContains(t, xmlStr, "true", "disabled must not contain textual boolean")
			} else {
				assert.NotContains(t, xmlStr, "<disabled", "disabled must be omitted when false")
			}

			if tt.wantMobile {
				assert.Contains(t, xmlStr, "<mobile>", "mobile must produce presence element")
			} else {
				assert.NotContains(t, xmlStr, "<mobile", "mobile must be omitted when false")
			}
		})
	}
}

// TestIPsecPhase1UnmarshalXML_BoolFlag verifies that BoolFlag fields on IPsecPhase1
// correctly unmarshal from self-closing and absent XML elements.
//
//nolint:dupl // structurally similar to TestIPsecClientUnmarshalXML_BoolFlag but tests different types
func TestIPsecPhase1UnmarshalXML_BoolFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		wantDisabled bool
		wantMobile   bool
	}{
		{
			name:         "disabled self-closing",
			xml:          `<phase1><disabled/><ikeid>1</ikeid></phase1>`,
			wantDisabled: true,
			wantMobile:   false,
		},
		{
			name:         "mobile self-closing",
			xml:          `<phase1><mobile/><ikeid>1</ikeid></phase1>`,
			wantDisabled: false,
			wantMobile:   true,
		},
		{
			name:         "both absent",
			xml:          `<phase1><ikeid>1</ikeid></phase1>`,
			wantDisabled: false,
			wantMobile:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var result IPsecPhase1
			err := xml.Unmarshal([]byte(tt.xml), &result)
			require.NoError(t, err)

			assert.Equal(t, tt.wantDisabled, result.Disabled.Bool(), "Disabled mismatch")
			assert.Equal(t, tt.wantMobile, result.Mobile.Bool(), "Mobile mismatch")
		})
	}
}

// TestIPsecPhase2MarshalXML_BoolFlagProducesPresenceElement verifies that the Disabled
// BoolFlag on IPsecPhase2 marshals as a presence-based XML element.
func TestIPsecPhase2MarshalXML_BoolFlagProducesPresenceElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		phase        IPsecPhase2
		wantDisabled bool
	}{
		{
			name: "disabled present",
			phase: IPsecPhase2{
				IKEId:    "1",
				Disabled: opnsense.BoolFlag(true),
			},
			wantDisabled: true,
		},
		{
			name: "disabled absent",
			phase: IPsecPhase2{
				IKEId:    "1",
				Disabled: opnsense.BoolFlag(false),
			},
			wantDisabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := xml.Marshal(tt.phase)
			require.NoError(t, err)

			xmlStr := string(out)

			if tt.wantDisabled {
				assert.Contains(t, xmlStr, "<disabled>", "disabled must produce presence element")
				assert.NotContains(t, xmlStr, "true", "disabled must not contain textual boolean")
			} else {
				assert.NotContains(t, xmlStr, "<disabled", "disabled must be omitted when false")
			}
		})
	}
}

// TestIPsecPhase2UnmarshalXML_BoolFlag verifies that the Disabled BoolFlag field on
// IPsecPhase2 correctly unmarshals from self-closing and absent XML elements.
func TestIPsecPhase2UnmarshalXML_BoolFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		xml          string
		wantDisabled bool
	}{
		{
			name:         "disabled self-closing",
			xml:          `<phase2><disabled/><ikeid>1</ikeid></phase2>`,
			wantDisabled: true,
		},
		{
			name:         "disabled absent",
			xml:          `<phase2><ikeid>1</ikeid></phase2>`,
			wantDisabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var result IPsecPhase2
			err := xml.Unmarshal([]byte(tt.xml), &result)
			require.NoError(t, err)

			assert.Equal(t, tt.wantDisabled, result.Disabled.Bool(), "Disabled mismatch")
		})
	}
}

// TestIPsecXMLRoundTrip_NestedStructs verifies that a realistic IPsec XML fragment
// with Phase 1, Phase 2, encryption algorithms, and network identities correctly
// survives XML unmarshal. This catches tag mismatches on nested types like IPsecID,
// IPsecEncryptionAlgorithm, and IPsecPhase1Encryption that converter tests cannot detect.
func TestIPsecXMLRoundTrip_NestedStructs(t *testing.T) {
	t.Parallel()

	input := `<ipsec>
		<phase1>
			<ikeid>1</ikeid>
			<iketype>ikev2</iketype>
			<remote-gateway>203.0.113.1</remote-gateway>
			<authentication_method>pre_shared_key</authentication_method>
			<encryption>
				<encryption-algorithm-option>
					<name>aes</name>
					<keylen>256</keylen>
				</encryption-algorithm-option>
				<encryption-algorithm-option>
					<name>aes</name>
					<keylen>128</keylen>
				</encryption-algorithm-option>
			</encryption>
			<disabled/>
		</phase1>
		<phase2>
			<ikeid>1</ikeid>
			<uniqid>abc123</uniqid>
			<mode>tunnel</mode>
			<localid>
				<type>network</type>
				<address>192.168.1.0</address>
				<netbits>24</netbits>
			</localid>
			<remoteid>
				<type>network</type>
				<address>10.0.0.0</address>
				<netbits>8</netbits>
			</remoteid>
			<encryption-algorithm-option>
				<name>aes</name>
				<keylen>256</keylen>
			</encryption-algorithm-option>
			<hash-algorithm-option>
				<name>hmac-sha256</name>
			</hash-algorithm-option>
			<pfsgroup>14</pfsgroup>
		</phase2>
		<client>
			<enable/>
			<user_source>local</user_source>
			<pool_address>10.10.10.0</pool_address>
			<dns_server1>8.8.8.8</dns_server1>
		</client>
	</ipsec>`

	var result IPsec
	err := xml.Unmarshal([]byte(input), &result)
	require.NoError(t, err)

	// Phase 1
	require.Len(t, result.Phase1, 1)
	p1 := result.Phase1[0]
	assert.Equal(t, "1", p1.IKEId)
	assert.Equal(t, "ikev2", p1.IKEType)
	assert.Equal(t, "203.0.113.1", p1.RemoteGW)
	assert.Equal(t, "pre_shared_key", p1.AuthMethod)
	assert.True(t, p1.Disabled.Bool())
	require.Len(t, p1.Encryption.Algorithms, 2)
	assert.Equal(t, "aes", p1.Encryption.Algorithms[0].Name)
	assert.Equal(t, "256", p1.Encryption.Algorithms[0].KeyLen)
	assert.Equal(t, "128", p1.Encryption.Algorithms[1].KeyLen)

	// Phase 2
	require.Len(t, result.Phase2, 1)
	p2 := result.Phase2[0]
	assert.Equal(t, "1", p2.IKEId)
	assert.Equal(t, "abc123", p2.UniqID)
	assert.Equal(t, "tunnel", p2.Mode)
	assert.Equal(t, "network", p2.LocalID.Type)
	assert.Equal(t, "192.168.1.0", p2.LocalID.Address)
	assert.Equal(t, "24", p2.LocalID.Netbits)
	assert.Equal(t, "network", p2.RemoteID.Type)
	assert.Equal(t, "10.0.0.0", p2.RemoteID.Address)
	assert.Equal(t, "8", p2.RemoteID.Netbits)
	require.Len(t, p2.EncryptionAlgorithms, 1)
	assert.Equal(t, "aes", p2.EncryptionAlgorithms[0].Name)
	assert.Equal(t, "256", p2.EncryptionAlgorithms[0].KeyLen)
	require.Len(t, p2.HashAlgorithms, 1)
	assert.Equal(t, "hmac-sha256", p2.HashAlgorithms[0].Name)
	assert.Equal(t, "14", p2.PFSGroup)

	// Client
	assert.True(t, result.Client.Enable.Bool())
	assert.Equal(t, "local", result.Client.UserSource)
	assert.Equal(t, "10.10.10.0", result.Client.PoolAddress)
	assert.Equal(t, "8.8.8.8", result.Client.DNSServer1)
}

// TestIPsecClientMarshalXML_BoolFlagProducesPresenceElement verifies that the Enable
// and SavePasswd BoolFlag fields on IPsecClient marshal as presence-based XML elements.
func TestIPsecClientMarshalXML_BoolFlagProducesPresenceElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		client         IPsecClient
		wantEnable     bool
		wantSavePasswd bool
	}{
		{
			name: "enable and save_passwd present",
			client: IPsecClient{
				Enable:     opnsense.BoolFlag(true),
				SavePasswd: opnsense.BoolFlag(true),
				UserSource: "local",
			},
			wantEnable:     true,
			wantSavePasswd: true,
		},
		{
			name: "enable and save_passwd absent",
			client: IPsecClient{
				Enable:     opnsense.BoolFlag(false),
				SavePasswd: opnsense.BoolFlag(false),
				UserSource: "local",
			},
			wantEnable:     false,
			wantSavePasswd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := xml.Marshal(tt.client)
			require.NoError(t, err)

			xmlStr := string(out)

			if tt.wantEnable {
				assert.Contains(t, xmlStr, "<enable>", "enable must produce presence element")
				assert.NotContains(t, xmlStr, "true", "enable must not contain textual boolean")
			} else {
				assert.NotContains(t, xmlStr, "<enable", "enable must be omitted when false")
			}

			if tt.wantSavePasswd {
				assert.Contains(t, xmlStr, "<save_passwd>", "save_passwd must produce presence element")
			} else {
				assert.NotContains(t, xmlStr, "<save_passwd", "save_passwd must be omitted when false")
			}
		})
	}
}

// TestIPsecClientUnmarshalXML_BoolFlag verifies that BoolFlag fields on IPsecClient
// correctly unmarshal from self-closing and absent XML elements.
//
//nolint:dupl // structurally similar to TestIPsecPhase1UnmarshalXML_BoolFlag but tests different types
func TestIPsecClientUnmarshalXML_BoolFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		xml            string
		wantEnable     bool
		wantSavePasswd bool
	}{
		{
			name:           "enable self-closing",
			xml:            `<client><enable/><user_source>local</user_source></client>`,
			wantEnable:     true,
			wantSavePasswd: false,
		},
		{
			name:           "save_passwd self-closing",
			xml:            `<client><save_passwd/><user_source>local</user_source></client>`,
			wantEnable:     false,
			wantSavePasswd: true,
		},
		{
			name:           "both absent",
			xml:            `<client><user_source>local</user_source></client>`,
			wantEnable:     false,
			wantSavePasswd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var result IPsecClient
			err := xml.Unmarshal([]byte(tt.xml), &result)
			require.NoError(t, err)

			assert.Equal(t, tt.wantEnable, result.Enable.Bool(), "Enable mismatch")
			assert.Equal(t, tt.wantSavePasswd, result.SavePasswd.Bool(), "SavePasswd mismatch")
		})
	}
}
