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
