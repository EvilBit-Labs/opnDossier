package pfsense_test

import (
	"encoding/json"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_IPsecEnabled_Gotchas16 locks in the GOTCHAS §16 invariant for
// pfSense IPsec: IPsecConfig.Enabled is driven solely by the presence of
// Phase 1 entries. Phase 2 tunnels and the mobile client hang off Phase 1 in
// pfSense, so data without a Phase 1 gate is functionally inactive and must
// produce an orphan warning — not a falsely-enabled IPsecConfig.
//
// Downstream consumers (notably builder_vpn.go) short-circuit when
// Enabled=false, so breaking this invariant either hides real tunnel data
// (Enabled stuck at false with valid Phase 1) or surfaces empty configs as
// real (Enabled=true with nothing to report).
func TestConverter_IPsecEnabled_Gotchas16(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		ipsec           pfsenseSchema.IPsec
		wantEnabled     bool
		wantOrphanP2    bool
		wantOrphanMC    bool
		expectWarnCount int
	}{
		{
			name: "phase1 only enables ipsec",
			ipsec: pfsenseSchema.IPsec{
				Phase1: []pfsenseSchema.IPsecPhase1{{IKEId: "1", Descr: "p1-only"}},
			},
			wantEnabled: true,
		},
		{
			name: "phase1 plus phase2 enables ipsec",
			ipsec: pfsenseSchema.IPsec{
				Phase1: []pfsenseSchema.IPsecPhase1{{IKEId: "1", Descr: "p1"}},
				Phase2: []pfsenseSchema.IPsecPhase2{{Descr: "p2"}},
			},
			wantEnabled: true,
		},
		{
			name: "phase1 plus mobile client enables ipsec",
			ipsec: pfsenseSchema.IPsec{
				Phase1: []pfsenseSchema.IPsecPhase1{{IKEId: "1"}},
				Client: pfsenseSchema.IPsecClient{Enable: opnsenseSchema.BoolFlag(true)},
			},
			wantEnabled: true,
		},
		{
			name: "phase2 without phase1 is orphan and disabled",
			ipsec: pfsenseSchema.IPsec{
				Phase2: []pfsenseSchema.IPsecPhase2{{Descr: "orphan-p2"}},
			},
			wantEnabled:     false,
			wantOrphanP2:    true,
			expectWarnCount: 1,
		},
		{
			name: "mobile client without phase1 is orphan and disabled",
			ipsec: pfsenseSchema.IPsec{
				Client: pfsenseSchema.IPsecClient{Enable: opnsenseSchema.BoolFlag(true)},
			},
			wantEnabled:     false,
			wantOrphanMC:    true,
			expectWarnCount: 1,
		},
		{
			name: "phase2 and mobile client both orphan emit two warnings",
			ipsec: pfsenseSchema.IPsec{
				Phase2: []pfsenseSchema.IPsecPhase2{{Descr: "orphan-p2"}},
				Client: pfsenseSchema.IPsecClient{Enable: opnsenseSchema.BoolFlag(true)},
			},
			wantEnabled:     false,
			wantOrphanP2:    true,
			wantOrphanMC:    true,
			expectWarnCount: 2,
		},
		{
			name:        "empty ipsec config is disabled without warnings",
			ipsec:       pfsenseSchema.IPsec{},
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := &pfsenseSchema.Document{IPsec: tt.ipsec}
			device, warnings, err := pfsense.ConvertDocument(doc)
			require.NoError(t, err)
			require.NotNil(t, device)

			assert.Equal(t, tt.wantEnabled, device.VPN.IPsec.Enabled,
				"IPsec.Enabled mismatch")

			orphanP2 := false
			orphanMC := false
			for _, w := range warnings {
				switch w.Field {
				case "IPsec.Phase2":
					orphanP2 = true
					assert.Contains(t, w.Message, "Phase 1")
					assert.Equal(t, common.SeverityMedium, w.Severity)
					// warnOrphanIPsecData formats the value as "<N> entries";
					// lock that in so the message format can't drift silently.
					assert.Contains(t, w.Value, "entries",
						"Phase 2 orphan value should describe the orphan count")
				case "IPsec.Client":
					orphanMC = true
					assert.Contains(t, w.Message, "Phase 1")
					assert.Equal(t, common.SeverityMedium, w.Severity)
					assert.Equal(t, "enabled", w.Value,
						"mobile client orphan value should be literal 'enabled'")
				}
			}
			assert.Equal(t, tt.wantOrphanP2, orphanP2, "Phase 2 orphan warning presence mismatch")
			assert.Equal(t, tt.wantOrphanMC, orphanMC, "mobile client orphan warning presence mismatch")

			if tt.expectWarnCount > 0 {
				// Count only IPsec orphan warnings (other fields may also warn on hand-built docs).
				ipsecOrphan := 0
				for _, w := range warnings {
					if w.Field == "IPsec.Phase2" || w.Field == "IPsec.Client" {
						ipsecOrphan++
					}
				}
				assert.Equal(t, tt.expectWarnCount, ipsecOrphan,
					"expected %d IPsec orphan warning(s), got %d", tt.expectWarnCount, ipsecOrphan)
			}
		})
	}
}

// TestConverter_IPsecPhase1FieldValidators locks in the Phase 1 field-level
// enum-like validators (validateIPsecPhase1Fields): unrecognized non-empty
// IKEType, Mode, or Protocol each emit a SeverityMedium warning.
func TestConverter_IPsecPhase1FieldValidators(t *testing.T) {
	t.Parallel()

	doc := &pfsenseSchema.Document{
		IPsec: pfsenseSchema.IPsec{
			Phase1: []pfsenseSchema.IPsecPhase1{{
				IKEId:    "1",
				IKEType:  "ikev9",    // invalid
				Mode:     "sideways", // invalid
				Protocol: "inet999",  // invalid
			}},
		},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	expected := []struct {
		field   string
		value   string
		snippet string
	}{
		{"IPsec.Phase1[0].IKEType", "ikev9", "IKE version"},
		{"IPsec.Phase1[0].Mode", "sideways", "negotiation mode"},
		{"IPsec.Phase1[0].Protocol", "inet999", "address family"},
	}

	for _, exp := range expected {
		w := findPfSenseWarning(warnings, exp.field, exp.value)
		require.NotNil(t, w, "expected warning on %s=%q, got %+v",
			exp.field, exp.value, warnings)
		assert.Contains(t, w.Message, exp.snippet,
			"message for %s should mention %q", exp.field, exp.snippet)
		assert.Equal(t, common.SeverityMedium, w.Severity,
			"severity for %s drifted", exp.field)
	}
}

// TestConverter_IPsecPhase2FieldValidators locks in the Phase 2 field-level
// validators (validateIPsecPhase2Fields). Phase 2 validators only run when a
// Phase 1 also exists, so the fixture includes a minimal Phase 1.
func TestConverter_IPsecPhase2FieldValidators(t *testing.T) {
	t.Parallel()

	doc := &pfsenseSchema.Document{
		IPsec: pfsenseSchema.IPsec{
			Phase1: []pfsenseSchema.IPsecPhase1{{IKEId: "1"}},
			Phase2: []pfsenseSchema.IPsecPhase2{{
				Mode:     "pigeon",   // invalid
				Protocol: "rfc-9999", // invalid
			}},
		},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	expected := []struct {
		field   string
		value   string
		snippet string
	}{
		{"IPsec.Phase2[0].Mode", "pigeon", "tunnel mode"},
		{"IPsec.Phase2[0].Protocol", "rfc-9999", "IPsec protocol"},
	}

	for _, exp := range expected {
		w := findPfSenseWarning(warnings, exp.field, exp.value)
		require.NotNil(t, w, "expected warning on %s=%q, got %+v",
			exp.field, exp.value, warnings)
		assert.Contains(t, w.Message, exp.snippet,
			"message for %s should mention %q", exp.field, exp.snippet)
		assert.Equal(t, common.SeverityMedium, w.Severity,
			"severity for %s drifted", exp.field)
	}
}

// TestConverter_IPsecPhase2FieldValidators_EmptyDoesNotWarn protects the
// empty-string exemption (`if p2.Mode != ""`) on Phase 2 field validators.
// Parallels the Phase 1 empty-string coverage in converter_enum_cast_test.go.
func TestConverter_IPsecPhase2FieldValidators_EmptyDoesNotWarn(t *testing.T) {
	t.Parallel()

	doc := &pfsenseSchema.Document{
		IPsec: pfsenseSchema.IPsec{
			Phase1: []pfsenseSchema.IPsecPhase1{{IKEId: "1"}},
			Phase2: []pfsenseSchema.IPsecPhase2{{
				Mode:     "", // empty -- must not warn
				Protocol: "", // empty -- must not warn
			}},
		},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	for _, w := range warnings {
		assert.NotEqual(t, "IPsec.Phase2[0].Mode", w.Field,
			"empty Phase 2 Mode must not warn, got %+v", w)
		assert.NotEqual(t, "IPsec.Phase2[0].Protocol", w.Field,
			"empty Phase 2 Protocol must not warn, got %+v", w)
	}
}

// TestConverter_IPsecPhase1_PreSharedKeyExclusion locks in the security
// invariant that a present PreSharedKey emits a SeverityLow warning and is
// deliberately NOT propagated into the exported IPsecPhase1Tunnel. Removing
// the exclusion (and the warning) would silently leak pre-shared keys into
// downstream exports.
func TestConverter_IPsecPhase1_PreSharedKeyExclusion(t *testing.T) {
	t.Parallel()

	doc := &pfsenseSchema.Document{
		IPsec: pfsenseSchema.IPsec{
			Phase1: []pfsenseSchema.IPsecPhase1{{
				IKEId:        "1",
				PreSharedKey: "super-secret-psk-42",
			}},
		},
	}

	device, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.NotNil(t, device)

	pskWarning := findPfSenseWarning(warnings, "IPsec.Phase1[0].PreSharedKey", "[present]")
	require.NotNil(t, pskWarning, "expected PSK exclusion warning")
	assert.Contains(t, pskWarning.Message, "security",
		"PSK warning should explain the security reason for exclusion")
	assert.Equal(t, common.SeverityLow, pskWarning.Severity)

	// The converted Phase 1 tunnel must not carry the raw PSK anywhere that
	// would round-trip through the canonical export format. Marshal to JSON
	// (the primary export format) and assert the raw key is absent — this
	// catches accidental exposure through any exported field, including
	// pointer fields that %+v would stringify without dereferencing.
	require.Len(t, device.VPN.IPsec.Phase1Tunnels, 1)
	tunnelJSON, err := json.Marshal(device.VPN.IPsec.Phase1Tunnels[0])
	require.NoError(t, err, "Phase1Tunnel must be JSON-marshalable")
	assert.NotContains(t, string(tunnelJSON), "super-secret-psk-42",
		"raw PSK must not appear in JSON-exported Phase1Tunnel")
}
