package pfsense_test

import (
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
				case "IPsec.Client":
					orphanMC = true
					assert.Contains(t, w.Message, "Phase 1")
					assert.Equal(t, common.SeverityMedium, w.Severity)
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
