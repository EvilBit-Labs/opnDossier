package sans_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/compliance"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/sans"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
)

// TestPacketFilterControls_List pins the controls that fail with packet
// filtering disabled. An end-to-end run cannot pin them: a fixture fails
// several of them on its own check, so dropping one from the list changes no
// verdict there.
func TestPacketFilterControls_List(t *testing.T) {
	t.Parallel()

	want := []string{
		"SANS-FW-001", "SANS-FW-002", "SANS-FW-003", "SANS-FW-007", "SANS-FW-009",
		"SANS-FW-012", "SANS-FW-014", "SANS-FW-015", "SANS-FW-017", "SANS-FW-018",
		"SANS-FW-019", "SANS-FW-020", "SANS-FW-021", "SANS-FW-022", "SANS-FW-024",
	}

	if !slices.Equal(sans.PacketFilterControls, want) {
		t.Errorf("packetFilterControls = %v, want %v", sans.PacketFilterControls, want)
	}
}

// TestPacketFilterDisabled_FTPIsolation checks that SANS-FW-016 fails with
// packet filtering disabled only when the config holds an FTP port forward. The
// forward goes to the DMZ, so the control passes its own check, and the
// failure can only come from the packet filter setting. Without a forward there
// is no FTP server to isolate and the control stays unknown.
func TestPacketFilterDisabled_FTPIsolation(t *testing.T) {
	t.Parallel()

	const control = "SANS-FW-016"

	ftp := []common.InboundNATRule{{Interfaces: []string{"opt1"}, ExternalPort: "21"}}

	for _, tt := range []struct {
		name             string
		forwards         []common.InboundNATRule
		disabled         bool
		evaluated, fails bool
	}{
		{"forward, filtering on", ftp, false, true, false},
		{"forward, filtering off", ftp, true, true, true},
		{"no forward, filtering off", nil, true, false, false},
	} {
		device := &common.CommonDevice{
			System: common.System{PacketFilterDisabled: tt.disabled},
			NAT:    common.NATConfig{InboundRules: tt.forwards},
		}

		findings, evaluated, err := sans.NewPlugin().RunChecks(device)
		if err != nil {
			t.Fatal(err)
		}

		if got := slices.Contains(evaluated, control); got != tt.evaluated {
			t.Errorf("%s: evaluated = %v, want %v", tt.name, got, tt.evaluated)
		}

		fails := slices.ContainsFunc(findings, func(f compliance.Finding) bool {
			return slices.Contains(f.References, control)
		})
		if fails != tt.fails {
			t.Errorf("%s: fails = %v, want %v", tt.name, fails, tt.fails)
		}
	}
}
