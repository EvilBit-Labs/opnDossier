package firewall_test

import (
	"slices"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/plugins/firewall"
)

// TestPacketFilterControls_List pins the controls that fail with packet
// filtering disabled. An end-to-end run cannot pin them: a fixture fails
// several of them on its own check, so dropping one from the list changes no
// verdict there.
func TestPacketFilterControls_List(t *testing.T) {
	t.Parallel()

	want := []string{
		"FIREWALL-022", "FIREWALL-023", "FIREWALL-024", "FIREWALL-027", "FIREWALL-028",
		"FIREWALL-029", "FIREWALL-030", "FIREWALL-032", "FIREWALL-041",
	}

	if !slices.Equal(firewall.PacketFilterControls, want) {
		t.Errorf("packetFilterControls = %v, want %v", firewall.PacketFilterControls, want)
	}
}
