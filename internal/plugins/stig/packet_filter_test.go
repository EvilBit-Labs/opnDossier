package stig

import (
	"slices"
	"testing"
)

// TestPacketFilterControls_List pins the controls that fail with packet
// filtering disabled. An end-to-end run cannot pin them: a fixture fails
// several of them on its own check, so dropping one from the list changes no
// verdict there.
func TestPacketFilterControls_List(t *testing.T) {
	t.Parallel()

	want := []string{"V-206694", "V-206674", "V-206701", "V-206682"}

	if !slices.Equal(packetFilterControls, want) {
		t.Errorf("packetFilterControls = %v, want %v", packetFilterControls, want)
	}
}
