package schema

import (
	"encoding/xml"
	"testing"
)

const testInterfaceDevice = "em0"

// TestInterfaces_MarshalUnmarshal_Simple tests XML round-trip for Interfaces.
//

func TestInterfaces_MarshalUnmarshal_Simple(t *testing.T) {
	t.Parallel()

	i := &Interfaces{Items: map[string]Interface{
		"wan": {If: testInterfaceDevice, Enable: "1"},
	}}

	data, err := xml.Marshal(i)
	if err != nil {
		t.Fatalf("MarshalXML failed: %v", err)
	}

	var result Interfaces
	if err := xml.Unmarshal(data, &result); err != nil {
		t.Fatalf("UnmarshalXML failed: %v", err)
	}

	if len(result.Items) != 1 {
		t.Errorf("Expected 1 item, got %d", len(result.Items))
	}

	wan, exists := result.Items["wan"]
	if !exists {
		t.Fatal("Expected wan interface to exist after round-trip")
	}

	if wan.If != testInterfaceDevice {
		t.Errorf("wan.If = %q, want %q", wan.If, testInterfaceDevice)
	}

	if wan.Enable != "1" {
		t.Errorf("wan.Enable = %q, want %q", wan.Enable, "1")
	}
}
