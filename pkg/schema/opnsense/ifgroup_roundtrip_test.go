package opnsense

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"
)

// TestInterfaceGroups_DescrRoundTrip decodes an <ifgroups> block as the Group
// model writes it, marshals it and decodes it again. The description must
// survive under the vendor's element name, <descr>; a renamed tag would
// survive a round trip through its own output, so the marshaled text is
// checked too.
func TestInterfaceGroups_DescrRoundTrip(t *testing.T) {
	t.Parallel()

	const raw = `<ifgroups version="1.0.0">` +
		`<ifgroupentry uuid="d4d4d4d4-0000-4000-8000-000000000001">` +
		`<ifname>UPLINKS</ifname><members>wan,opt1</members><sequence>10</sequence>` +
		`<descr>Internet uplinks</descr></ifgroupentry></ifgroups>`

	var decoded InterfaceGroups
	if err := xml.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.IfGroupEntry) != 1 {
		t.Fatalf("got %d groups, want 1", len(decoded.IfGroupEntry))
	}

	if got := decoded.IfGroupEntry[0].Descr; got != "Internet uplinks" {
		t.Errorf("Descr = %q, want %q", got, "Internet uplinks")
	}

	data, err := xml.Marshal(&decoded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if !strings.Contains(string(data), "<descr>Internet uplinks</descr>") {
		t.Errorf("marshaled text lost <descr>: %s", data)
	}

	var back InterfaceGroups
	if err := xml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal after marshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, back) {
		t.Errorf("round trip changed the groups:\nfrom %s\n  to %s", raw, data)
	}
}
