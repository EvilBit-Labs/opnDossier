package opnsense_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_InterfaceGroups_MemberSeparators drives <ifgroups> through the
// parser. The Group model writes members comma-separated, its migration
// rewrote the older space-separated form, and filter.inc ifgroup_setup splits
// on any run of spaces, commas and pipes, so each form must read as the
// firewall reads it. The description is kept.
func TestConverter_InterfaceGroups_MemberSeparators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members string
		want    []string
	}{
		{name: "comma-separated, as the Group model writes", members: "lan,opt1", want: []string{"lan", "opt1"}},
		{name: "space-separated, as older releases wrote", members: "lan opt1", want: []string{"lan", "opt1"}},
		{name: "pipes and mixed runs", members: " lan|opt1, opt2 ", want: []string{"lan", "opt1", "opt2"}},
		{name: "a single member", members: "wan", want: []string{"wan"}},
		{name: "no members", members: "", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces>
    <wan><if>vtnet0</if></wan>
    <lan><if>vtnet1</if></lan>
  </interfaces>
  <ifgroups version="1.0.0">
    <ifgroupentry uuid="d4d4d4d4-0000-4000-8000-000000000001">
      <ifname>INSIDE</ifname>
      <members>` + tt.members + `</members>
      <nogroup>0</nogroup>
      <sequence>0</sequence>
      <descr>Inside networks</descr>
    </ifgroupentry>
  </ifgroups>
</opnsense>`

			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
			require.NoError(t, err)
			require.Len(t, device.InterfaceGroups, 1)

			group := device.InterfaceGroups[0]
			assert.Equal(t, "INSIDE", group.Name)
			assert.Equal(t, tt.want, group.Members)
			assert.Equal(t, "Inside networks", group.Description)
		})
	}
}
