package opnsense_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseGatewayGroup runs a config holding one <gateway_group> with the given
// member elements through the full parser pipeline.
func parseGatewayGroup(t *testing.T, members string) common.GatewayGroup {
	t.Helper()

	config := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.com</domain></system>
  <interfaces><wan><if>em0</if></wan></interfaces>
  <gateways>
    <gateway_group><name>WAN_FAILOVER</name>%s<trigger>down</trigger></gateway_group>
  </gateways>
</opnsense>`, members)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(), strings.NewReader(config), common.DeviceTypeUnknown, false)
	require.NoError(t, err)
	require.Len(t, device.Routing.GatewayGroups, 1)

	return device.Routing.GatewayGroups[0]
}

// TestConverter_GatewayGroups_Tiers pins the members of a group across the
// OPNsense 26.7 change: up to 26.1 each <item> is name|tier, and from 26.7
// <item> and <item2> to <item5> each hold one tier's gateways, comma-separated.
func TestConverter_GatewayGroups_Tiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members string
		want    []string
	}{
		{
			name:    "26.7 tier lists",
			members: `<item2>WAN_GW2</item2><item3/><item4/><item5/><item>WAN_GW,WAN_GW3</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW3|1", "WAN_GW2|2"},
		},
		{
			name:    "26.7 group with no tier 1 gateway",
			members: `<item2/><item3>WAN_GW2</item3><item4/><item5>WAN_GW</item5><item/>`,
			want:    []string{"WAN_GW2|3", "WAN_GW|5"},
		},
		{
			name:    "legacy name|tier entries",
			members: `<item>WAN_GW|1</item><item>WAN_GW3|1</item><item>WAN_GW2|2</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW3|1", "WAN_GW2|2"},
		},
		{
			name:    "26.7 tier 4",
			members: `<item2/><item3/><item4>WAN_GW4</item4><item5/><item>WAN_GW</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW4|4"},
		},
		{
			name:    "legacy name|tier|vip entries keep name and tier",
			members: `<item>WAN_GW|1|address</item><item>WAN_GW2|2|address</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW2|2"},
		},
		{
			name:    "legacy entries override only the tiers they use",
			members: `<item2>WAN_GW4</item2><item3>WAN_GW5</item3><item>WAN_GW|1</item><item>WAN_GW2|2</item><item/>`,
			want:    []string{"WAN_GW|1", "WAN_GW2|2", "WAN_GW5|3"},
		},
		{
			name:    "legacy entries in gateway order export in tier order",
			members: `<item>WAN_GW|2</item><item>WAN_GW3|1</item><item>WAN_GW2|1</item>`,
			want:    []string{"WAN_GW3|1", "WAN_GW2|1", "WAN_GW|2"},
		},
		{
			name:    "a tier list the legacy entries keep sorts among them",
			members: `<item2>WAN_GW4</item2><item>WAN_GW|3</item>`,
			want:    []string{"WAN_GW4|2", "WAN_GW|3"},
		},
		{
			name:    "legacy tier 5 entry replaces the tier 5 list",
			members: `<item5>WAN_GW5</item5><item>WAN_GW|5</item><item>WAN_GW2|2</item>`,
			want:    []string{"WAN_GW2|2", "WAN_GW|5"},
		},
		{
			name:    "legacy tiers above 5 are kept in numeric order",
			members: `<item>WAN_GW10|10</item><item>WAN_GW6|6</item><item>WAN_GW|1</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW6|6", "WAN_GW10|10"},
		},
		{
			name:    "legacy tier 0 is kept and sorts first",
			members: `<item>WAN_GW2|2</item><item>WAN_GW|0</item>`,
			want:    []string{"WAN_GW|0", "WAN_GW2|2"},
		},
		{
			name:    "legacy tier that is not a number sorts last",
			members: `<item>WAN_GW9|x</item><item>WAN_GW|2</item>`,
			want:    []string{"WAN_GW|2", "WAN_GW9|x"},
		},
		{
			name:    "legacy tier that is not a number sorts after tiers above 5",
			members: `<item>WAN_GW9|x</item><item>WAN_GW6|6</item>`,
			want:    []string{"WAN_GW6|6", "WAN_GW9|x"},
		},
		{
			name:    "tier-less entries in a legacy group read as tier 1",
			members: `<item>WAN_GW|2</item><item>WAN_GW2</item><item>WAN_GW3|</item>`,
			want:    []string{"WAN_GW2|1", "WAN_GW3|1", "WAN_GW|2"},
		},
		{
			name:    "a pipe in a later item still makes the group legacy",
			members: `<item>WAN_GW</item><item>WAN_GW2|2</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW2|2"},
		},
		{
			name:    "bare names read as tier 1",
			members: `<item>WAN_GW</item><item>WAN_GW2</item>`,
			want:    []string{"WAN_GW|1", "WAN_GW2|1"},
		},
		{
			name:    "no members",
			members: `<item2/><item3/><item4/><item5/><item/>`,
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, parseGatewayGroup(t, tc.members).Items)
		})
	}
}

// TestConverter_GatewayGroups_DocumentOrderWithinTier pins that a tier keeps its
// document order. The group has more than twelve entries because slices.SortFunc
// only scrambles equal elements above that size.
func TestConverter_GatewayGroups_DocumentOrderWithinTier(t *testing.T) {
	t.Parallel()

	var legacy strings.Builder
	var byTier [2][]string
	for i := range 20 {
		entry := fmt.Sprintf("GW%02d|%d", i, i%2+1)
		legacy.WriteString("<item>" + entry + "</item>")
		byTier[i%2] = append(byTier[i%2], entry)
	}

	assert.Equal(t, slices.Concat(byTier[0], byTier[1]), parseGatewayGroup(t, legacy.String()).Items)
}

// TestConverter_GatewayGroups_LegacyExportsAsMigrated pins that a legacy group,
// which the GUI writes in gateway rather than tier order, exports the same array
// as the group GatewayGroupItemField writes from it on 26.7.
func TestConverter_GatewayGroups_LegacyExportsAsMigrated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		legacy   string
		migrated string
	}{
		{
			name:     "tier 2 gateway written first",
			legacy:   `<item>WAN_GW|2</item><item>WAN_GW3|1</item><item>WAN_GW2|1</item>`,
			migrated: `<item2>WAN_GW</item2><item3/><item4/><item5/><item>WAN_GW3,WAN_GW2</item>`,
		},
		{
			name:     "name|tier|vip entries",
			legacy:   `<item>WAN_GW|3|address</item><item>WAN_GW2|1|address</item>`,
			migrated: `<item2/><item3>WAN_GW</item3><item4/><item5/><item>WAN_GW2</item>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := parseGatewayGroup(t, tc.migrated).Items
			require.NotEmpty(t, want)
			assert.Equal(t, want, parseGatewayGroup(t, tc.legacy).Items)
		})
	}
}
