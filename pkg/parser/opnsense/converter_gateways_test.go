package opnsense_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyGatewayItem is the <gateways><gateway_item> in sample.config.4.xml.
const legacyGatewayItem = `    <gateway_item>
      <descr>Interface WAN Gateway</descr>
      <defaultgw>1</defaultgw>
      <ipprotocol>inet</ipprotocol>
      <interface>wan</interface>
      <gateway>192.0.2.1</gateway>
      <monitor_disable>1</monitor_disable>
      <name>WAN_GW</name>
      <interval>1</interval>
      <weight>1</weight>
      <fargw>0</fargw>
    </gateway_item>
`

// gatewayModelItemTemplate is a gateway as OPNsense 24.1 migration M1_0_0
// stores it, in the field order of Routing/Gateways.xml. The verbs are the
// uuid, name, description, address family and address.
const gatewayModelItemTemplate = `      <gateway_item uuid="%s">
        <disabled>0</disabled>
        <name>%s</name>
        <descr>%s</descr>
        <interface>wan</interface>
        <ipprotocol>%s</ipprotocol>
        <gateway>%s</gateway>
        <defaultgw>1</defaultgw>
        <fargw>0</fargw>
        <monitor_disable>1</monitor_disable>
        <monitor_noroute>0</monitor_noroute>
        <monitor/>
        <force_down>0</force_down>
        <priority>255</priority>
        <weight>1</weight>
        <latencylow/>
        <latencyhigh/>
        <losslow/>
        <losshigh/>
        <interval>1</interval>
        <time_period/>
        <loss_interval/>
        <data_length/>
      </gateway_item>
`

// Elements the tests rewrite in legacyGatewayItem and the migrated gateway.
const (
	gatewayDefaultElement        = "<defaultgw>1</defaultgw>"
	gatewayFarElement            = "<fargw>0</fargw>"
	gatewayMonitorDisableElement = "<monitor_disable>1</monitor_disable>"
)

// gatewayVersionAttr is the version attribute of the model OPNsense writes.
const gatewayVersionAttr = ` version="1.0.0"`

// Uuids of model gateways.
const (
	gatewayUUIDFirst  = "7f3c2a1e-5b6d-4e8f-9a0b-1c2d3e4f5a6b"
	gatewayUUIDSecond = "0b8e4d2c-1a3f-4c5e-8d7b-6a9f0e1d2c3b"
	gatewayUUIDThird  = "3c9d1f7a-2e4b-4a6c-8b1d-5f0e7a9c2d4e"
)

// gatewayConfig is sample.config.4.xml, rewritten around its one legacy gateway.
type gatewayConfig []byte

// openSenseAnchor is the element the model block is written under.
const openSenseAnchor = "  <OPNsense>\n"

func readGatewayConfig(t *testing.T) gatewayConfig {
	t.Helper()

	raw := readFixture(t, "sample.config.4.xml")
	require.Equal(t, 1, bytes.Count(raw, []byte(legacyGatewayItem)), "fixture <gateways> changed")
	require.Equal(t, 1, bytes.Count(raw, []byte(openSenseAnchor)), "fixture <OPNsense> changed")

	return raw
}

// withLegacy replaces the legacy gateway with item.
func (raw gatewayConfig) withLegacy(item string) []byte {
	return bytes.Replace(raw, []byte(legacyGatewayItem), []byte(item), 1)
}

// withModel writes the model block with the given version attribute and items.
// leftover replaces the legacy gateway; empty deletes it, as the migration does.
func (raw gatewayConfig) withModel(version, leftover string, items ...string) []byte {
	block := "    <Gateways" + version + ">\n" + strings.Join(items, "") + "    </Gateways>\n"
	if len(items) == 0 {
		block = "    <Gateways" + version + "/>\n"
	}

	cfg := bytes.Replace(raw, []byte(openSenseAnchor), []byte(openSenseAnchor+block), 1)

	return gatewayConfig(cfg).withLegacy(leftover)
}

// migratedWANGateway is legacyGatewayItem after the migration.
func migratedWANGateway(address string) string {
	return fmt.Sprintf(gatewayModelItemTemplate,
		gatewayUUIDFirst, "WAN_GW", "Interface WAN Gateway", "inet", address)
}

// namedModelGateway is a model gateway its name and address tell apart.
func namedModelGateway(uuid, name, address string) string {
	return fmt.Sprintf(gatewayModelItemTemplate, uuid, name, "Gateway "+name, "inet", address)
}

// emptyModelGateway is an item with a uuid and no child element.
func emptyModelGateway(uuid string) string {
	return `      <gateway_item uuid="` + uuid + `"/>` + "\n"
}

// setGatewayFlags rewrites the two flags of a gateway in either store.
func setGatewayFlags(defaultGW, monitorDisable string) *strings.Replacer {
	return strings.NewReplacer(
		gatewayDefaultElement, "<defaultgw>"+defaultGW+"</defaultgw>",
		gatewayMonitorDisableElement, "<monitor_disable>"+monitorDisable+"</monitor_disable>",
	)
}

func gatewayWarnings(warnings []common.ConversionWarning) []common.ConversionWarning {
	var result []common.ConversionWarning
	for _, w := range warnings {
		if strings.Contains(w.Field, "Gateways") {
			result = append(result, w)
		}
	}

	return result
}

func gatewayNames(gws []common.Gateway) []string {
	names := make([]string, 0, len(gws))
	for _, gw := range gws {
		names = append(names, gw.Name)
	}

	return names
}

// TestConverter_Gateways_ReadFromModel rewrites sample.config.4.xml the way
// OPNsense 24.1 migration M1_0_0 does: it moves the gateway into
// <OPNsense><Gateways> and deletes the <gateways><gateway_item>.
func TestConverter_Gateways_ReadFromModel(t *testing.T) {
	t.Parallel()

	raw := readGatewayConfig(t)
	want, _ := convertConfig(t, raw)
	require.Len(t, want.Routing.Gateways, 1)

	t.Run("migrated", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, "", migratedWANGateway("192.0.2.1")))
		assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("every model gateway in order", func(t *testing.T) {
		t.Parallel()

		v6 := fmt.Sprintf(gatewayModelItemTemplate,
			gatewayUUIDSecond, "WAN_GW6", "Interface WAN IPv6 Gateway", "inet6", "2001:db8::1")
		device, warnings := convertConfig(t,
			raw.withModel(gatewayVersionAttr, "", migratedWANGateway("192.0.2.1"), v6))
		require.Equal(t, []string{"WAN_GW", "WAN_GW6"}, gatewayNames(device.Routing.Gateways))
		assert.Equal(t, "2001:db8::1", device.Routing.Gateways[1].Address)
		assert.Equal(t, "inet6", device.Routing.Gateways[1].IPProtocol)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("every model gateway takes the address and monitor_disable readings", func(t *testing.T) {
		t.Parallel()

		// A static gateway ahead of two that omit both, so a reading that
		// stops early leaves the later ones wrong.
		omitted := strings.NewReplacer(gatewayMonitorDisableElement, "")
		static := setGatewayFlags("1", "0").Replace(namedModelGateway(gatewayUUIDFirst, "GW_STATIC", "192.0.2.1"))
		second := omitted.Replace(namedModelGateway(gatewayUUIDSecond, "GW_DYNAMIC_A", ""))
		third := omitted.Replace(namedModelGateway(gatewayUUIDThird, "GW_DYNAMIC_B", ""))

		device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, "", static, second, third))
		gws := device.Routing.Gateways
		require.Equal(t, []string{"GW_STATIC", "GW_DYNAMIC_A", "GW_DYNAMIC_B"}, gatewayNames(gws))
		assert.Equal(t, "192.0.2.1", gws[0].Address)
		assert.Empty(t, gws[0].MonitorDisable)

		for _, gw := range gws[1:] {
			assert.Equal(t, "dynamic", gw.Address, gw.Name)
			assert.Equal(t, "1", gw.MonitorDisable, gw.Name)
		}

		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("model wins over legacy gateways", func(t *testing.T) {
		t.Parallel()

		// Once one gateway is stored in the model, M1_0_0 deletes every legacy
		// one. Both remain when the migration dropped every gateway and one
		// was added in the model later, or after a hand edit, and the vendor
		// then ignores every legacy gateway, named or not.
		left := strings.Replace(legacyGatewayItem, "WAN_GW", "OLD_GW", 1)
		device, _ := convertConfig(t, raw.withModel(gatewayVersionAttr, left, migratedWANGateway("192.0.2.9")))
		require.Equal(t, []string{"WAN_GW"}, gatewayNames(device.Routing.Gateways))
		assert.Equal(t, "192.0.2.9", device.Routing.Gateways[0].Address)
	})

	t.Run("empty model falls back to the legacy element", func(t *testing.T) {
		t.Parallel()

		for _, version := range []string{gatewayVersionAttr, ` version="0.0.1"`, ""} {
			device, warnings := convertConfig(t, raw.withModel(version, legacyGatewayItem))
			assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways, version)
			assert.Empty(t, gatewayWarnings(warnings), version)
		}
	})

	t.Run("dynamic address", func(t *testing.T) {
		t.Parallel()

		// The migration rewrites a legacy "dynamic" address to empty.
		device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, "", migratedWANGateway("")))
		require.Len(t, device.Routing.Gateways, 1)
		assert.Equal(t, "dynamic", device.Routing.Gateways[0].Address)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("unrecognized model version", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, raw.withModel(` version="9.9.9"`, "", migratedWANGateway("192.0.2.1")))
		assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways)

		got := gatewayWarnings(warnings)
		require.Len(t, got, 1)
		assert.Equal(t, "OPNsense.Gateways.Version", got[0].Field)
		assert.Equal(t, "9.9.9", got[0].Value)
		assert.Equal(t, common.SeverityMedium, got[0].Severity)
	})

	t.Run("unrecognized model version with no gateway decoded", func(t *testing.T) {
		t.Parallel()

		// A version that renamed gateway_item would decode nothing, and the
		// migration has deleted the legacy element.
		renamed := strings.ReplaceAll(migratedWANGateway("192.0.2.1"), "gateway_item", "gw_entry")
		device, warnings := convertConfig(t, raw.withModel(` version="9.9.9"`, "", renamed))
		assert.Empty(t, device.Routing.Gateways)

		got := gatewayWarnings(warnings)
		require.Len(t, got, 1)
		assert.Equal(t, "OPNsense.Gateways.Version", got[0].Field)
		assert.Equal(t, "9.9.9", got[0].Value)
		assert.Equal(t, common.SeverityLow, got[0].Severity)
	})
}

// repeatedGatewayUUIDCase is a model and what is exported of it. wantReplaced
// names the items left out with a warning, all of them of gatewayUUIDFirst.
// wantCollided names the items that are kept with a warning, because through
// 25.1.12 the firewall holds a later item in their place, and collidedUUID is
// the uuid those warnings give.
type repeatedGatewayUUIDCase struct {
	name          string
	items         []string
	wantNames     []string
	wantAddresses []string
	wantReplaced  []string
	wantCollided  []string
	collidedUUID  string
}

// Names of the gateways in the repeated uuid cases.
const (
	gatewayEarlier = "GW_EARLIER"
	gatewayMiddle  = "GW_MIDDLE"
	gatewayLater   = "GW_LATER"
)

// repeatedGatewayUUIDCases covers a uuid that is a key on every release.
func repeatedGatewayUUIDCases() []repeatedGatewayUUIDCase {
	return []repeatedGatewayUUIDCase{
		{
			name: "a later item takes the place of the earlier one",
			items: []string{
				namedModelGateway(gatewayUUIDFirst, gatewayEarlier, "192.0.2.1"),
				namedModelGateway(gatewayUUIDSecond, gatewayMiddle, "192.0.2.2"),
				namedModelGateway(gatewayUUIDFirst, gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayLater, gatewayMiddle},
			wantAddresses: []string{"192.0.2.3", "192.0.2.2"},
			wantReplaced:  []string{gatewayEarlier},
		},
		{
			name: "the replaced item need not be the first",
			items: []string{
				namedModelGateway(gatewayUUIDSecond, gatewayMiddle, "192.0.2.2"),
				namedModelGateway(gatewayUUIDFirst, gatewayEarlier, "192.0.2.1"),
				namedModelGateway(gatewayUUIDFirst, gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayMiddle, gatewayLater},
			wantAddresses: []string{"192.0.2.2", "192.0.2.3"},
			wantReplaced:  []string{gatewayEarlier},
		},
		{
			name: "only the last of three is kept",
			items: []string{
				namedModelGateway(gatewayUUIDFirst, gatewayEarlier, "192.0.2.1"),
				namedModelGateway(gatewayUUIDFirst, gatewayMiddle, "192.0.2.2"),
				namedModelGateway(gatewayUUIDFirst, gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayLater},
			wantAddresses: []string{"192.0.2.3"},
			wantReplaced:  []string{gatewayEarlier, gatewayMiddle},
		},
		{
			name: "a uuid differing in case is another uuid",
			items: []string{
				namedModelGateway(gatewayUUIDFirst, gatewayEarlier, "192.0.2.1"),
				namedModelGateway(strings.ToUpper(gatewayUUIDFirst), gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayEarlier, gatewayLater},
			wantAddresses: []string{"192.0.2.1", "192.0.2.3"},
		},
		{
			name: "an empty item replaces nothing",
			items: []string{
				namedModelGateway(gatewayUUIDFirst, gatewayEarlier, "192.0.2.1"),
				emptyModelGateway(gatewayUUIDFirst),
			},
			wantNames:     []string{gatewayEarlier},
			wantAddresses: []string{"192.0.2.1"},
		},
		{
			name: "an empty item is not replaced",
			items: []string{
				emptyModelGateway(gatewayUUIDFirst),
				namedModelGateway(gatewayUUIDFirst, gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayLater},
			wantAddresses: []string{"192.0.2.3"},
		},
	}
}

// emptyGatewayUUIDCases covers a uuid attribute that is absent, empty or 0, which
// OPNsense does not read as a key on every release.
func emptyGatewayUUIDCases() []repeatedGatewayUUIDCase {
	const noUUID = ` uuid=""`

	return []repeatedGatewayUUIDCase{
		{
			name: "items with no uuid are each given one",
			items: []string{
				strings.Replace(namedModelGateway("", gatewayEarlier, "192.0.2.1"), noUUID, "", 1),
				strings.Replace(namedModelGateway("", gatewayLater, "192.0.2.3"), noUUID, "", 1),
			},
			wantNames:     []string{gatewayEarlier, gatewayLater},
			wantAddresses: []string{"192.0.2.1", "192.0.2.3"},
		},
		{
			name: "an empty uuid repeated is fresh from 25.7 and collides through 25.1.12",
			items: []string{
				namedModelGateway("", gatewayEarlier, "192.0.2.1"),
				namedModelGateway("", gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayEarlier, gatewayLater},
			wantAddresses: []string{"192.0.2.1", "192.0.2.3"},
			wantCollided:  []string{gatewayEarlier},
		},
		{
			name: "a uuid of 0 repeated is fresh from 25.7 and collides through 25.1.12",
			items: []string{
				namedModelGateway("0", gatewayEarlier, "192.0.2.1"),
				namedModelGateway("0", gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayEarlier, gatewayLater},
			wantAddresses: []string{"192.0.2.1", "192.0.2.3"},
			wantCollided:  []string{gatewayEarlier},
			collidedUUID:  "0",
		},
		{
			name: "each collision names the item a later one would replace",
			items: []string{
				namedModelGateway(gatewayUUIDSecond, "GW_OTHER", "192.0.2.4"),
				namedModelGateway("0", gatewayEarlier, "192.0.2.1"),
				namedModelGateway("0", gatewayMiddle, "192.0.2.2"),
				namedModelGateway("0", gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{"GW_OTHER", gatewayEarlier, gatewayMiddle, gatewayLater},
			wantAddresses: []string{"192.0.2.4", "192.0.2.1", "192.0.2.2", "192.0.2.3"},
			wantCollided:  []string{gatewayEarlier, gatewayMiddle},
			collidedUUID:  "0",
		},
		{
			name: "an empty uuid and a uuid of 0 are different keys on every release",
			items: []string{
				namedModelGateway("", gatewayEarlier, "192.0.2.1"),
				namedModelGateway("0", gatewayLater, "192.0.2.3"),
			},
			wantNames:     []string{gatewayEarlier, gatewayLater},
			wantAddresses: []string{"192.0.2.1", "192.0.2.3"},
		},
		{
			name: "an item with no uuid does not collide with an empty one",
			items: []string{
				strings.Replace(namedModelGateway("", gatewayEarlier, "192.0.2.1"), noUUID, "", 1),
				namedModelGateway("", gatewayMiddle, "192.0.2.2"),
				strings.Replace(namedModelGateway("", gatewayLater, "192.0.2.3"), noUUID, "", 1),
			},
			wantNames:     []string{gatewayEarlier, gatewayMiddle, gatewayLater},
			wantAddresses: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		},
		{
			name: "an empty item does not collide with a uuid of 0",
			items: []string{
				emptyModelGateway("0"),
				namedModelGateway("0", gatewayLater, "192.0.2.3"),
				emptyModelGateway("0"),
			},
			wantNames:     []string{gatewayLater},
			wantAddresses: []string{"192.0.2.3"},
		},
	}
}

// assertGatewayUUIDWarning checks one warning of TestConverter_Gateways_RepeatedUUID.
func assertGatewayUUIDWarning(t *testing.T, got common.ConversionWarning, uuid, name, wantText string) {
	t.Helper()

	assert.Equal(t, "OPNsense.Gateways.Items", got.Field)
	assert.Equal(t, uuid, got.Value)
	assert.Equal(t, common.SeverityMedium, got.Severity)
	assert.Contains(t, got.Message, wantText)
	assert.Contains(t, got.Message, fmt.Sprintf("name %q", name))
	assert.Contains(t, got.Message, fmt.Sprintf("description %q", "Gateway "+name))
}

// TestConverter_Gateways_RepeatedUUID covers model items that share a uuid. The
// model keeps its items by uuid, so the firewall holds the later item at the
// place of the earlier one. An empty uuid or 0 is the exception: only through
// 25.1.12 is it a key, and the model version does not say which applies, so both
// items are exported with a warning. Only a hand edit or a generator writes this.
func TestConverter_Gateways_RepeatedUUID(t *testing.T) {
	t.Parallel()

	const (
		replacedText = "so it is left out"
		collidedText = "through 25.1.12 it replaces this one on the firewall, from 25.7 both load"
	)

	raw := readGatewayConfig(t)

	for _, tt := range slices.Concat(repeatedGatewayUUIDCases(), emptyGatewayUUIDCases()) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, "", tt.items...))
			require.Equal(t, tt.wantNames, gatewayNames(device.Routing.Gateways))

			for i, want := range tt.wantAddresses {
				assert.Equal(t, want, device.Routing.Gateways[i].Address)
			}

			got := gatewayWarnings(warnings)
			require.Len(t, got, len(tt.wantReplaced)+len(tt.wantCollided))

			for i, name := range tt.wantReplaced {
				assertGatewayUUIDWarning(t, got[i], gatewayUUIDFirst, name, replacedText)
			}

			for i, name := range tt.wantCollided {
				assertGatewayUUIDWarning(t, got[len(tt.wantReplaced)+i], tt.collidedUUID, name, collidedText)
			}
		})
	}

	t.Run("the legacy store does not read a uuid", func(t *testing.T) {
		t.Parallel()

		// gatewayIterator writes an empty uuid into every legacy record.
		tagged := strings.Replace(legacyGatewayItem, "<gateway_item>", `<gateway_item uuid="`+gatewayUUIDFirst+`">`, 1)
		other := strings.Replace(tagged, "WAN_GW", "OTHER_GW", 1)

		device, warnings := convertConfig(t, raw.withLegacy(tagged+other))
		assert.Equal(t, []string{"WAN_GW", "OTHER_GW"}, gatewayNames(device.Routing.Gateways))
		assert.Empty(t, gatewayWarnings(warnings))
	})
}

// TestConverter_Gateways_Flags covers the two gateway flags the common model
// keeps as text, which the stores spell differently.
func TestConverter_Gateways_Flags(t *testing.T) {
	t.Parallel()

	raw := readGatewayConfig(t)

	t.Run("migrated with flags unset", func(t *testing.T) {
		t.Parallel()

		// The 23.7 page left both elements out of a gateway with neither box
		// ticked, and M1_0_0 writes both as 0.
		before := strings.NewReplacer(gatewayDefaultElement, "", gatewayMonitorDisableElement, "").
			Replace(legacyGatewayItem)
		after := setGatewayFlags("0", "0").Replace(migratedWANGateway("192.0.2.1"))
		require.NotContains(t, before, "defaultgw")
		require.NotContains(t, before, "monitor_disable")
		require.Contains(t, after, "<defaultgw>0</defaultgw>")
		require.Contains(t, after, "<monitor_disable>0</monitor_disable>")

		pre, _ := convertConfig(t, raw.withLegacy(before))
		post, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, "", after))
		require.Len(t, pre.Routing.Gateways, 1)
		assert.Equal(t, pre.Routing.Gateways, post.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("a monitored default gateway keeps the flags apart", func(t *testing.T) {
		t.Parallel()

		flags := setGatewayFlags("1", "0")
		modelCfg := raw.withModel(gatewayVersionAttr, "", flags.Replace(migratedWANGateway("192.0.2.1")))
		legacyCfg := raw.withLegacy(flags.Replace(legacyGatewayItem))

		for _, cfg := range [][]byte{modelCfg, legacyCfg} {
			device, _ := convertConfig(t, cfg)
			require.Len(t, device.Routing.Gateways, 1)
			assert.Equal(t, "1", device.Routing.Gateways[0].DefaultGW)
			assert.Empty(t, device.Routing.Gateways[0].MonitorDisable)
		}
	})

	t.Run("either store reads a flag as the firewall does", func(t *testing.T) {
		t.Parallel()

		// From 24.1 the firewall reads a flag as set unless it is empty or 0,
		// so text no page writes, such as no, reads as set.
		for value, flag := range map[string]string{"0": "", "": "", "1": "1", "yes": "1", "no": "1"} {
			flags := setGatewayFlags(value, value)
			modelCfg := raw.withModel(gatewayVersionAttr, "", flags.Replace(migratedWANGateway("192.0.2.1")))
			legacyCfg := raw.withLegacy(flags.Replace(legacyGatewayItem))

			for _, cfg := range [][]byte{modelCfg, legacyCfg} {
				device, _ := convertConfig(t, cfg)
				require.Len(t, device.Routing.Gateways, 1, value)
				assert.Equal(t, flag, device.Routing.Gateways[0].DefaultGW, value)
				assert.Equal(t, flag, device.Routing.Gateways[0].MonitorDisable, value)
			}
		}
	})

	t.Run("either store reads fargw as the firewall does", func(t *testing.T) {
		t.Parallel()

		// From 24.1.8 the firewall tests !empty(). Up to 24.1.7 it tested
		// isset(), which also reads text no page writes as set.
		tests := []struct {
			name    string
			element string
			want    bool
		}{
			{name: "absent"},
			{name: "self-closing", element: "<fargw/>"},
			{name: "empty", element: "<fargw></fargw>"},
			{name: "zero", element: gatewayFarElement},
			{name: "one", element: "<fargw>1</fargw>", want: true},
			{name: "yes", element: "<fargw>yes</fargw>", want: true},
			{name: "no", element: "<fargw>no</fargw>", want: true},
		}

		for _, tt := range tests {
			modelCfg := raw.withModel(gatewayVersionAttr, "",
				strings.Replace(migratedWANGateway("192.0.2.1"), gatewayFarElement, tt.element, 1))
			legacyCfg := raw.withLegacy(strings.Replace(legacyGatewayItem, gatewayFarElement, tt.element, 1))

			for _, cfg := range [][]byte{modelCfg, legacyCfg} {
				device, _ := convertConfig(t, cfg)
				require.Len(t, device.Routing.Gateways, 1, tt.name)
				assert.Equal(t, tt.want, device.Routing.Gateways[0].FarGW, tt.name)
			}
		}
	})

	t.Run("an absent monitor_disable takes the default of its store", func(t *testing.T) {
		t.Parallel()

		// The model defaults the flag to 1, which is not what an empty element
		// reads as, and the vendor fills in 0 for a legacy gateway.
		modelItem := strings.Replace(migratedWANGateway("192.0.2.1"), gatewayMonitorDisableElement, "", 1)
		legacyItem := strings.Replace(legacyGatewayItem, gatewayMonitorDisableElement, "", 1)
		require.NotContains(t, modelItem, "monitor_disable")
		require.NotContains(t, legacyItem, "monitor_disable")

		device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, "", modelItem))
		require.Len(t, device.Routing.Gateways, 1)
		assert.Equal(t, "1", device.Routing.Gateways[0].MonitorDisable)
		assert.Empty(t, gatewayWarnings(warnings))

		device, _ = convertConfig(t, raw.withLegacy(legacyItem))
		require.Len(t, device.Routing.Gateways, 1)
		assert.Empty(t, device.Routing.Gateways[0].MonitorDisable)
	})
}

// TestConverter_Gateways_EmptyItems covers the <gateway_item> with no child
// element, which OPNsense skips in both stores. It is not a gateway, so it must
// not decide which store is read: the real gateway would be lost to a phantom.
func TestConverter_Gateways_EmptyItems(t *testing.T) {
	t.Parallel()

	const empty = "      <gateway_item/>\n"

	emptyWithUUID := emptyModelGateway(gatewayUUIDThird)
	raw := readGatewayConfig(t)
	want, _ := convertConfig(t, raw)
	require.Len(t, want.Routing.Gateways, 1)

	t.Run("a model holding nothing else falls back to the legacy gateway", func(t *testing.T) {
		t.Parallel()

		// Text and comments are not child elements, so these are empty too.
		noChild := []string{
			`      <gateway_item uuid="` + gatewayUUIDThird + `">` + "\n      </gateway_item>\n",
			`      <gateway_item uuid="` + gatewayUUIDThird + `"><!-- <name>GW</name> --></gateway_item>` + "\n",
		}

		for _, item := range append([]string{empty, emptyWithUUID}, noChild...) {
			device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, legacyGatewayItem, item))
			assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways, item)
			assert.Empty(t, gatewayWarnings(warnings), item)
		}
	})

	t.Run("beside a model gateway", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t,
			raw.withModel(gatewayVersionAttr, "", empty, migratedWANGateway("192.0.2.1"), emptyWithUUID))
		assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("alone in the legacy element", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, raw.withLegacy(empty))
		assert.Empty(t, device.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("beside a legacy gateway", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, raw.withLegacy(empty+legacyGatewayItem))
		assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("in both stores", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, empty, emptyWithUUID))
		assert.Empty(t, device.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("an unrecognized model version counts no gateway", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, raw.withModel(` version="9.9.9"`, legacyGatewayItem, empty))
		assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways)

		got := gatewayWarnings(warnings)
		require.Len(t, got, 1)
		assert.Equal(t, "9.9.9", got[0].Value)
		assert.Equal(t, common.SeverityLow, got[0].Severity)
	})
}

// TestConverter_Gateways_ChildrenThatDecodeToZero covers an item whose only
// child decodes to the zero value, or is an element the schema does not bind.
// OPNsense loads it in both stores, because it has a child element, so the
// converter keeps it. In the model it then decides the store: the firewall
// reads the model and not the leftover legacy gateway. The item has no name,
// so it draws the converter's empty-name warning, and in the legacy store,
// where no address is filled in, the empty-address one too.
func TestConverter_Gateways_ChildrenThatDecodeToZero(t *testing.T) {
	t.Parallel()

	raw := readGatewayConfig(t)
	children := []string{
		"<name/>",
		"<descr></descr>",
		"<priority>255</priority>",
		"<monitor_noroute/>",
	}

	t.Run("model store", func(t *testing.T) {
		t.Parallel()

		for _, child := range children {
			item := `      <gateway_item uuid="` + gatewayUUIDThird + `">` + child + "</gateway_item>\n"
			device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, legacyGatewayItem, item))
			require.Len(t, device.Routing.Gateways, 1, child)

			gw := device.Routing.Gateways[0]
			assert.Empty(t, gw.Name, child)
			assert.Equal(t, "dynamic", gw.Address, child)
			assert.Equal(t, "wan", gw.Interface, child)
			assert.Equal(t, "1", gw.MonitorDisable, child)

			got := gatewayWarnings(warnings)
			require.Len(t, got, 1, child)
			assert.Equal(t, "gateway has empty name", got[0].Message, child)
			assert.Equal(t, "wan", got[0].Value, child)
		}
	})

	t.Run("legacy store", func(t *testing.T) {
		t.Parallel()

		for _, child := range slices.Concat(children, []string{"<disabled>0</disabled>"}) {
			item := "    <gateway_item>" + child + "</gateway_item>\n"

			device, warnings := convertConfig(t, raw.withLegacy(item))
			require.Len(t, device.Routing.Gateways, 1, child)
			assert.Empty(t, device.Routing.Gateways[0].Interface, child)

			got := gatewayWarnings(warnings)
			require.Len(t, got, 2, child)
			assert.Equal(t, "gateway has empty address", got[0].Message, child)
			assert.Equal(t, "gateway has empty name", got[1].Message, child)

			device, _ = convertConfig(t, raw.withLegacy(item+legacyGatewayItem))
			assert.Equal(t, []string{"", "WAN_GW"}, gatewayNames(device.Routing.Gateways), child)
		}
	})
}

// TestConverter_Gateways_Disabled covers <disabled> in both stores. In the model
// the firewall reads it with !empty(), and it makes an item a gateway whatever
// its text: OPNsense loads any item with a child element, and then reads the
// model and not <gateways>. Under <gateways> it is the BoolFlag of the type
// pfSense shares, which reads <disabled/> and <disabled>no</disabled> the
// reverse of the firewall (GOTCHAS 3.7); the legacy page writes only 1 or leaves
// the element out.
func TestConverter_Gateways_Disabled(t *testing.T) {
	t.Parallel()

	const migratedDisabled = "<disabled>0</disabled>"

	raw := readGatewayConfig(t)

	tests := []struct {
		name       string
		element    string
		want       bool
		wantLegacy bool
	}{
		{name: "absent"},
		{name: "self-closing", element: "<disabled/>", wantLegacy: true},
		{name: "zero", element: migratedDisabled},
		{name: "one", element: "<disabled>1</disabled>", want: true, wantLegacy: true},
		{name: "no", element: "<disabled>no</disabled>", want: true},
	}

	t.Run("an item holding only the element is read from the model", func(t *testing.T) {
		t.Parallel()

		for _, tt := range tests[1:] {
			item := `      <gateway_item uuid="` + gatewayUUIDThird + `">` + tt.element + "</gateway_item>\n"
			device, warnings := convertConfig(t, raw.withModel(gatewayVersionAttr, legacyGatewayItem, item))
			require.Len(t, device.Routing.Gateways, 1, tt.name)

			gw := device.Routing.Gateways[0]
			assert.Empty(t, gw.Name, tt.name)
			assert.Equal(t, "dynamic", gw.Address, tt.name)
			assert.Equal(t, tt.want, gw.Disabled, tt.name)

			got := gatewayWarnings(warnings)
			require.Len(t, got, 1, tt.name)
			assert.Equal(t, "gateway has empty name", got[0].Message, tt.name)
		}
	})

	t.Run("a migrated gateway reads the element as the firewall does", func(t *testing.T) {
		t.Parallel()

		require.Contains(t, migratedWANGateway("192.0.2.1"), migratedDisabled)

		for _, tt := range tests {
			item := strings.Replace(migratedWANGateway("192.0.2.1"), migratedDisabled, tt.element, 1)
			device, _ := convertConfig(t, raw.withModel(gatewayVersionAttr, "", item))
			require.Len(t, device.Routing.Gateways, 1, tt.name)
			assert.Equal(t, "WAN_GW", device.Routing.Gateways[0].Name, tt.name)
			assert.Equal(t, tt.want, device.Routing.Gateways[0].Disabled, tt.name)
		}
	})

	t.Run("a legacy gateway reads the element as a BoolFlag", func(t *testing.T) {
		t.Parallel()

		const name = "      <name>WAN_GW</name>\n"

		require.Contains(t, legacyGatewayItem, name)

		for _, tt := range tests {
			item := strings.Replace(legacyGatewayItem, name, "      "+tt.element+"\n"+name, 1)
			device, _ := convertConfig(t, raw.withLegacy(item))
			require.Len(t, device.Routing.Gateways, 1, tt.name)
			assert.Equal(t, "WAN_GW", device.Routing.Gateways[0].Name, tt.name)
			assert.Equal(t, tt.wantLegacy, device.Routing.Gateways[0].Disabled, tt.name)
		}
	})
}

// TestConverter_Gateways_ReducedItemTakesTheDefaults drives a gateway that
// leaves <ipprotocol> and <weight> out, or writes them empty, through parse and
// convert in both stores. The firewall reads inet and 1 for each but one: the
// model defaults both (Routing/Gateways.xml), OPNsense fills in inet for a
// legacy gateway, and the gateway groups read an empty weight as 1. The
// exception is the empty <ipprotocol/> in the model, which the firewall keeps
// empty; that row pins the converter's reading, since the schema cannot tell it
// from an absent element, and OPNsense never writes one (GOTCHAS 3.7).
func TestConverter_Gateways_ReducedItemTakesTheDefaults(t *testing.T) {
	t.Parallel()

	raw := readGatewayConfig(t)
	item := namedModelGateway(gatewayUUIDFirst, "GW_REDUCED", "192.0.2.1")

	omitModel := strings.NewReplacer(
		"        <ipprotocol>inet</ipprotocol>\n", "",
		"        <weight>1</weight>\n", "",
	)
	omitLegacy := strings.NewReplacer(
		"      <ipprotocol>inet</ipprotocol>\n", "",
		"      <weight>1</weight>\n", "",
	)
	empty := strings.NewReplacer(
		"<ipprotocol>inet</ipprotocol>", "<ipprotocol/>",
		"<weight>1</weight>", "<weight/>",
	)

	// A replacer that matches nothing would leave both elements in place and
	// the test would pass on the unfixed converter.
	for _, shape := range []string{
		omitModel.Replace(item), empty.Replace(item),
		omitLegacy.Replace(legacyGatewayItem), empty.Replace(legacyGatewayItem),
	} {
		require.NotContains(t, shape, "<ipprotocol>inet</ipprotocol>")
		require.NotContains(t, shape, "<weight>1</weight>")
	}

	tests := []struct {
		name string
		cfg  []byte
	}{
		{"model item omits both", raw.withModel(gatewayVersionAttr, "", omitModel.Replace(item))},
		{"model item empties both", raw.withModel(gatewayVersionAttr, "", empty.Replace(item))},
		{"legacy item omits both", raw.withLegacy(omitLegacy.Replace(legacyGatewayItem))},
		{"legacy item empties both", raw.withLegacy(empty.Replace(legacyGatewayItem))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, warnings := convertConfig(t, tc.cfg)
			require.Len(t, device.Routing.Gateways, 1)
			assert.Equal(t, "inet", device.Routing.Gateways[0].IPProtocol)
			assert.Equal(t, "1", device.Routing.Gateways[0].Weight)
			assert.Empty(t, gatewayWarnings(warnings))
		})
	}

	t.Run("a set value is kept", func(t *testing.T) {
		t.Parallel()

		set := strings.NewReplacer(
			"<ipprotocol>inet</ipprotocol>", "<ipprotocol>inet6</ipprotocol>",
			"<weight>1</weight>", "<weight>3</weight>",
		)
		device, _ := convertConfig(t, raw.withModel(gatewayVersionAttr, "", set.Replace(item)))
		require.Len(t, device.Routing.Gateways, 1)
		assert.Equal(t, "inet6", device.Routing.Gateways[0].IPProtocol)
		assert.Equal(t, "3", device.Routing.Gateways[0].Weight)
	})
}

// TestConverter_Gateways_InterfaceDefault drives a gateway that leaves
// <interface> out, or writes it empty, through parse and convert in both
// stores. The model defaults an absent interface to wan (Routing/Gateways.xml),
// and gatewayIterator fills in none for a legacy gateway. The empty
// <interface/> in the model stays empty on the firewall; that row pins the
// converter's reading, since the schema cannot tell it from an absent element,
// and OPNsense never writes one, as the field is required (GOTCHAS 3.7).
func TestConverter_Gateways_InterfaceDefault(t *testing.T) {
	t.Parallel()

	const (
		modelInterface  = "        <interface>wan</interface>\n"
		legacyInterface = "      <interface>wan</interface>\n"
		wanElement      = "<interface>wan</interface>"
	)

	raw := readGatewayConfig(t)
	item := namedModelGateway(gatewayUUIDFirst, "GW_REDUCED", "192.0.2.1")

	tests := []struct {
		name  string
		shape string
		cfg   func(string) []byte
		want  string
	}{
		{
			name:  "model item omits it",
			shape: strings.Replace(item, modelInterface, "", 1),
			cfg:   func(s string) []byte { return raw.withModel(gatewayVersionAttr, "", s) },
			want:  "wan",
		},
		{
			name:  "model item empties it",
			shape: strings.Replace(item, wanElement, "<interface/>", 1),
			cfg:   func(s string) []byte { return raw.withModel(gatewayVersionAttr, "", s) },
			want:  "wan",
		},
		{
			name:  "model item sets it",
			shape: strings.Replace(item, wanElement, "<interface>opt1</interface>", 1),
			cfg:   func(s string) []byte { return raw.withModel(gatewayVersionAttr, "", s) },
			want:  "opt1",
		},
		{
			name:  "legacy item omits it",
			shape: strings.Replace(legacyGatewayItem, legacyInterface, "", 1),
			cfg:   raw.withLegacy,
		},
		{
			name:  "legacy item empties it",
			shape: strings.Replace(legacyGatewayItem, wanElement, "<interface/>", 1),
			cfg:   raw.withLegacy,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A replacement that matched nothing would leave wan in place and
			// the test would pass on a converter without the default.
			require.NotContains(t, tc.shape, wanElement)

			device, warnings := convertConfig(t, tc.cfg(tc.shape))
			require.Len(t, device.Routing.Gateways, 1)
			assert.Equal(t, tc.want, device.Routing.Gateways[0].Interface)
			assert.Empty(t, gatewayWarnings(warnings))
		})
	}
}

// TestConvertDocument_GatewaysLeaveTheDocumentUnchanged pins that neither store
// is filtered or rewritten in place: ConvertDocument takes a document the
// caller owns. The empty item comes first because slices.DeleteFunc writes
// nothing into a slice it deletes nothing from. Each store is built twice, so
// the expected value shares no pointer with the document: a copy made with
// slices.Clone would share them, and a write through UUID, MonitorDisable or a
// model item's Disabled would change both sides alike.
func TestConvertDocument_GatewaysLeaveTheDocumentUnchanged(t *testing.T) {
	t.Parallel()

	// gateways returns a gateway with no address and no monitor_disable, which
	// the converter fills in for a model item, and one whose monitor_disable is
	// 0, which it exports as empty. Every call allocates new pointers.
	gateways := func() []schema.Gateway {
		return []schema.Gateway{
			{Name: "WAN_GW", Interface: "wan"},
			{Name: "LAN_GW", Interface: "lan", Gateway: "192.0.2.1", MonitorDisable: new("0")},
		}
	}

	t.Run("model store", func(t *testing.T) {
		t.Parallel()

		items := func() []schema.GatewayModelItem {
			gws := gateways()

			return []schema.GatewayModelItem{
				{},
				{Gateway: gws[0], UUID: new(gatewayUUIDFirst)},
				{Gateway: gws[1], UUID: new(gatewayUUIDSecond), Disabled: new("0")},
			}
		}

		doc := &schema.OpnSenseDocument{}
		doc.OPNsense.Gateways.Version = "1.0.0"
		doc.OPNsense.Gateways.Items = items()

		device, _, err := opnsense.ConvertDocument(doc)
		require.NoError(t, err)
		require.Len(t, device.Routing.Gateways, 2)
		assert.Equal(t, "dynamic", device.Routing.Gateways[0].Address)
		assert.Equal(t, "1", device.Routing.Gateways[0].MonitorDisable)
		assert.Empty(t, device.Routing.Gateways[1].MonitorDisable)
		assert.Equal(t, items(), doc.OPNsense.Gateways.Items)
	})

	t.Run("legacy store", func(t *testing.T) {
		t.Parallel()

		legacy := func() []schema.Gateway {
			return append([]schema.Gateway{{}}, gateways()...)
		}

		doc := &schema.OpnSenseDocument{}
		doc.Gateways.Gateway = legacy()

		device, _, err := opnsense.ConvertDocument(doc)
		require.NoError(t, err)
		require.Len(t, device.Routing.Gateways, 2)
		assert.Empty(t, device.Routing.Gateways[1].MonitorDisable)
		assert.Equal(t, legacy(), doc.Gateways.Gateway)
	})
}
