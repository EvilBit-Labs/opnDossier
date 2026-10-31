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

// TestConverter_Gateways_EmptyItems covers the empty <gateway_item/> OPNsense
// skips in both stores. It is not a gateway, so it must not decide which store
// is read: the real gateway would be lost to a phantom.
func TestConverter_Gateways_EmptyItems(t *testing.T) {
	t.Parallel()

	const empty = "      <gateway_item/>\n"

	emptyWithUUID := emptyModelGateway(gatewayUUIDThird)
	raw := readGatewayConfig(t)
	want, _ := convertConfig(t, raw)
	require.Len(t, want.Routing.Gateways, 1)

	t.Run("a model holding nothing else falls back to the legacy gateway", func(t *testing.T) {
		t.Parallel()

		for _, item := range []string{empty, emptyWithUUID} {
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

// TestConvertDocument_GatewaysLeaveTheDocumentUnchanged pins that neither store
// is filtered or rewritten in place: ConvertDocument takes a document the
// caller owns. The empty item comes first because slices.DeleteFunc writes
// nothing into a slice it deletes nothing from.
func TestConvertDocument_GatewaysLeaveTheDocumentUnchanged(t *testing.T) {
	t.Parallel()

	gateway := schema.Gateway{Name: "WAN_GW", Interface: "wan"}

	t.Run("model store", func(t *testing.T) {
		t.Parallel()

		doc := &schema.OpnSenseDocument{}
		doc.OPNsense.Gateways.Version = "1.0.0"
		doc.OPNsense.Gateways.Items = []schema.GatewayModelItem{{}, {Gateway: gateway}}
		before := slices.Clone(doc.OPNsense.Gateways.Items)

		device, _, err := opnsense.ConvertDocument(doc)
		require.NoError(t, err)
		require.Len(t, device.Routing.Gateways, 1)
		assert.Equal(t, "dynamic", device.Routing.Gateways[0].Address)
		assert.Equal(t, "1", device.Routing.Gateways[0].MonitorDisable)
		assert.Equal(t, before, doc.OPNsense.Gateways.Items)
	})

	t.Run("legacy store", func(t *testing.T) {
		t.Parallel()

		doc := &schema.OpnSenseDocument{}
		doc.Gateways.Gateway = []schema.Gateway{{}, gateway}
		before := slices.Clone(doc.Gateways.Gateway)

		device, _, err := opnsense.ConvertDocument(doc)
		require.NoError(t, err)
		require.Len(t, device.Routing.Gateways, 1)
		assert.Equal(t, before, doc.Gateways.Gateway)
	})
}
