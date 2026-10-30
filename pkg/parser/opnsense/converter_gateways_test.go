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
	gatewayMonitorDisableElement = "<monitor_disable>1</monitor_disable>"
)

// gatewayVersionAttr is the version attribute of the model OPNsense writes.
const gatewayVersionAttr = ` version="1.0.0"`

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
		"7f3c2a1e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", "WAN_GW", "Interface WAN Gateway", "inet", address)
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
			"0b8e4d2c-1a3f-4c5e-8d7b-6a9f0e1d2c3b", "WAN_GW6", "Interface WAN IPv6 Gateway", "inet6", "2001:db8::1")
		device, warnings := convertConfig(t,
			raw.withModel(gatewayVersionAttr, "", migratedWANGateway("192.0.2.1"), v6))
		require.Equal(t, []string{"WAN_GW", "WAN_GW6"}, gatewayNames(device.Routing.Gateways))
		assert.Equal(t, "2001:db8::1", device.Routing.Gateways[1].Address)
		assert.Equal(t, "inet6", device.Routing.Gateways[1].IPProtocol)
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
		assert.Equal(t, common.SeverityLow, got[0].Severity)
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

	const (
		empty         = "      <gateway_item/>\n"
		emptyWithUUID = `      <gateway_item uuid="3c9d1f7a-2e4b-4a6c-8b1d-5f0e7a9c2d4e"/>` + "\n"
	)

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
		assert.Equal(t, common.SeverityLow, got[0].Severity)
	})
}

// TestConvertDocument_ModelGatewaysLeaveTheDocumentUnchanged pins that the
// model gateways are rewritten in a copy: ConvertDocument takes a document the
// caller owns.
func TestConvertDocument_ModelGatewaysLeaveTheDocumentUnchanged(t *testing.T) {
	t.Parallel()

	doc := &schema.OpnSenseDocument{}
	doc.OPNsense.Gateways.Version = "1.0.0"
	doc.OPNsense.Gateways.Items = []schema.Gateway{{Name: "WAN_GW", Interface: "wan"}}
	before := slices.Clone(doc.OPNsense.Gateways.Items)

	device, _, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)
	require.Len(t, device.Routing.Gateways, 1)
	assert.Equal(t, "dynamic", device.Routing.Gateways[0].Address)
	assert.Equal(t, "1", device.Routing.Gateways[0].MonitorDisable)
	assert.Equal(t, before, doc.OPNsense.Gateways.Items)
}
