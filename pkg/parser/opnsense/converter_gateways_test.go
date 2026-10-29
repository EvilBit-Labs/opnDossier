package opnsense_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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

// migratedWANGateway is legacyGatewayItem after the migration.
func migratedWANGateway(address string) string {
	return fmt.Sprintf(gatewayModelItemTemplate,
		"7f3c2a1e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", "WAN_GW", "Interface WAN Gateway", "inet", address)
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

	raw := readFixture(t, "sample.config.4.xml")
	legacy := []byte(legacyGatewayItem)
	anchor := []byte("  <OPNsense>\n")
	require.Equal(t, 1, bytes.Count(raw, legacy), "fixture <gateways> changed")
	require.Equal(t, 1, bytes.Count(raw, anchor), "fixture <OPNsense> changed")

	want, _ := convertConfig(t, raw)
	require.Len(t, want.Routing.Gateways, 1)

	// withModel writes the model block with the given version attribute and
	// items. leftover replaces the legacy gateway; nil deletes it, as the
	// migration does.
	withModel := func(version string, leftover []byte, items ...string) []byte {
		block := "    <Gateways" + version + ">\n" + strings.Join(items, "") + "    </Gateways>\n"
		if len(items) == 0 {
			block = "    <Gateways" + version + "/>\n"
		}

		cfg := bytes.Replace(raw, anchor, append(bytes.Clone(anchor), block...), 1)

		return bytes.Replace(cfg, legacy, leftover, 1)
	}

	t.Run("migrated", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, withModel(` version="1.0.0"`, nil, migratedWANGateway("192.0.2.1")))
		assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("every model gateway in order", func(t *testing.T) {
		t.Parallel()

		v6 := fmt.Sprintf(gatewayModelItemTemplate,
			"0b8e4d2c-1a3f-4c5e-8d7b-6a9f0e1d2c3b", "WAN_GW6", "Interface WAN IPv6 Gateway", "inet6", "2001:db8::1")
		device, warnings := convertConfig(t,
			withModel(` version="1.0.0"`, nil, migratedWANGateway("192.0.2.1"), v6))
		assert.Equal(t, []string{"WAN_GW", "WAN_GW6"}, gatewayNames(device.Routing.Gateways))
		assert.Equal(t, "2001:db8::1", device.Routing.Gateways[1].Address)
		assert.Equal(t, "inet6", device.Routing.Gateways[1].IPProtocol)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("model replaces legacy gateways left behind", func(t *testing.T) {
		t.Parallel()

		// M1_0_0 drops a gateway that fails validation from the model, and
		// the vendor then ignores every legacy gateway, named or not.
		left := bytes.Replace(legacy, []byte("WAN_GW"), []byte("OLD_GW"), 1)
		device, _ := convertConfig(t, withModel(` version="1.0.0"`, left, migratedWANGateway("192.0.2.9")))
		assert.Equal(t, []string{"WAN_GW"}, gatewayNames(device.Routing.Gateways))
		assert.Equal(t, "192.0.2.9", device.Routing.Gateways[0].Address)
	})

	t.Run("empty model falls back to the legacy element", func(t *testing.T) {
		t.Parallel()

		for _, version := range []string{` version="1.0.0"`, ` version="0.0.1"`, ""} {
			device, warnings := convertConfig(t, withModel(version, legacy))
			assert.Equal(t, want.Routing.Gateways, device.Routing.Gateways, version)
			assert.Empty(t, gatewayWarnings(warnings), version)
		}
	})

	t.Run("dynamic address", func(t *testing.T) {
		t.Parallel()

		// The migration rewrites a legacy "dynamic" address to empty.
		device, warnings := convertConfig(t, withModel(` version="1.0.0"`, nil, migratedWANGateway("")))
		require.Len(t, device.Routing.Gateways, 1)
		assert.Equal(t, "dynamic", device.Routing.Gateways[0].Address)
		assert.Empty(t, gatewayWarnings(warnings))
	})

	t.Run("unrecognized model version", func(t *testing.T) {
		t.Parallel()

		device, warnings := convertConfig(t, withModel(` version="9.9.9"`, nil, migratedWANGateway("192.0.2.1")))
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
		device, warnings := convertConfig(t, withModel(` version="9.9.9"`, nil, renamed))
		assert.Empty(t, device.Routing.Gateways)

		got := gatewayWarnings(warnings)
		require.Len(t, got, 1)
		assert.Equal(t, "OPNsense.Gateways.Version", got[0].Field)
		assert.Equal(t, common.SeverityLow, got[0].Severity)
	})
}
