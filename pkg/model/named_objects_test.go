package model_test

import (
	"encoding/json"
	"fmt"
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNamedObjects_Resolve_StaticLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		objects      common.NamedObjects
		lookup       string
		wantMembers  []string
		wantResolved bool
	}{
		{
			name: "host object resolves its members",
			objects: common.NamedObjects{
				"webserver": {Name: "webserver", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.5"}},
			},
			lookup:       "webserver",
			wantMembers:  []string{"10.0.0.5"},
			wantResolved: true,
		},
		{
			name: "network object resolves its members",
			objects: common.NamedObjects{
				"lan_net": {Name: "lan_net", Type: common.NamedObjectTypeNetwork, Members: []string{"10.0.0.0/24"}},
			},
			lookup:       "lan_net",
			wantMembers:  []string{"10.0.0.0/24"},
			wantResolved: true,
		},
		{
			name: "port object resolves its members",
			objects: common.NamedObjects{
				"webports": {Name: "webports", Type: common.NamedObjectTypePort, Members: []string{"80", "443"}},
			},
			lookup:       "webports",
			wantMembers:  []string{"80", "443"},
			wantResolved: true,
		},
		{
			name: "nested reference flattens with a literal sibling",
			objects: common.NamedObjects{
				"GRP": {Name: "GRP", Type: common.NamedObjectTypeNetwork, Members: []string{"A", "1.2.3.4"}},
				"A":   {Name: "A", Type: common.NamedObjectTypeNetwork, Members: []string{"10.0.0.0/8"}},
			},
			lookup:       "GRP",
			wantMembers:  []string{"10.0.0.0/8", "1.2.3.4"},
			wantResolved: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			members, resolved := tt.objects.Resolve(tt.lookup)

			assert.Equal(t, tt.wantResolved, resolved)
			assert.ElementsMatch(t, tt.wantMembers, members)
		})
	}
}

func TestNamedObjects_Resolve_Cycle(t *testing.T) {
	t.Parallel()

	objects := common.NamedObjects{
		"A": {Name: "A", Type: common.NamedObjectTypeNetwork, Members: []string{"B", "10.0.0.1"}},
		"B": {Name: "B", Type: common.NamedObjectTypeNetwork, Members: []string{"A"}},
	}

	members, resolved := objects.Resolve("A")

	assert.False(t, resolved, "a cycle must never be reported as fully resolved")
	assert.Contains(t, members, "10.0.0.1",
		"the literal member reached before the cycle should still surface in the partial result")
	assert.NotContains(t, members, "A", "the alias name itself must never leak into the member set")
	assert.NotContains(t, members, "B", "the alias name itself must never leak into the member set")
}

func TestNamedObjects_Resolve_DepthCapExceeded(t *testing.T) {
	t.Parallel()

	const chainLength = 20 // comfortably deeper than maxAliasDepth (16)

	objects := make(common.NamedObjects, chainLength)
	for i := range chainLength {
		name := fmt.Sprintf("obj%d", i)
		next := fmt.Sprintf("obj%d", i+1)
		if i == chainLength-1 {
			next = "10.0.0.1" // terminal literal, never reached
		}
		objects[name] = common.NamedObject{
			Name:    name,
			Type:    common.NamedObjectTypeNetwork,
			Members: []string{next},
		}
	}

	_, resolved := objects.Resolve("obj0")

	assert.False(t, resolved, "a reference chain deeper than maxAliasDepth must not resolve fully")
}

func TestNamedObjects_Resolve_DynamicTypesStayOpaque(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		objectType common.NamedObjectType
	}{
		{"url", common.NamedObjectTypeURL},
		{"geoip", common.NamedObjectTypeGeoIP},
		{"external", common.NamedObjectTypeExternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			objects := common.NamedObjects{
				"dyn": {Name: "dyn", Type: tt.objectType, Members: []string{"https://example.com/list.txt"}},
			}

			members, resolved := objects.Resolve("dyn")

			assert.False(t, resolved)
			assert.Empty(t, members, "dynamic object members must stay opaque, never echoed as resolved literals")
		})
	}
}

func TestNamedObjects_Resolve_EmptyOrUnknown(t *testing.T) {
	t.Parallel()

	t.Run("nil registry", func(t *testing.T) {
		t.Parallel()

		var objects common.NamedObjects

		members, resolved := objects.Resolve("anything")

		assert.False(t, resolved)
		assert.Nil(t, members)
	})

	t.Run("empty registry", func(t *testing.T) {
		t.Parallel()

		objects := common.NamedObjects{}

		members, resolved := objects.Resolve("anything")

		assert.False(t, resolved)
		assert.Nil(t, members)
	})

	t.Run("unknown name in populated registry", func(t *testing.T) {
		t.Parallel()

		objects := common.NamedObjects{
			"known": {Name: "known", Type: common.NamedObjectTypeHost, Members: []string{"10.0.0.1"}},
		}

		members, resolved := objects.Resolve("unknown")

		assert.False(t, resolved)
		assert.Nil(t, members)
	})
}

func TestNamedObjectType_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		val  common.NamedObjectType
		want bool
	}{
		{"host is valid", common.NamedObjectTypeHost, true},
		{"network is valid", common.NamedObjectTypeNetwork, true},
		{"port is valid", common.NamedObjectTypePort, true},
		{"url is valid", common.NamedObjectTypeURL, true},
		{"geoip is valid", common.NamedObjectTypeGeoIP, true},
		{"external is valid", common.NamedObjectTypeExternal, true},
		{"empty is invalid", common.NamedObjectType(""), false},
		{"unknown string is invalid", common.NamedObjectType("bogus"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.val.IsValid())
		})
	}
}

func TestCommonDevice_NamedObjects_OmitEmpty(t *testing.T) {
	t.Parallel()

	device := common.CommonDevice{DeviceType: common.DeviceTypeOPNsense}

	jsonData, err := json.Marshal(device)
	require.NoError(t, err)

	var jsonMap map[string]any
	require.NoError(t, json.Unmarshal(jsonData, &jsonMap))
	_, present := jsonMap["namedObjects"]
	assert.False(t, present, "namedObjects must be omitted from JSON for an alias-free device")

	yamlData, err := yaml.Marshal(device)
	require.NoError(t, err)

	var yamlMap map[string]any
	require.NoError(t, yaml.Unmarshal(yamlData, &yamlMap))
	_, present = yamlMap["namedObjects"]
	assert.False(t, present, "namedObjects must be omitted from YAML for an alias-free device")
}

func TestRuleEndpoint_ObjectRef_OmitEmpty(t *testing.T) {
	t.Parallel()

	endpoint := common.RuleEndpoint{Address: "192.168.1.1"}

	jsonData, err := json.Marshal(endpoint)
	require.NoError(t, err)

	var jsonMap map[string]any
	require.NoError(t, json.Unmarshal(jsonData, &jsonMap))
	_, present := jsonMap["addressRef"]
	assert.False(t, present, "addressRef must be omitted when the endpoint value is a literal")
	_, present = jsonMap["portRef"]
	assert.False(t, present, "portRef must be omitted when the endpoint value is a literal")
}

func TestRuleEndpoint_ObjectRef_PopulatedWhenAliased(t *testing.T) {
	t.Parallel()

	endpoint := common.RuleEndpoint{
		Address:    "10.0.0.0/24",
		AddressRef: &common.ObjectRef{Name: "lan_net"},
	}

	assert.NotNil(t, endpoint.AddressRef)
	assert.Equal(t, "lan_net", endpoint.AddressRef.Name)
	assert.Equal(t, "10.0.0.0/24", endpoint.Address,
		"the resolved inline value must stay populated alongside the ref (ADR-0002 optionality invariant)")
}
