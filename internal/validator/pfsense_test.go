package validator

import (
	"strings"
	"testing"

	opnsense "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// invalidPowerdMode is a test value for invalid powerd mode validation.
const invalidPowerdMode = "turbo"

// newValidPfSenseDocument returns a fully valid pfSense Document for use as a baseline.
func newValidPfSenseDocument() *pfsense.Document {
	doc := pfsense.NewDocument()
	doc.System = pfsense.System{
		Hostname:     "pfSense",
		Domain:       "localdomain",
		Timezone:     "Etc/UTC",
		Optimization: "normal",
		PowerdACMode: "hadp",
		Bogons: struct {
			Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty"`
		}{Interval: "monthly"},
		WebGUI: pfsense.WebGUI{Protocol: "https"},
		Group: []pfsense.Group{
			{Name: "admins", Gid: "1999", Scope: "system"},
		},
		User: []pfsense.User{
			{Name: "admin", UID: "0", Scope: "system", Groupname: "admins"},
		},
	}
	doc.Interfaces = pfsense.Interfaces{
		Items: map[string]pfsense.Interface{
			"wan": {IPAddr: "dhcp"},
			"lan": {IPAddr: "192.168.1.1", Subnet: "24"},
		},
	}
	doc.Dhcpd = pfsense.Dhcpd{
		Items: map[string]pfsense.DhcpdInterface{
			"lan": {Range: opnsense.Range{From: "192.168.1.100", To: "192.168.1.199"}},
		},
	}
	doc.Filter = pfsense.Filter{
		Rule: []pfsense.FilterRule{
			{
				Type:      "pass",
				Interface: opnsense.InterfaceList{"lan"},
				Source:    opnsense.Source{Any: new(string)},
				Destination: opnsense.Destination{
					Network: "lan",
				},
			},
		},
	}
	doc.Nat = pfsense.Nat{
		Outbound: opnsense.Outbound{Mode: "automatic"},
	}

	return doc
}

func TestValidatePfSenseDocument_ValidConfig(t *testing.T) {
	t.Parallel()

	doc := newValidPfSenseDocument()
	errors := ValidatePfSenseDocument(doc)
	assert.Empty(t, errors, "expected zero validation errors for valid config, got: %v", errors)
}

func TestValidatePfSenseDocument_NilDocument(t *testing.T) {
	t.Parallel()

	errors := ValidatePfSenseDocument(nil)
	require.Len(t, errors, 1)
	assert.Equal(t, "document", errors[0].Field)
	assert.Contains(t, errors[0].Message, "nil")
}

func TestValidatePfSenseSystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(sys *pfsense.System)
		wantCount int
		wantMsg   string
	}{
		{
			name:      "missing hostname",
			mutate:    func(sys *pfsense.System) { sys.Hostname = "" },
			wantCount: 1,
			wantMsg:   "hostname is required",
		},
		{
			name:      "invalid hostname",
			mutate:    func(sys *pfsense.System) { sys.Hostname = "inv@lid" },
			wantCount: 1,
			wantMsg:   "invalid characters",
		},
		{
			name:      "missing domain",
			mutate:    func(sys *pfsense.System) { sys.Domain = "" },
			wantCount: 1,
			wantMsg:   "domain is required",
		},
		{
			name:      "invalid timezone",
			mutate:    func(sys *pfsense.System) { sys.Timezone = "Invalid/Bad" },
			wantCount: 1,
			wantMsg:   "invalid timezone",
		},
		{
			name:      "invalid optimization",
			mutate:    func(sys *pfsense.System) { sys.Optimization = "bogus" },
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "invalid webgui protocol",
			mutate:    func(sys *pfsense.System) { sys.WebGUI.Protocol = "ftp" },
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "invalid powerd mode",
			mutate:    func(sys *pfsense.System) { sys.PowerdACMode = invalidPowerdMode },
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name: "invalid bogons interval",
			mutate: func(sys *pfsense.System) {
				sys.Bogons.Interval = "hourly"
			},
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "valid system",
			mutate:    func(_ *pfsense.System) {},
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sys := pfsense.System{
				Hostname:     "pfSense",
				Domain:       "localdomain",
				Timezone:     "Etc/UTC",
				Optimization: "normal",
				PowerdACMode: "hadp",
				Bogons: struct {
					Interval string `xml:"interval" json:"interval,omitempty" yaml:"interval,omitempty"`
				}{Interval: "monthly"},
				WebGUI: pfsense.WebGUI{Protocol: "https"},
			}
			tc.mutate(&sys)

			errs := validatePfSenseSystem(&sys)
			assert.Len(t, errs, tc.wantCount, "unexpected error count for %q: %v", tc.name, errs)
			if tc.wantMsg != "" && len(errs) > 0 {
				assert.Contains(t, errs[0].Message, tc.wantMsg)
			}
		})
	}
}

func TestValidatePfSenseFilter(t *testing.T) {
	t.Parallel()

	ifaces := &pfsense.Interfaces{
		Items: map[string]pfsense.Interface{
			"wan": {},
			"lan": {},
		},
	}

	validRule := func() pfsense.FilterRule {
		return pfsense.FilterRule{
			Type:      "pass",
			Interface: opnsense.InterfaceList{"lan"},
			Source:    opnsense.Source{Any: new(string)},
			Destination: opnsense.Destination{
				Network: "lan",
			},
		}
	}

	tests := []struct {
		name      string
		mutate    func(r *pfsense.FilterRule)
		wantCount int
		wantMsg   string
	}{
		{
			name:      "invalid rule type",
			mutate:    func(r *pfsense.FilterRule) { r.Type = "allow" },
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "invalid IP protocol",
			mutate:    func(r *pfsense.FilterRule) { r.IPProtocol = "ipv4" },
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "unknown interface",
			mutate:    func(r *pfsense.FilterRule) { r.Interface = opnsense.InterfaceList{"opt99"} },
			wantCount: 1,
			wantMsg:   "must be one of the configured interfaces",
		},
		{
			name: "invalid source port",
			mutate: func(r *pfsense.FilterRule) {
				r.Source = opnsense.Source{Any: new(string), Port: "99999"}
			},
			wantCount: 1,
			wantMsg:   "not a valid port",
		},
		{
			name: "floating rule without direction",
			mutate: func(r *pfsense.FilterRule) {
				r.Floating = "yes"
				r.Direction = ""
			},
			wantCount: 1,
			wantMsg:   "direction is required",
		},
		{
			name: "invalid direction",
			mutate: func(r *pfsense.FilterRule) {
				r.Direction = "both"
			},
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "invalid state type",
			mutate:    func(r *pfsense.FilterRule) { r.StateType = "invalid" },
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name: "source mutual exclusivity",
			mutate: func(r *pfsense.FilterRule) {
				r.Source = opnsense.Source{
					Any:     new(string),
					Network: "lan",
				}
			},
			wantCount: 1,
			wantMsg:   "one of: any, network, or address",
		},
		{
			name:      "inet46 is accepted",
			mutate:    func(r *pfsense.FilterRule) { r.IPProtocol = "inet46" },
			wantCount: 0,
		},
		{
			name:      "valid rule",
			mutate:    func(_ *pfsense.FilterRule) {},
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := validRule()
			tc.mutate(&rule)
			filter := &pfsense.Filter{Rule: []pfsense.FilterRule{rule}}

			errs := validatePfSenseFilter(filter, ifaces)
			assert.Len(t, errs, tc.wantCount, "unexpected error count for %q: %v", tc.name, errs)
			if tc.wantMsg != "" && len(errs) > 0 {
				assert.Contains(t, errs[0].Message, tc.wantMsg)
			}
		})
	}
}

func TestValidatePfSenseNat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		nat       pfsense.Nat
		wantCount int
		wantMsg   string
	}{
		{
			name:      "invalid outbound mode",
			nat:       pfsense.Nat{Outbound: opnsense.Outbound{Mode: "manual"}},
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name: "invalid reflection mode",
			nat: pfsense.Nat{
				Inbound: []pfsense.InboundRule{
					{NATReflection: "custom"},
				},
			},
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name:      "valid nat",
			nat:       pfsense.Nat{Outbound: opnsense.Outbound{Mode: "hybrid"}},
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errs := validatePfSenseNat(&tc.nat)
			assert.Len(t, errs, tc.wantCount, "unexpected error count for %q: %v", tc.name, errs)
			if tc.wantMsg != "" && len(errs) > 0 {
				assert.Contains(t, errs[0].Message, tc.wantMsg)
			}
		})
	}
}

//nolint:funlen // test table or data declaration; length is in data not logic
func TestValidatePfSenseUsersAndGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sys       pfsense.System
		wantCount int
		wantMsg   string
	}{
		{
			name: "duplicate user name",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "admin", UID: "0", Scope: "system", Groupname: "admins"},
					{Name: "admin", UID: "1", Scope: "local", Groupname: "admins"},
				},
			},
			wantCount: 1,
			wantMsg:   "must be unique",
		},
		{
			name: "duplicate user UID",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "admin", UID: "0", Scope: "system", Groupname: "admins"},
					{Name: "operator", UID: "0", Scope: "local", Groupname: "admins"},
				},
			},
			wantCount: 1,
			wantMsg:   "must be unique",
		},
		{
			name: "missing user name",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "", UID: "100", Scope: "local"},
				},
			},
			wantCount: 1,
			wantMsg:   "user name is required",
		},
		{
			name: "missing user UID",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "operator", UID: "", Scope: "local"},
				},
			},
			wantCount: 1,
			wantMsg:   "user UID is required",
		},
		{
			name: "invalid user UID",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "operator", UID: "-1", Scope: "local"},
				},
			},
			wantCount: 1,
			wantMsg:   "must be a non-negative integer",
		},
		{
			name: "invalid user scope",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "operator", UID: "1000", Scope: "remote", Groupname: "admins"},
				},
			},
			wantCount: 1,
			wantMsg:   "must be one of",
		},
		{
			name: "unknown group reference",
			sys: pfsense.System{
				Group: []pfsense.Group{{Name: "admins", Gid: "1999", Scope: "system"}},
				User: []pfsense.User{
					{Name: "operator", UID: "1000", Scope: "local", Groupname: "nonexistent"},
				},
			},
			wantCount: 1,
			wantMsg:   "does not exist",
		},
		{
			name: "duplicate group GID",
			sys: pfsense.System{
				Group: []pfsense.Group{
					{Name: "admins", Gid: "1999", Scope: "system"},
					{Name: "operators", Gid: "1999", Scope: "local"},
				},
				User: []pfsense.User{},
			},
			wantCount: 1,
			wantMsg:   "must be unique",
		},
		{
			name: "valid users and groups",
			sys: pfsense.System{
				Group: []pfsense.Group{
					{Name: "admins", Gid: "1999", Scope: "system"},
					{Name: "users", Gid: "2000", Scope: "local"},
				},
				User: []pfsense.User{
					{Name: "admin", UID: "0", Scope: "system", Groupname: "admins"},
					{Name: "operator", UID: "1000", Scope: "local", Groupname: "users"},
				},
			},
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errs := validatePfSenseUsersAndGroups(&tc.sys)
			assert.Len(t, errs, tc.wantCount, "unexpected error count for %q: %v", tc.name, errs)
			if tc.wantMsg != "" && len(errs) > 0 {
				found := false
				for _, e := range errs {
					if strings.Contains(e.Message, tc.wantMsg) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q in: %v", tc.wantMsg, errs)
			}
		})
	}
}

func TestValidatePfSenseDocument_CrossValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(doc *pfsense.Document)
		wantCount int
		wantMsg   string
	}{
		{
			name: "DHCP references non-existent interface",
			mutate: func(doc *pfsense.Document) {
				doc.Dhcpd = pfsense.Dhcpd{
					Items: map[string]pfsense.DhcpdInterface{
						"opt99": {Range: opnsense.Range{From: "10.0.0.100", To: "10.0.0.200"}},
					},
				}
			},
			wantCount: 1,
			wantMsg:   "must reference a configured interface",
		},
		{
			name: "filter rule references non-existent interface",
			mutate: func(doc *pfsense.Document) {
				doc.Filter = pfsense.Filter{
					Rule: []pfsense.FilterRule{
						{
							Type:      "pass",
							Interface: opnsense.InterfaceList{"opt99"},
							Source:    opnsense.Source{Any: new(string)},
							Destination: opnsense.Destination{
								Any: new(string),
							},
						},
					},
				}
			},
			wantCount: 1,
			wantMsg:   "must be one of the configured interfaces",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := newValidPfSenseDocument()
			tc.mutate(doc)

			errs := ValidatePfSenseDocument(doc)

			found := 0
			for _, e := range errs {
				if strings.Contains(e.Message, tc.wantMsg) {
					found++
				}
			}
			assert.GreaterOrEqual(t, found, tc.wantCount,
				"expected at least %d errors containing %q, got %d in: %v",
				tc.wantCount, tc.wantMsg, found, errs)
		})
	}
}

func TestValidatePfSenseSystem_PowerdModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		field  string
		mutate func(sys *pfsense.System)
	}{
		{
			field:  "system.powerd_battery_mode",
			mutate: func(sys *pfsense.System) { sys.PowerdBatteryMode = invalidPowerdMode },
		},
		{
			field:  "system.powerd_normal_mode",
			mutate: func(sys *pfsense.System) { sys.PowerdNormalMode = invalidPowerdMode },
		},
	}

	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			t.Parallel()

			sys := pfsense.System{
				Hostname:     "test",
				Domain:       "test.local",
				Timezone:     "Etc/UTC",
				Optimization: "normal",
			}
			tc.mutate(&sys)

			errs := validatePfSenseSystem(&sys)
			require.Len(t, errs, 1)
			assert.Equal(t, tc.field, errs[0].Field)
			assert.Contains(t, errs[0].Message, "must be one of")
		})
	}
}

func TestValidatePfSenseFilter_DestinationMutualExclusivity(t *testing.T) {
	t.Parallel()

	ifaces := &pfsense.Interfaces{
		Items: map[string]pfsense.Interface{"lan": {}},
	}

	filter := &pfsense.Filter{
		Rule: []pfsense.FilterRule{
			{
				Type:      "pass",
				Interface: opnsense.InterfaceList{"lan"},
				Source:    opnsense.Source{Any: new(string)},
				Destination: opnsense.Destination{
					Any:     new(string),
					Network: "lan",
				},
			},
		},
	}

	errs := validatePfSenseFilter(filter, ifaces)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "one of: any, network, or address") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected destination mutual exclusivity error, got: %v", errs)
}

func TestValidatePfSenseNat_ValidReflectionModes(t *testing.T) {
	t.Parallel()

	validModes := []string{"enable", "disable", "purenat"}
	for _, mode := range validModes {
		t.Run("valid_"+mode, func(t *testing.T) {
			t.Parallel()

			nat := &pfsense.Nat{
				Inbound: []pfsense.InboundRule{
					{NATReflection: mode},
				},
			}
			errs := validatePfSenseNat(nat)
			assert.Empty(t, errs, "expected no errors for valid reflection mode %q, got: %v", mode, errs)
		})
	}
}
