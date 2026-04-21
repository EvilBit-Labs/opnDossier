package opnsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConverter_EnumCast_EmitsWarning locks in the GOTCHAS §5.2 invariant:
// every XML string that is cast to a typed enum is guarded by IsValid(), and
// an unrecognized non-empty value produces exactly one ConversionWarning on
// the offending field with the documented severity. This test is the
// canonical regression for the pattern for OPNsense enum casts; pfSense
// enum casts are covered separately in
// pkg/parser/pfsense/converter_enum_cast_test.go. Future enum casts added to
// the OPNsense converter should be covered here; pfSense additions belong
// in the sibling file.
//
//nolint:funlen // test table or data declaration; length is in data not logic
func TestConverter_EnumCast_EmitsWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		doc          *schema.OpnSenseDocument
		wantField    string
		wantValue    string
		wantSeverity common.Severity
	}{
		{
			name: "firewall rule type",
			doc: &schema.OpnSenseDocument{
				Filter: schema.Filter{
					Rule: []schema.Rule{{
						Type:      "definitely-not-a-real-type",
						Interface: schema.InterfaceList{"wan"},
						UUID:      "11111111-1111-1111-1111-111111111111",
					}},
				},
			},
			wantField:    "FirewallRules[0].Type",
			wantValue:    "definitely-not-a-real-type",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "firewall rule direction",
			doc: &schema.OpnSenseDocument{
				Filter: schema.Filter{
					Rule: []schema.Rule{{
						Type:      "pass",
						Direction: "sideways",
						Interface: schema.InterfaceList{"wan"},
						UUID:      "22222222-2222-2222-2222-222222222222",
					}},
				},
			},
			wantField:    "FirewallRules[0].Direction",
			wantValue:    "sideways",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "firewall rule ip protocol",
			doc: &schema.OpnSenseDocument{
				Filter: schema.Filter{
					Rule: []schema.Rule{{
						Type:       "pass",
						IPProtocol: "inet42",
						Interface:  schema.InterfaceList{"wan"},
						UUID:       "33333333-3333-3333-3333-333333333333",
					}},
				},
			},
			wantField:    "FirewallRules[0].IPProtocol",
			wantValue:    "inet42",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "nat outbound mode",
			doc: &schema.OpnSenseDocument{
				Nat: schema.Nat{
					Outbound: schema.Outbound{Mode: "telepathic"},
				},
			},
			wantField:    "NAT.OutboundMode",
			wantValue:    "telepathic",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "nat outbound rule ip protocol",
			doc: &schema.OpnSenseDocument{
				Nat: schema.Nat{
					Outbound: schema.Outbound{
						Rule: []schema.NATRule{{
							IPProtocol: "inet99",
							Interface:  schema.InterfaceList{"wan"},
							UUID:       "44444444-4444-4444-4444-444444444444",
						}},
					},
				},
			},
			wantField:    "NAT.OutboundRules[0].IPProtocol",
			wantValue:    "inet99",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "nat inbound rule ip protocol",
			doc: &schema.OpnSenseDocument{
				Nat: schema.Nat{
					Inbound: []schema.InboundRule{{
						IPProtocol: "inet77",
						Interface:  schema.InterfaceList{"wan"},
						UUID:       "55555555-5555-5555-5555-555555555555",
						InternalIP: "10.0.0.10",
					}},
				},
			},
			wantField:    "NAT.InboundRules[0].IPProtocol",
			wantValue:    "inet77",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "lagg protocol",
			doc: &schema.OpnSenseDocument{
				LAGGInterfaces: schema.LAGGInterfaces{
					Lagg: []schema.LAGG{{Laggif: "lagg0", Proto: "not-a-proto"}},
				},
			},
			wantField:    "LAGGs[0].Protocol",
			wantValue:    "not-a-proto",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "virtual ip mode",
			doc: &schema.OpnSenseDocument{
				VirtualIP: schema.VirtualIP{
					Vip: []schema.VIP{{Interface: "wan", Mode: "bogus-mode"}},
				},
			},
			wantField:    "VirtualIPs[0].Mode",
			wantValue:    "bogus-mode",
			wantSeverity: common.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, warnings, err := opnsense.ConvertDocument(tt.doc)
			require.NoError(t, err)
			require.NotEmpty(t, warnings, "expected at least one warning for unrecognized %s", tt.wantField)

			w := findWarning(warnings, tt.wantField, tt.wantValue)
			require.NotNil(t, w, "expected warning on field %q with value %q, got %+v",
				tt.wantField, tt.wantValue, warnings)

			assert.NotEmpty(t, w.Message, "warning message must not be empty")
			assert.Equal(t, tt.wantSeverity, w.Severity,
				"severity drifted for %s (expected %q)", tt.wantField, tt.wantSeverity)
		})
	}
}

// TestConverter_EnumCast_EmptyStringDoesNotWarn protects the intentional
// empty-string exemption: `if field != "" && !cast.IsValid()`. Empty XML
// elements are a legitimate way to omit a value and must not produce an
// enum-cast warning on any of the enum field paths.
//
// Note: this test sets Type: "pass" on the firewall rule because the
// converter emits a separate SeverityHigh "firewall rule has empty type"
// warning when Type is empty — that warning is not an enum-cast concern
// and would obscure the invariant under test. Direction, IPProtocol, and
// the NAT / LAGG / VIP enum fields are left empty to exercise the
// enum-cast branch specifically.
func TestConverter_EnumCast_EmptyStringDoesNotWarn(t *testing.T) {
	t.Parallel()

	doc := &schema.OpnSenseDocument{
		Filter: schema.Filter{
			Rule: []schema.Rule{{
				Type:      "pass",
				Interface: schema.InterfaceList{"wan"},
				UUID:      "00000000-0000-0000-0000-000000000000",
			}},
		},
		Nat: schema.Nat{
			Outbound: schema.Outbound{
				Mode: "",
				Rule: []schema.NATRule{{
					IPProtocol: "",
					Interface:  schema.InterfaceList{"wan"},
					UUID:       "00000000-0000-0000-0000-00000000aaaa",
				}},
			},
			Inbound: []schema.InboundRule{{
				IPProtocol: "",
				Interface:  schema.InterfaceList{"wan"},
				UUID:       "00000000-0000-0000-0000-00000000bbbb",
				InternalIP: "10.0.0.10",
			}},
		},
		LAGGInterfaces: schema.LAGGInterfaces{
			Lagg: []schema.LAGG{{Laggif: "lagg0", Proto: ""}},
		},
		VirtualIP: schema.VirtualIP{
			Vip: []schema.VIP{{Interface: "wan", Mode: ""}},
		},
	}

	_, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	// Assert on the specific enum-cast field paths rather than scanning for
	// a message substring — a future code path emitting a different message
	// on empty enum values should still fail this test.
	unexpectedFields := []string{
		"FirewallRules[0].Direction",
		"FirewallRules[0].IPProtocol",
		"NAT.OutboundMode",
		"NAT.OutboundRules[0].IPProtocol",
		"NAT.InboundRules[0].IPProtocol",
		"LAGGs[0].Protocol",
		"VirtualIPs[0].Mode",
	}

	for _, field := range unexpectedFields {
		for _, w := range warnings {
			assert.NotEqual(t, field, w.Field,
				"empty enum value on %s should not produce a warning (got %+v)", field, w)
		}
	}
}

// TestConverter_EnumCast_MultipleInvalidsAccumulate ensures invalid values in
// multiple independent fields each produce their own warning — no coalescing,
// no early-exit after the first bad value. Uses a slice rather than a map so
// two warnings on the same Field do not silently collapse.
func TestConverter_EnumCast_MultipleInvalidsAccumulate(t *testing.T) {
	t.Parallel()

	doc := &schema.OpnSenseDocument{
		Filter: schema.Filter{
			Rule: []schema.Rule{{
				Type:      "bogus-type",
				Direction: "bogus-dir",
				Interface: schema.InterfaceList{"wan"},
				UUID:      "44444444-4444-4444-4444-444444444444",
			}},
		},
		Nat: schema.Nat{Outbound: schema.Outbound{Mode: "bogus-mode"}},
	}

	_, warnings, err := opnsense.ConvertDocument(doc)
	require.NoError(t, err)

	expected := []struct {
		field string
		value string
	}{
		{"FirewallRules[0].Type", "bogus-type"},
		{"FirewallRules[0].Direction", "bogus-dir"},
		{"NAT.OutboundMode", "bogus-mode"},
	}

	for _, exp := range expected {
		require.NotNil(t, findWarning(warnings, exp.field, exp.value),
			"expected warning on %s=%q, got %+v", exp.field, exp.value, warnings)
	}
}
