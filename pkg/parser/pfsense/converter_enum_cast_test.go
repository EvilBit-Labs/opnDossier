package pfsense_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfsenseSchema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findPfSenseWarning returns the first matching ConversionWarning by field+value.
// Returns nil when no match; callers require-NotNil to assert presence.
func findPfSenseWarning(warnings []common.ConversionWarning, field, value string) *common.ConversionWarning {
	for i := range warnings {
		if warnings[i].Field == field && warnings[i].Value == value {
			return &warnings[i]
		}
	}
	return nil
}

// TestConverter_EnumCast_EmitsWarning locks in the GOTCHAS §5.2 invariant for
// pfSense: every XML string cast to a typed enum is guarded by IsValid(), and
// an unrecognized non-empty value produces a ConversionWarning at the
// documented severity. Each pfSense enum callsite is covered: firewall rule
// Type/Direction/IPProtocol, NAT OutboundMode, NAT OutboundRules[*].IPProtocol,
// and NAT InboundRules[*].IPProtocol.
func TestConverter_EnumCast_EmitsWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		doc          *pfsenseSchema.Document
		wantField    string
		wantValue    string
		wantSeverity common.Severity
	}{
		{
			name: "firewall rule type",
			doc: &pfsenseSchema.Document{
				Filter: pfsenseSchema.Filter{
					Rule: []pfsenseSchema.FilterRule{{
						Type:      "definitely-not-a-real-type",
						Interface: opnsenseSchema.InterfaceList{"wan"},
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
			doc: &pfsenseSchema.Document{
				Filter: pfsenseSchema.Filter{
					Rule: []pfsenseSchema.FilterRule{{
						Type:      "pass",
						Direction: "sideways",
						Interface: opnsenseSchema.InterfaceList{"wan"},
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
			doc: &pfsenseSchema.Document{
				Filter: pfsenseSchema.Filter{
					Rule: []pfsenseSchema.FilterRule{{
						Type:       "pass",
						IPProtocol: "inet42",
						Interface:  opnsenseSchema.InterfaceList{"wan"},
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
			doc: &pfsenseSchema.Document{
				Nat: pfsenseSchema.Nat{
					Outbound: opnsenseSchema.Outbound{Mode: "telepathic"},
				},
			},
			wantField:    "NAT.OutboundMode",
			wantValue:    "telepathic",
			wantSeverity: common.SeverityLow,
		},
		{
			name: "nat outbound rule ip protocol",
			doc: &pfsenseSchema.Document{
				Nat: pfsenseSchema.Nat{
					Outbound: opnsenseSchema.Outbound{
						Rule: []opnsenseSchema.NATRule{{
							IPProtocol: "inet99",
							Interface:  opnsenseSchema.InterfaceList{"wan"},
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
			doc: &pfsenseSchema.Document{
				Nat: pfsenseSchema.Nat{
					Inbound: []pfsenseSchema.InboundRule{{
						IPProtocol: "inet77",
						Interface:  opnsenseSchema.InterfaceList{"wan"},
						UUID:       "55555555-5555-5555-5555-555555555555",
						Target:     "10.0.0.10",
					}},
				},
			},
			wantField:    "NAT.InboundRules[0].IPProtocol",
			wantValue:    "inet77",
			wantSeverity: common.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, warnings, err := pfsense.ConvertDocument(tt.doc)
			require.NoError(t, err)
			require.NotEmpty(t, warnings, "expected at least one warning for %s", tt.wantField)

			w := findPfSenseWarning(warnings, tt.wantField, tt.wantValue)
			require.NotNil(t, w, "expected warning on field %q with value %q, got %+v",
				tt.wantField, tt.wantValue, warnings)

			assert.NotEmpty(t, w.Message, "warning message must not be empty")
			assert.Equal(t, tt.wantSeverity, w.Severity,
				"severity drifted for %s (expected %q)", tt.wantField, tt.wantSeverity)
		})
	}
}

// TestConverter_EnumCast_EmptyStringDoesNotWarn protects the empty-string
// exemption for every pfSense enum-cast field path.
//
// Note: this test intentionally sets Type: "pass" rather than leaving Type
// empty, because pfSense's convertFirewallRules emits a distinct
// "firewall rule has empty type" warning when both Type and
// AssociatedRuleID are empty. That warning is not an enum-cast concern, so
// the test uses a valid Type to isolate the enum-cast invariant.
func TestConverter_EnumCast_EmptyStringDoesNotWarn(t *testing.T) {
	t.Parallel()

	doc := &pfsenseSchema.Document{
		Filter: pfsenseSchema.Filter{
			Rule: []pfsenseSchema.FilterRule{{
				Type:      "pass",
				Interface: opnsenseSchema.InterfaceList{"wan"},
				UUID:      "00000000-0000-0000-0000-000000000000",
				Source: opnsenseSchema.Source{
					Address: "any",
				},
				Destination: opnsenseSchema.Destination{
					Address: "any",
				},
			}},
		},
		Nat: pfsenseSchema.Nat{
			Outbound: opnsenseSchema.Outbound{
				Mode: "",
				Rule: []opnsenseSchema.NATRule{{
					IPProtocol: "",
					Interface:  opnsenseSchema.InterfaceList{"wan"},
					UUID:       "66666666-6666-6666-6666-666666666666",
				}},
			},
			Inbound: []pfsenseSchema.InboundRule{{
				IPProtocol: "",
				Interface:  opnsenseSchema.InterfaceList{"wan"},
				UUID:       "77777777-7777-7777-7777-777777777777",
				Target:     "10.0.0.10",
			}},
		},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
	require.NoError(t, err)

	unexpectedFields := []string{
		"FirewallRules[0].Direction",
		"FirewallRules[0].IPProtocol",
		"NAT.OutboundMode",
		"NAT.OutboundRules[0].IPProtocol",
		"NAT.InboundRules[0].IPProtocol",
	}

	for _, field := range unexpectedFields {
		for _, w := range warnings {
			assert.NotEqual(t, field, w.Field,
				"empty enum value on %s should not produce a warning (got %+v)", field, w)
		}
	}
}

// TestConverter_EnumCast_MultipleInvalidsAccumulate ensures invalid values in
// multiple independent pfSense enum fields each produce their own warning —
// no coalescing, no early-exit after the first bad value. Uses a slice
// rather than a map so same-Field collisions do not silently collapse.
func TestConverter_EnumCast_MultipleInvalidsAccumulate(t *testing.T) {
	t.Parallel()

	doc := &pfsenseSchema.Document{
		Filter: pfsenseSchema.Filter{
			Rule: []pfsenseSchema.FilterRule{{
				Type:      "bogus-type",
				Direction: "bogus-dir",
				Interface: opnsenseSchema.InterfaceList{"wan"},
				UUID:      "88888888-8888-8888-8888-888888888888",
			}},
		},
		Nat: pfsenseSchema.Nat{Outbound: opnsenseSchema.Outbound{Mode: "bogus-mode"}},
	}

	_, warnings, err := pfsense.ConvertDocument(doc)
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
		assert.NotNil(t, findPfSenseWarning(warnings, exp.field, exp.value),
			"expected warning on %s=%q, got %+v", exp.field, exp.value, warnings)
	}
}
