package opnsense

import (
	"reflect"
	"testing"
)

// xmlNameField is the encoding/xml bookkeeping field every schema element type
// carries. It is populated on unmarshal and is never configuration data, so the
// placeholder predicates exclude it and so does the coverage tripwire below.
const xmlNameField = "XMLName"

// placeholderReporter is implemented by every schema element type that carries a
// vendor placeholder guard.
type placeholderReporter interface {
	IsPlaceholder() bool
}

// TestIsPlaceholder_EveryFieldDefeatsPlaceholder_NoFieldIsSilentlyUncovered is
// the tripwire for the safety promise every IsPlaceholder doc comment makes:
// under-reporting configured resources is the dangerous direction, so an entry
// carrying any data at all must be retained.
//
// The predicates enumerate their fields by hand, which they must -- encoding/xml
// populates XMLName on unmarshal, so comparing against the zero value would
// never match a decoded element. That hand-written list is the weak point: add a
// field to one of these structs, forget to add it to the predicate, and an entry
// carrying only that field is silently dropped from an audit report.
//
// This test sets each non-XMLName field in isolation and asserts the entry is
// still retained, so a forgotten field fails here rather than in production. It
// deliberately has no allowlist of field names to fall out of sync; a field type
// it cannot populate fails loudly instead of being skipped, which forces a human
// decision at exactly the moment a new field type appears.
func TestIsPlaceholder_EveryFieldDefeatsPlaceholder_NoFieldIsSilentlyUncovered(t *testing.T) {
	t.Parallel()

	types := []struct {
		name string
		zero placeholderReporter
	}{
		{name: "PPP", zero: PPP{}},
		{name: "StaticRoute", zero: StaticRoute{}},
		{name: "Bridge", zero: Bridge{}},
		{name: "GIF", zero: GIF{}},
		{name: "GRE", zero: GRE{}},
		{name: "LAGG", zero: LAGG{}},
		{name: "VIP", zero: VIP{}},
		{name: "VLAN", zero: VLAN{}},
		// SysctlItem's guard runs in SysctlItems.UnmarshalXML rather than at a
		// converter boundary, but the predicate carries the same risk: drop a
		// field from it and an entry holding only that field is discarded with
		// the whole suite still green. It has no XMLName, so no harness change
		// is needed to enrol it.
		{name: "SysctlItem", zero: SysctlItem{}},
		// InboundRule is the first enrolled type with fields that are not
		// strings or bools, which is what populateField is for.
		{name: "InboundRule", zero: InboundRule{}},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			typ := reflect.TypeOf(tt.zero)
			if !tt.zero.IsPlaceholder() {
				t.Fatalf("%s zero value must report as a placeholder", tt.name)
			}

			for i := range typ.NumField() {
				field := typ.Field(i)
				if field.Name == xmlNameField {
					continue
				}

				// A struct field is populated one leaf at a time, so the
				// predicate cannot pass by looking at only some of it.
				leaves := 1
				if field.Type.Kind() == reflect.Struct {
					leaves = field.Type.NumField()
				}

				for leaf := range leaves {
					populated := reflect.New(typ).Elem()

					target, label := populated.Field(i), field.Name
					if field.Type.Kind() == reflect.Struct {
						target, label = target.Field(leaf), field.Name+"."+field.Type.Field(leaf).Name
					}

					if !populateField(target) {
						t.Fatalf(
							"field %s.%s has kind %s, which this test cannot populate -- "+
								"extend both this test and %s.IsPlaceholder to cover it",
							tt.name, label, target.Kind(), tt.name,
						)
					}

					entry, ok := populated.Interface().(placeholderReporter)
					if !ok {
						t.Fatalf("%s does not implement placeholderReporter", tt.name)
					}

					if entry.IsPlaceholder() {
						t.Errorf(
							"%s.IsPlaceholder() dropped an entry carrying only %s -- "+
								"the field is missing from the predicate",
							tt.name, label,
						)
					}
				}
			}
		})
	}
}

// populateField gives v a non-zero value and reports whether it could.
func populateField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int:
		v.SetInt(1)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))

		return populateField(v.Index(0))
	default:
		return false
	}

	return true
}
