package parser_test

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	opnschema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
	pfschema "github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// TestCommonDeviceSubsystemParity asserts that every CommonDevice subsystem
// OPNsense populates from a representative fixture is either (a) also populated
// by pfSense from its representative fixture, or (b) explicitly listed in
// pfsense.KnownGaps() with a corresponding ConversionWarning.
//
// When a pfSense subsystem gets implemented, remove its entry from
// pfsenseKnownGaps AND the parity test passes automatically. When a new
// subsystem lands on OPNsense but not pfSense, add it to pfsenseKnownGaps
// in the same PR (the converter emits a SeverityMedium warning per entry).
// The test fails loudly if pfSense silently drops a subsystem.
//
// See docs/user-guide/device-support-matrix.md for the human-readable table.
func TestCommonDeviceSubsystemParity(t *testing.T) {
	opnDoc := loadOpnsenseFixture(t)
	pfsDoc := loadPfsenseFixture(t)

	opnDev, _, err := opnsense.ConvertDocument(opnDoc)
	if err != nil {
		t.Fatalf("opnsense.ConvertDocument: %v", err)
	}
	pfsDev, pfsWarnings, err := pfsense.ConvertDocument(pfsDoc)
	if err != nil {
		t.Fatalf("pfsense.ConvertDocument: %v", err)
	}

	// Release-gate invariant: for every subsystem declared in pfsense.KnownGaps(),
	// the pfSense converter MUST emit a matching ConversionWarning. If someone
	// deletes or rewords the warning-emission code without also removing the
	// subsystem from pfsenseKnownGaps, this assertion fails loudly. Without it,
	// the parity test above passes vacuously — the IsKnownGap() escape hatch
	// would short-circuit the loop without verifying the warning contract.
	for _, gap := range pfsense.KnownGaps() {
		found := false
		for _, w := range pfsWarnings {
			if w.Field == gap && w.Message == pfsense.PfsenseKnownGapMessage {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(
				"pfSense converter did not emit a ConversionWarning for known-gap subsystem %q; "+
					"expected Field=%q and Message=%q. Either remove %q from pfsenseKnownGaps "+
					"or restore the warning emission in emitKnownGapWarnings().",
				gap, gap, pfsense.PfsenseKnownGapMessage, gap)
		}
	}

	opnVal := reflect.ValueOf(*opnDev)
	pfsVal := reflect.ValueOf(*pfsDev)
	opnType := opnVal.Type()

	for i := range opnType.NumField() {
		fieldName := opnType.Field(i).Name
		if strings.HasPrefix(fieldName, "DeviceType") ||
			fieldName == "Version" ||
			fieldName == "Statistics" ||
			fieldName == "Analysis" ||
			fieldName == "ComplianceResults" ||
			fieldName == "Metadata" ||
			fieldName == "ReportID" {
			continue
		}

		if !isFieldPopulated(opnVal.Field(i)) {
			continue
		}
		if isFieldPopulated(pfsVal.FieldByName(fieldName)) {
			continue
		}
		if pfsense.IsKnownGap(fieldName) {
			continue
		}
		t.Errorf(
			"pfSense silently drops the %s subsystem that OPNsense populates; "+
				"either implement it in the pfSense converter or add %q to "+
				"pfsenseKnownGaps with a ConversionWarning.",
			fieldName, fieldName)
	}
}

// isFieldPopulated reports whether v carries non-zero content for parity
// purposes. Slices and maps are considered populated when non-empty; structs
// are considered populated when any non-zero field is present; pointers when
// non-nil; scalars when non-zero. This matches the spirit of "converter
// emitted data for this subsystem.".
func isFieldPopulated(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	switch v.Kind() {
	case reflect.Slice, reflect.Map, reflect.String:
		return v.Len() > 0
	case reflect.Ptr, reflect.Interface:
		return !v.IsNil()
	case reflect.Struct:
		// reflect.Value.Fields() returns iter.Seq2[reflect.StructField, reflect.Value]
		// (Go 1.26+), so the two-value range form is required. This differs from
		// reflect.Type.Fields() (iter.Seq[reflect.StructField]) used elsewhere in
		// the repo — do not reduce to a single range variable or the file will not
		// compile.
		for _, fv := range v.Fields() {
			if isFieldPopulated(fv) {
				return true
			}
		}
		return false
	default:
		return !v.IsZero()
	}
}

func loadOpnsenseFixture(t *testing.T) *opnschema.OpnSenseDocument {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "sample.config.1.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read opnsense fixture %s: %v", path, err)
	}
	var doc opnschema.OpnSenseDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal opnsense fixture: %v", err)
	}
	return &doc
}

func loadPfsenseFixture(t *testing.T) *pfschema.Document {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "pfsense", "config-pfSense.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pfsense fixture %s: %v", path, err)
	}
	var doc pfschema.Document
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal pfsense fixture: %v", err)
	}
	return &doc
}
