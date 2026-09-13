package cfgparser

// This file statically proves handleStartElement in xml.go has exactly one
// case per xml-tagged top-level field on schema.OpnSenseDocument, and that
// each case decodes into the field that OWNS that tag -- not merely a case
// with a matching label. A label-only check would not catch a copy-paste
// swap between adjacent, structurally-identical elements (e.g. a case
// "gifs" that decodes into &doc.GREInterfaces instead of &doc.GIFInterfaces)
// -- see GOTCHAS.md §3.6, the "values parsed but never converted" class this
// guards against.
//
// The check is done via go/ast source inspection rather than by exercising
// XML fixtures, because the failure mode it targets (a case existing but
// targeting the wrong field, or a schema field with no case at all) produces
// no error and no visibly wrong output for most fields -- it just silently
// drops or misroutes data. See U3's fix for schema.OpnSenseDocument.Aliases,
// which had exactly this shape of gap: the case was simply absent, and no
// test failed until testdata/opnsense-legacy-aliases.xml was added.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// TestHandleStartElement_DispatchCoversEverySchemaField is the drift guard
// described above. It fails if:
//   - a schema field's xml tag has no matching case in handleStartElement
//     (a new top-level element added to the schema with no dispatch case), or
//   - a case in handleStartElement decodes into a field other than the one
//     that owns its tag (a copy-paste swap), or
//   - handleStartElement has a case for a tag the schema no longer declares.
func TestHandleStartElement_DispatchCoversEverySchemaField(t *testing.T) {
	t.Parallel()

	dispatch := extractDispatchTargets(t)
	schemaTags := extractSchemaTags(t)

	for tag, field := range schemaTags {
		targets, ok := dispatch[tag]
		if !ok {
			t.Errorf("handleStartElement has no case for schema tag %q (owned by field %s)", tag, field)
			continue
		}
		if !targets[field] {
			t.Errorf(
				"case %q in handleStartElement does not decode into doc.%s (the field owning xml tag %q); it references %v",
				tag,
				field,
				tag,
				targets,
			)
		}
	}

	for tag := range dispatch {
		if _, ok := schemaTags[tag]; !ok {
			t.Errorf(
				"handleStartElement has a case for %q, but schema.OpnSenseDocument has no field with that xml tag",
				tag,
			)
		}
	}
}

// extractDispatchTargets parses xml.go and returns, for every non-default
// case label in handleStartElement's switch statement, the set of doc.<Field>
// references appearing anywhere in that case's body. Walking the whole case
// body (rather than pattern-matching only a `return decodeChild(dec,
// &doc.X, se)` shape) also covers the "ca" and "cert" cases, which decode
// into a local variable and then append it to doc.CAs / doc.Certs.
func extractDispatchTargets(t *testing.T) map[string]map[string]bool {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "xml.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing xml.go: %v", err)
	}

	fn := findFuncDecl(file, "handleStartElement")
	if fn == nil {
		t.Fatal("handleStartElement not found in xml.go")
	}

	sw := findSwitchStmt(fn)
	if sw == nil {
		t.Fatal("no switch statement found in handleStartElement")
	}

	result := make(map[string]map[string]bool)

	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok || clause.List == nil { // nil List marks the default case.
			continue
		}

		targets := collectDocFieldRefs(clause.Body)

		for _, expr := range clause.List {
			lit, ok := expr.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}

			label, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}

			result[label] = targets
		}
	}

	return result
}

// findFuncDecl returns the top-level function declaration named name, or nil
// if none is found.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}

	return nil
}

// findSwitchStmt returns the first *ast.SwitchStmt found in fn's body.
func findSwitchStmt(fn *ast.FuncDecl) *ast.SwitchStmt {
	var sw *ast.SwitchStmt

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sw != nil {
			return false
		}
		if s, ok := n.(*ast.SwitchStmt); ok {
			sw = s
			return false
		}
		return true
	})

	return sw
}

// collectDocFieldRefs walks stmts and returns the set of field names
// referenced as doc.<Field> -- the case body's decode target(s). This is
// intentionally a reference scan rather than a pattern match on
// `decodeChild(dec, &doc.Field, se)`, so it also covers cases like "ca" and
// "cert" that decode into a local variable and assign it via
// `doc.CAs = append(doc.CAs, ca)`.
func collectDocFieldRefs(stmts []ast.Stmt) map[string]bool {
	targets := make(map[string]bool)

	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "doc" {
				return true
			}

			targets[sel.Sel.Name] = true

			return true
		})
	}

	return targets
}

// extractSchemaTags reflects over schema.OpnSenseDocument and returns a map
// from xml tag element name to the Go field name that owns it. XMLName is
// skipped: its tag ("opnsense") names the document root, which
// handleStartElement handles in an `if` before the switch, not as a case.
func extractSchemaTags(t *testing.T) map[string]string {
	t.Helper()

	typ := reflect.TypeFor[schema.OpnSenseDocument]()
	tags := make(map[string]string, typ.NumField())

	for field := range typ.Fields() {
		if field.Name == "XMLName" {
			continue
		}

		xmlTag, ok := field.Tag.Lookup("xml")
		if !ok || xmlTag == "-" {
			t.Fatalf("schema field %s has no xml tag; dispatch coverage cannot be verified", field.Name)
		}

		name, _, _ := strings.Cut(xmlTag, ",")
		if name == "" {
			t.Fatalf("schema field %s has an empty xml tag element name", field.Name)
		}

		if existing, ok := tags[name]; ok {
			t.Fatalf("xml tag %q is used by both field %s and field %s", name, existing, field.Name)
		}

		tags[name] = field.Name
	}

	return tags
}
