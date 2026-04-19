// Package parser_test contains compile-time assertions that lock the shape of
// the public pkg/parser API surface before v1.5 tags. Any time a method is
// added to a public interface, or a concrete implementation drifts from its
// interface contract, the build here breaks before any test runs.
//
// See docs/development/public-api.md § API Shape Enforcement for the policy
// and the companion goldie snapshot tests in api_snapshot_test.go.
package parser_test

import (
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
)

// Compile-time assertions that every public concrete type still satisfies the
// public interface it claims to implement. These are free at runtime — they
// only fire during `go build` / `go test` compilation.
//
// When an intentional interface change lands, update this file in the same
// commit so reviewers can see the before/after contract explicitly.
var (
	// DeviceParser — the per-device parser contract. Both vendor-specific
	// Parser types are registered through parser.DefaultRegistry() from their
	// init() functions and must satisfy this interface for Factory.CreateDevice
	// to dispatch correctly.
	_ parser.DeviceParser = (*opnsense.Parser)(nil)
	_ parser.DeviceParser = (*pfsense.Parser)(nil)
)

// Note on parser.OPNsenseXMLDecoder: the only concrete implementation lives in
// internal/cfgparser.XMLParser and is not part of the public API (internal/
// packages are not importable outside the module). External consumers inject
// their own OPNsenseXMLDecoder implementations; we therefore cannot add a
// compile-time assertion here. The interface itself is still snapshot-tracked
// in pkg-parser.golden.
//
// Note on parser.Factory and parser.DeviceParserRegistry: both are concrete
// structs in pkg/parser, not interfaces, so there is no interface/impl pair to
// assert. Their exported method set is snapshot-tracked in pkg-parser.golden.
