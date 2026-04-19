// Package pfsense provides a pfSense-specific parser and converter that
// transforms pfsense.Document (pkg/schema/pfsense, imported without an alias
// and therefore not usable as a doc-link target within this package) into the
// platform-agnostic [common.CommonDevice] (pkg/model). The bracketed name
// matches the import alias used in this file.
//
// # Registration
//
// This package self-registers its [Parser] with the global
// [parser.DefaultRegistry] under the device type name "pfsense" from an
// init() function. Consumers that want the pfSense parser available through
// [parser.Factory] must add a blank import:
//
//	import _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
//
// See [parser] for the full registration contract.
//
// # Self-managed XML decoding
//
// Unlike the OPNsense parser, this package does not use the injected
// [parser.OPNsenseXMLDecoder] because that interface returns
// *opnsense.OpnSenseDocument (pkg/schema/opnsense), which is incompatible
// with pfsense.Document. The OPNsenseXMLDecoder parameter on [NewParser] is
// accepted but ignored — it exists so that [NewParserFactory] (the function
// registered with [parser.DefaultRegistry]) matches the
// [parser.ConstructorFunc] signature. pfSense input is decoded internally
// with the shared security-hardened decoder from [parser.NewSecureXMLDecoder].
//
// # Validation injection
//
// Semantic validation lives in internal/validator, which pkg/ cannot import
// directly. [SetValidator] is the injection point: call it once at startup
// from cmd/ (or an equivalent composition root) to wire validation into
// [Parser.ParseAndValidate]. The installed validator is locked in by a
// [sync.Once] — subsequent calls are silently ignored, which prevents a
// dynamically loaded plugin's init() from overwriting the CLI-installed
// validator (see GOTCHAS.md §20). When no validator has been installed,
// ParseAndValidate falls back to structural parsing only, which is the safe
// default for library consumers that do not want to couple to opnDossier's
// validator.
//
// # Dependencies
//
// This package has no internal/ dependencies in production code; it depends
// only on other public pkg/ packages (pkg/model, pkg/parser, pkg/schema/pfsense,
// and pkg/schema/opnsense — the latter supplies shared DHCP/Unbound types
// reused by the converters) plus the standard library.
package pfsense

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// errMissingRoot is returned when the XML document lacks a <pfsense> root element.
var errMissingRoot = errors.New("invalid XML: missing pfsense root element")

// validateFuncType is the wire type stored inside validateFuncHolder. A named
// type is required because atomic.Pointer[T] wants a concrete T, not a
// function literal, and we need to store a heap-addressable value.
type validateFuncType func(doc *pfsense.Document) error

// validateFuncHolder holds the currently installed pfSense semantic validator,
// or a nil pointer when no validator has been installed. It is unexported so
// that dynamically loaded plugin init() code cannot reassign it (see GOTCHAS.md
// §20). Writes are gated by setValidatorOnce; reads happen from
// [Parser.ParseAndValidate]. The atomic.Pointer provides a data-race-free
// read/write channel between the write side (SetValidator) and the read side
// (ParseAndValidate, potentially running on many goroutines).
//
//nolint:gochecknoglobals // injection point — set once at startup via SetValidator
var validateFuncHolder atomic.Pointer[validateFuncType]

// setValidatorOnce ensures the validator is installed at most once per process.
// Subsequent SetValidator calls are silently ignored. This is the enforcement
// point that prevents a malicious dynamic plugin's init() from stomping the
// CLI-installed validator.
//
//nolint:gochecknoglobals // enforcement point paired with validateFuncHolder
var setValidatorOnce sync.Once

// SetValidator installs fn as the pfSense semantic validator used by
// [Parser.ParseAndValidate]. Only the first call per process has any effect;
// subsequent calls are silently ignored. This one-shot semantics is the
// enforcement point against a dynamically loaded plugin's init() stomping
// the CLI-installed validator (see GOTCHAS.md §20).
//
// Passing a nil fn locks the slot in the "no validator" state — equivalent
// to never calling SetValidator, except that future SetValidator calls are
// still ignored. [Parser.ParseAndValidate] falls back to structural parsing
// only when no validator is installed.
//
// SetValidator is safe to call from any goroutine; concurrent callers race
// to be the one the sync.Once picks, but only one wins and the others are
// silently dropped.
func SetValidator(fn func(doc *pfsense.Document) error) {
	setValidatorOnce.Do(func() {
		// Always store a non-nil pointer so later SetValidator calls can be
		// distinguished from the never-called state, even when fn is nil.
		// loadValidator dereferences the pointer and returns the (possibly
		// nil) function value, which ParseAndValidate nil-checks before
		// invoking.
		wrapped := validateFuncType(fn)
		validateFuncHolder.Store(&wrapped)
	})
}

// loadValidator returns the currently installed validator, or nil if none
// has been installed (or a nil fn was explicitly passed to SetValidator).
// Callers read the return value exactly once; the returned function is
// safe to invoke without additional synchronization.
func loadValidator() validateFuncType {
	p := validateFuncHolder.Load()
	if p == nil {
		return nil
	}
	return *p
}

// Parser implements the DeviceParser interface for pfSense configuration files.
// It manages its own XML decoding because the shared OPNsenseXMLDecoder returns
// *opnsense.OpnSenseDocument (pkg/schema/opnsense), which is incompatible with
// pfsense.Document.
type Parser struct {
	maxInputSize int64
}

// NewParser returns a new pfSense Parser. The decoder parameter is accepted
// for compatibility with the ConstructorFunc signature but is not used because
// pfSense requires its own XML decoding pipeline.
func NewParser(_ parser.OPNsenseXMLDecoder) *Parser {
	return &Parser{maxInputSize: parser.DefaultMaxInputSize}
}

// Parse reads a pfSense XML configuration from r (structural parsing only,
// no semantic validation) and returns a platform-agnostic CommonDevice along
// with any non-fatal conversion warnings.
func (p *Parser) Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
	doc, err := p.decode(ctx, r)
	if err != nil {
		return nil, nil, fmt.Errorf("pfsense parser: %w", err)
	}

	return toCommonDevice(doc)
}

// ParseAndValidate reads a pfSense XML configuration from r, runs structural
// parsing and semantic validation, and returns a platform-agnostic CommonDevice
// along with any non-fatal conversion warnings. If no validator has been
// installed via [SetValidator] (e.g., by cmd/root.go), falls back to
// structural parsing only.
func (p *Parser) ParseAndValidate(
	ctx context.Context,
	r io.Reader,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	doc, err := p.decode(ctx, r)
	if err != nil {
		return nil, nil, fmt.Errorf("pfsense parser: %w", err)
	}

	if v := loadValidator(); v != nil {
		if vErr := v(doc); vErr != nil {
			return nil, nil, fmt.Errorf("pfsense validation: %w", vErr)
		}
	}

	return toCommonDevice(doc)
}

// decode reads XML from r into a pfsense.Document with security hardening
// (input size limit, XXE protection, charset handling) via the shared
// parser.NewSecureXMLDecoder helper. Presence-based <enable/> elements are
// decoded directly into BoolFlag fields on pfsense.Interface and pfsense.DhcpdInterface.
func (p *Parser) decode(ctx context.Context, r io.Reader) (*pfsense.Document, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	dec := parser.NewSecureXMLDecoder(r, p.maxInputSize)

	var doc pfsense.Document
	if err := parser.WrapDecodeError(dec.Decode(&doc), "/pfsense"); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if doc.XMLName.Local == "" {
		return nil, errMissingRoot
	}

	return &doc, nil
}

// toCommonDevice converts a parsed pfSense document into a CommonDevice.
func toCommonDevice(doc *pfsense.Document) (*common.CommonDevice, []common.ConversionWarning, error) {
	device, warnings, err := newConverter().ToCommonDevice(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("pfsense parser: %w", err)
	}

	return device, warnings, nil
}

// NewParserFactory returns a new DeviceParser configured for pfSense devices.
// It satisfies the factory function signature required by DeviceParserRegistry.
func NewParserFactory(decoder parser.OPNsenseXMLDecoder) parser.DeviceParser {
	return NewParser(decoder)
}

// init registers the pfSense parser with the global DeviceParserRegistry
// so that Factory.CreateDevice can auto-detect <pfsense> root elements.
func init() {
	parser.Register("pfsense", NewParserFactory)
}
