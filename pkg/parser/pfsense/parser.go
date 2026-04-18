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
// [parser.XMLDecoder] because that interface returns
// *opnsense.OpnSenseDocument (pkg/schema/opnsense), which is incompatible
// with pfsense.Document. The XMLDecoder parameter on [NewParser] is
// accepted but ignored — it exists so that [NewParserFactory] (the function
// registered with [parser.DefaultRegistry]) matches the
// [parser.ConstructorFunc] signature. pfSense input is decoded internally
// with the shared security-hardened decoder from [parser.NewSecureXMLDecoder].
//
// # Validation injection
//
// Semantic validation lives in internal/validator, which pkg/ cannot import
// directly. [ValidateFunc] is the injection point: set it once at startup
// from cmd/ (or an equivalent composition root) to wire validation into
// [Parser.ParseAndValidate]. When [ValidateFunc] is nil, ParseAndValidate
// falls back to structural parsing only, which is the safe default for
// library consumers that do not want to couple to opnDossier's validator.
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

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/EvilBit-Labs/opnDossier/pkg/schema/pfsense"
)

// errMissingRoot is returned when the XML document lacks a <pfsense> root element.
var errMissingRoot = errors.New("invalid XML: missing pfsense root element")

// ValidateFunc is a function that validates a parsed pfSense document and
// returns an error if validation fails. Set this package-level variable from
// the cmd layer to inject internal/validator without violating pkg/ purity.
// When nil, ParseAndValidate falls back to structural parsing only.
//
//nolint:gochecknoglobals // injection point — set once at startup from cmd/
var ValidateFunc func(doc *pfsense.Document) error

// Parser implements the DeviceParser interface for pfSense configuration files.
// It manages its own XML decoding because the shared XMLDecoder returns
// *schema.OpnSenseDocument which is incompatible with pfsense.Document.
type Parser struct {
	maxInputSize int64
}

// NewParser returns a new pfSense Parser. The decoder parameter is accepted
// for compatibility with the ConstructorFunc signature but is not used because
// pfSense requires its own XML decoding pipeline.
func NewParser(_ parser.XMLDecoder) *Parser {
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
// along with any non-fatal conversion warnings. If ValidateFunc has not been
// set (e.g., by cmd/root.go), falls back to structural parsing only.
func (p *Parser) ParseAndValidate(
	ctx context.Context,
	r io.Reader,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	doc, err := p.decode(ctx, r)
	if err != nil {
		return nil, nil, fmt.Errorf("pfsense parser: %w", err)
	}

	if ValidateFunc != nil {
		if vErr := ValidateFunc(doc); vErr != nil {
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
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("XML decode: %w", err)
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
func NewParserFactory(decoder parser.XMLDecoder) parser.DeviceParser {
	return NewParser(decoder)
}

// init registers the pfSense parser with the global DeviceParserRegistry
// so that Factory.CreateDevice can auto-detect <pfsense> root elements.
func init() {
	parser.Register("pfsense", NewParserFactory)
}
