// Package pfsense provides a pfSense-specific parser and converter that
// transforms pfsense.Document into the platform-agnostic CommonDevice.
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
// parsing, and returns a platform-agnostic CommonDevice along with any non-fatal
// conversion warnings.
// TODO: Wire semantic validation via cmd layer (similar to OPNsense cfgparser → validator).
func (p *Parser) ParseAndValidate(
	ctx context.Context,
	r io.Reader,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	return p.Parse(ctx, r)
}

// decode reads XML from r into a pfsense.Document with security hardening
// (input size limit, XXE protection, charset handling) via the shared
// parser.NewSecureXMLDecoder helper.
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
