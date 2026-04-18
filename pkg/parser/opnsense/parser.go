// Package opnsense provides an OPNsense-specific parser and converter that
// transforms [schema.OpnSenseDocument] (pkg/schema/opnsense) into the
// platform-agnostic [common.CommonDevice] (pkg/model). The bracketed names
// match the import aliases used in this file.
//
// # Registration
//
// This package self-registers its [Parser] with the global
// [parser.DefaultRegistry] under the device type name "opnsense" from an
// init() function. Consumers that want the OPNsense parser available through
// [parser.Factory] must add a blank import:
//
//	import _ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
//
// See [parser] for the full registration contract.
//
// # Dependencies
//
// This package has no internal/ dependencies in production code; it depends
// only on other public pkg/ packages plus the standard library. The
// [parser.XMLDecoder] is injected at construction so this package can stay
// on the public pkg/ side of the import boundary while still using the
// internal/cfgparser decoder when wired from the CLI layer.
package opnsense

import (
	"context"
	"fmt"
	"io"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Parser implements the DeviceParser interface for OPNsense configuration
// files. The XML decoder is injected at construction to keep this package
// free of internal/ imports.
type Parser struct {
	decoder parser.XMLDecoder
}

// NewParser returns a new OPNsense Parser backed by the given XML decoder.
// The decoder is typically cfgparser.NewXMLParser(), wired at the application
// layer.
func NewParser(decoder parser.XMLDecoder) *Parser {
	return &Parser{decoder: decoder}
}

// Parse reads an OPNsense XML configuration from r (structural parsing only,
// no semantic validation) and returns a platform-agnostic CommonDevice along
// with any non-fatal conversion warnings.
func (p *Parser) Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
	doc, err := p.decoder.Parse(ctx, r)
	if err != nil {
		return nil, nil, fmt.Errorf("opnsense parser: %w", err)
	}

	return toCommonDevice(doc)
}

// ParseAndValidate reads an OPNsense XML configuration from r, runs both
// structural parsing and semantic validation, and returns a platform-agnostic
// CommonDevice along with any non-fatal conversion warnings.
func (p *Parser) ParseAndValidate(
	ctx context.Context,
	r io.Reader,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	doc, err := p.decoder.ParseAndValidate(ctx, r)
	if err != nil {
		return nil, nil, fmt.Errorf("opnsense parser: %w", err)
	}

	return toCommonDevice(doc)
}

// toCommonDevice converts a parsed OPNsense document into a CommonDevice.
func toCommonDevice(doc *schema.OpnSenseDocument) (*common.CommonDevice, []common.ConversionWarning, error) {
	device, warnings, err := newConverter().ToCommonDevice(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("opnsense parser: %w", err)
	}

	return device, warnings, nil
}

// NewParserFactory returns a new DeviceParser configured for OPNsense devices.
// It satisfies the factory function signature required by DeviceParserRegistry.
func NewParserFactory(decoder parser.XMLDecoder) parser.DeviceParser {
	return NewParser(decoder)
}

// init registers the OPNsense parser with the global DeviceParserRegistry
// so that Factory.CreateDevice can auto-detect <opnsense> root elements.
func init() {
	parser.Register("opnsense", NewParserFactory)
}
