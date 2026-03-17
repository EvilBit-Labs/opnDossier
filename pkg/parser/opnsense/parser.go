// Package opnsense provides an OPNsense-specific parser and converter that
// transforms schema.OpnSenseDocument into the platform-agnostic CommonDevice.
package opnsense

import (
	"context"
	"fmt"
	"io"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// xmlDecoder parses raw XML input into an OpnSenseDocument. This interface
// matches the contract defined by parser.XMLDecoder and is satisfied by
// cfgparser.XMLParser.
type xmlDecoder interface {
	Parse(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
	ParseAndValidate(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
}

// Parser implements the DeviceParser interface for OPNsense configuration
// files. The XML decoder is injected at construction to keep this package
// free of internal/ imports.
type Parser struct {
	decoder xmlDecoder
}

// NewParser returns a new OPNsense Parser backed by the given XML decoder.
// The decoder is typically cfgparser.NewXMLParser(), wired at the application
// layer.
func NewParser(decoder xmlDecoder) *Parser {
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
