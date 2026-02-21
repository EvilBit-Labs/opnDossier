// Package opnsense provides an OPNsense-specific parser and converter that
// transforms schema.OpnSenseDocument into the platform-agnostic CommonDevice.
package opnsense

import (
	"context"
	"fmt"
	"io"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/schema"
)

// Parser wraps cfgparser.XMLParser and implements the DeviceParser interface
// for OPNsense configuration files.
type Parser struct {
	xmlParser *cfgparser.XMLParser
}

// NewParser returns a new OPNsense Parser backed by the default XMLParser.
func NewParser() *Parser {
	return &Parser{
		xmlParser: cfgparser.NewXMLParser(),
	}
}

// Parse reads an OPNsense XML configuration from r (structural parsing only,
// no semantic validation) and returns a platform-agnostic CommonDevice.
func (p *Parser) Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, error) {
	doc, err := p.xmlParser.Parse(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("opnsense parser: %w", err)
	}

	return toCommonDevice(doc)
}

// ParseAndValidate reads an OPNsense XML configuration from r, runs both
// structural parsing and semantic validation, and returns a platform-agnostic
// CommonDevice.
func (p *Parser) ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, error) {
	doc, err := p.xmlParser.ParseAndValidate(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("opnsense parser: %w", err)
	}

	return toCommonDevice(doc)
}

// toCommonDevice converts a parsed OPNsense document into a CommonDevice.
func toCommonDevice(doc *schema.OpnSenseDocument) (*common.CommonDevice, error) {
	device, err := NewConverter().ToCommonDevice(doc)
	if err != nil {
		return nil, fmt.Errorf("opnsense parser: %w", err)
	}

	return device, nil
}
