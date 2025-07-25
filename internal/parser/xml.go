// Package parser provides functionality to parse OPNsense configuration files.
package parser

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// Parser is the interface for parsing OPNsense configuration files.
type Parser interface {
	Parse(r io.Reader) (*model.Opnsense, error)
}

// XMLParser is an XML parser for OPNsense configuration files.
type XMLParser struct{}

// NewXMLParser returns a new instance of XMLParser for parsing OPNsense XML configuration files.
func NewXMLParser() *XMLParser {
	return &XMLParser{}
}

// Parse parses an OPNsense configuration file.
func (p *XMLParser) Parse(r io.Reader) (*model.Opnsense, error) {
	dec := xml.NewDecoder(r)

	var doc model.Opnsense
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	return &doc, nil
}
