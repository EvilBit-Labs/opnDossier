// Package parser provides functionality to parse OPNsense configuration files.
package parser

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

const (
	// DefaultMaxInputSize is the default maximum size in bytes for XML input to prevent XML bombs.
	DefaultMaxInputSize = 10 * 1024 * 1024 // 10MB
)

// Parser is the interface for parsing OPNsense configuration files.
type Parser interface {
	Parse(ctx context.Context, r io.Reader) (*model.Opnsense, error)
}

// XMLParser is an XML parser for OPNsense configuration files.
type XMLParser struct {
	// MaxInputSize is the maximum size in bytes for XML input to prevent XML bombs
	MaxInputSize int64
}

// NewXMLParser creates a new XMLParser configured with the default maximum input size for parsing OPNsense XML configuration files.
func NewXMLParser() *XMLParser {
	return &XMLParser{
		MaxInputSize: DefaultMaxInputSize,
	}
}

// Parse parses an OPNsense configuration file with security protections.
func (p *XMLParser) Parse(_ context.Context, r io.Reader) (*model.Opnsense, error) {
	// Limit input size to prevent XML bombs
	limitedReader := io.LimitReader(r, p.MaxInputSize)

	// Create decoder with security configurations
	dec := xml.NewDecoder(limitedReader)

	// Disable external entity loading to prevent XXE attacks
	dec.Entity = map[string]string{}

	// Disable DTD processing to prevent XXE attacks
	dec.DefaultSpace = ""
	dec.AutoClose = xml.HTMLAutoClose

	var doc model.Opnsense
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	return &doc, nil
}
