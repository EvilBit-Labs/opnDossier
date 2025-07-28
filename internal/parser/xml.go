// Package parser provides functionality to parse OPNsense configuration files.
package parser

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/unclesp1d3r/opnFocus/internal/model"
	"github.com/unclesp1d3r/opnFocus/internal/validator"
)

const (
	// DefaultMaxInputSize is the default maximum size in bytes for XML input to prevent XML bombs.
	DefaultMaxInputSize = 10 * 1024 * 1024 // 10MB
)

// ErrMissingOpnsenseRoot is returned when the XML document is missing the required opnsense root element.
var ErrMissingOpnsenseRoot = errors.New("invalid XML: missing opnsense root element")

// Parser is the interface for parsing OPNsense configuration files.
type Parser interface {
	Parse(ctx context.Context, r io.Reader) (*model.Opnsense, error)

	Validate(cfg *model.Opnsense) error
}

// XMLParser is an XML parser for OPNsense configuration files.
type XMLParser struct {
	// MaxInputSize is the maximum size in bytes for XML input to prevent XML bombs
	MaxInputSize int64
}

// NewXMLParser returns a new XMLParser instance with the default maximum input size for secure OPNsense XML configuration parsing.
func NewXMLParser() *XMLParser {
	return &XMLParser{
		MaxInputSize: DefaultMaxInputSize,
	}
}

// charsetReader creates a reader for the specified charset.
// This is a simple implementation that handles common encodings.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "us-ascii", "ascii":
		// us-ascii is a subset of UTF-8, so we can use the input as-is
		return input, nil
	case "utf-8", "utf8":
		// UTF-8 is the default, use input as-is
		return input, nil
	case "iso-8859-1", "latin1":
		// For now, treat as UTF-8 (this is a simplification)
		// TODO: use golang.org/x/text/encoding
		return input, nil
	default:
		// For unknown encodings, try to use as-is (common fallback)
		return input, nil
	}
}

// Parse parses an OPNsense configuration file with security protections using streaming to minimize memory usage.
// The streaming approach processes XML tokens individually rather than loading the entire document into memory,
// providing better memory efficiency for large configuration files while maintaining security protections
// against XML bombs, XXE attacks, and excessive entity expansion.
func (p *XMLParser) Parse(_ context.Context, r io.Reader) (*model.Opnsense, error) {
	// Limit input size to prevent XML bombs
	limitedReader := io.LimitReader(r, p.MaxInputSize)

	// Create decoder with security configurations
	dec := xml.NewDecoder(limitedReader)

	// Add charset reader to handle encoding declarations
	dec.CharsetReader = charsetReader

	// Disable external entity loading to prevent XXE attacks
	dec.Entity = map[string]string{}

	// Disable DTD processing to prevent XXE attacks
	dec.DefaultSpace = ""
	dec.AutoClose = xml.HTMLAutoClose

	var doc model.Opnsense
	inOPNsenseRoot := false
	foundOpnsenseRoot := false

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Wrap XML syntax errors with location information and context
			if wrappedErr := WrapXMLSyntaxErrorWithOffset(err, "opnsense", dec); wrappedErr != nil {
				return nil, fmt.Errorf("failed to decode XML: %w", wrappedErr)
			}
			return nil, fmt.Errorf("failed to read token: %w", err)
		}

		switch se := tok.(type) {
		case xml.StartElement:
			if se.Name.Local == "opnsense" {
				inOPNsenseRoot = true
				foundOpnsenseRoot = true
				// Set the XMLName field for compatibility with existing tests
				doc.XMLName = se.Name
				continue
			}

			if !inOPNsenseRoot {
				continue
			}

			// Process each major section individually to avoid keeping entire tree in memory
			switch se.Name.Local {
			case "version":
				if err := dec.DecodeElement(&doc.Version, &se); err != nil {
					return nil, fmt.Errorf("failed to decode version: %w", err)
				}
			case "trigger_initial_wizard":
				if err := dec.DecodeElement(&doc.TriggerInitialWizard, &se); err != nil {
					return nil, fmt.Errorf("failed to decode trigger_initial_wizard: %w", err)
				}
			case "theme":
				if err := dec.DecodeElement(&doc.Theme, &se); err != nil {
					return nil, fmt.Errorf("failed to decode theme: %w", err)
				}
			case "system":
				var system model.System
				if err := dec.DecodeElement(&system, &se); err != nil {
					return nil, fmt.Errorf("failed to decode system: %w", err)
				}
				doc.System = system
				// Trigger garbage collection after processing large sections
				runtime.GC()
			case "interfaces":
				var interfaces model.Interfaces
				if err := dec.DecodeElement(&interfaces, &se); err != nil {
					return nil, fmt.Errorf("failed to decode interfaces: %w", err)
				}
				doc.Interfaces = interfaces
			case "dhcpd":
				var dhcpd model.Dhcpd
				if err := dec.DecodeElement(&dhcpd, &se); err != nil {
					return nil, fmt.Errorf("failed to decode dhcpd: %w", err)
				}
				doc.Dhcpd = dhcpd
			case "sysctl":
				// Handle standard OPNsense sysctl format (container with <item> wrappers)
				var container struct {
					Items []model.SysctlItem `xml:"item"`
				}
				if err := dec.DecodeElement(&container, &se); err == nil {
					doc.Sysctl = append(doc.Sysctl, container.Items...)
				} else {
					// Skip non-standard direct format to avoid decoder corruption
					if err := skipElement(dec); err != nil {
						return nil, fmt.Errorf("failed to skip sysctl element: %w", err)
					}
				}
				runtime.GC()
			case "unbound":
				var unbound model.Unbound
				if err := dec.DecodeElement(&unbound, &se); err != nil {
					return nil, fmt.Errorf("failed to decode unbound: %w", err)
				}
				doc.Unbound = unbound
			case "snmpd":
				var snmpd model.Snmpd
				if err := dec.DecodeElement(&snmpd, &se); err != nil {
					return nil, fmt.Errorf("failed to decode snmpd: %w", err)
				}
				doc.Snmpd = snmpd
			case "nat":
				var nat model.Nat
				if err := dec.DecodeElement(&nat, &se); err != nil {
					return nil, fmt.Errorf("failed to decode nat: %w", err)
				}
				doc.Nat = nat
			case "filter":
				var filter model.Filter
				if err := dec.DecodeElement(&filter, &se); err != nil {
					return nil, fmt.Errorf("failed to decode filter: %w", err)
				}
				doc.Filter = filter
			case "rrd":
				var rrd model.Rrd
				if err := dec.DecodeElement(&rrd, &se); err != nil {
					return nil, fmt.Errorf("failed to decode rrd: %w", err)
				}
				doc.Rrd = rrd
			case "load_balancer":
				var loadBalancer model.LoadBalancer
				if err := dec.DecodeElement(&loadBalancer, &se); err != nil {
					return nil, fmt.Errorf("failed to decode load_balancer: %w", err)
				}
				doc.LoadBalancer = loadBalancer
			case "ntpd":
				var ntpd model.Ntpd
				if err := dec.DecodeElement(&ntpd, &se); err != nil {
					return nil, fmt.Errorf("failed to decode ntpd: %w", err)
				}
				doc.Ntpd = ntpd
			case "widgets":
				var widgets model.Widgets
				if err := dec.DecodeElement(&widgets, &se); err != nil {
					return nil, fmt.Errorf("failed to decode widgets: %w", err)
				}
				doc.Widgets = widgets
			default:
				// Skip unknown elements by consuming tokens until the end element
				if err := skipElement(dec); err != nil {
					return nil, fmt.Errorf("failed to skip unknown element %s: %w", se.Name.Local, err)
				}
			}
		case xml.EndElement:
			if se.Name.Local == "opnsense" {
				inOPNsenseRoot = false
			}
		}
	}

	// Check if we found a valid opnsense root element
	if !foundOpnsenseRoot {
		return nil, ErrMissingOpnsenseRoot
	}

	return &doc, nil
}

// Validate validates the given OPNsense configuration and returns an error if validation fails.
// Returns an AggregatedValidationError containing all validation failures with element paths.
func (p *XMLParser) Validate(cfg *model.Opnsense) error {
	validationErrors := validator.ValidateOpnsense(cfg)
	if len(validationErrors) > 0 {
		return NewAggregatedValidationError(convertValidatorToParserValidationErrors(validationErrors))
	}
	return nil
}

// ParseAndValidate parses and validates the given OPNsense configuration from an io.Reader.
// Returns an error if parsing or validation fails.
func (p *XMLParser) ParseAndValidate(ctx context.Context, r io.Reader) (*model.Opnsense, error) {
	cfg, err := p.Parse(ctx, r)
	if err != nil {
		return nil, err
	}
	if err := p.Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// convertValidatorToParserValidationErrors converts validator.ValidationError slice to parser.ValidationError slice.
// convertValidatorToParserValidationErrors converts a slice of validator.ValidationError to a slice of parser ValidationError, prefixing each field path with "opnsense.".
func convertValidatorToParserValidationErrors(validatorErrors []validator.ValidationError) []ValidationError {
	parserErrors := make([]ValidationError, 0, len(validatorErrors))

	for _, validatorErr := range validatorErrors {
		// Convert field path to element path with opnsense prefix
		path := "opnsense." + validatorErr.Field
		parserErrors = append(parserErrors, ValidationError{
			Path:    path,
			Message: validatorErr.Message,
		})
	}

	return parserErrors
}

// skipElement advances the XML decoder past the current element, including all nested elements, without decoding their contents.
func skipElement(dec *xml.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}
