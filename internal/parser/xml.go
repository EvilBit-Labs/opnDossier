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

	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/validator"
)

const (
	// DefaultMaxInputSize is the default maximum size in bytes for XML input to prevent XML bombs.
	DefaultMaxInputSize = 10 * 1024 * 1024 // 10MB
)

// ErrMissingOpnSenseDocumentRoot is returned when the XML document is missing the required opnsense root element.
var ErrMissingOpnSenseDocumentRoot = errors.New("invalid XML: missing opnsense root element")

// Parser is the interface for parsing OPNsense configuration files.
type Parser interface {
	Parse(ctx context.Context, r io.Reader) (*model.OpnSenseDocument, error)

	Validate(cfg *model.OpnSenseDocument) error
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
func (p *XMLParser) Parse(_ context.Context, r io.Reader) (*model.OpnSenseDocument, error) {
	limitedReader := io.LimitReader(r, p.MaxInputSize)
	dec := xml.NewDecoder(limitedReader)
	dec.CharsetReader = charsetReader
	dec.Entity = map[string]string{}
	dec.DefaultSpace = ""
	dec.AutoClose = xml.HTMLAutoClose

	var doc model.OpnSenseDocument
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, handleXMLError(err, dec)
		}

		if startElem, ok := tok.(xml.StartElement); ok {
			if err := handleStartElement(dec, &doc, startElem); err != nil {
				return nil, err
			}
		}

		if endElem, ok := tok.(xml.EndElement); ok {
			if endElem.Name.Local == "opnsense" {
				break
			}
		}
	}

	if doc.XMLName.Local == "" {
		return nil, ErrMissingOpnSenseDocumentRoot
	}

	return &doc, nil
}

// handleXMLError processes XML syntax errors.
func handleXMLError(err error, dec *xml.Decoder) error {
	if wrappedErr := WrapXMLSyntaxErrorWithOffset(err, "opnsense", dec); wrappedErr != nil {
		return fmt.Errorf("failed to decode XML: %w", wrappedErr)
	}
	return fmt.Errorf("failed to read token: %w", err)
}

// handleStartElement processes XML StartElement tokens.
func handleStartElement(dec *xml.Decoder, doc *model.OpnSenseDocument, se xml.StartElement) error {
	if se.Name.Local == "opnsense" {
		doc.XMLName = se.Name
		return nil
	}

	if doc.XMLName.Local == "" {
		return nil
	}

	switch se.Name.Local {
	case "version":
		return decodeElement(dec, &doc.Version, se)
	case "trigger_initial_wizard":
		return decodeElement(dec, &doc.TriggerInitialWizard, se)
	case "theme":
		return decodeElement(dec, &doc.Theme, se)
	case "system":
		return decodeSection(dec, &doc.System, se)
	case "interfaces":
		return decodeSection(dec, &doc.Interfaces, se)
	case "dhcpd":
		return decodeSection(dec, &doc.Dhcpd, se)
	case "sysctl":
		return decodeSysctl(dec, doc, se)
	case "unbound":
		return decodeSection(dec, &doc.Unbound, se)
	case "snmpd":
		return decodeSection(dec, &doc.Snmpd, se)
	case "nat":
		return decodeSection(dec, &doc.Nat, se)
	case "filter":
		return decodeSection(dec, &doc.Filter, se)
	case "rrd":
		return decodeSection(dec, &doc.Rrd, se)
	case "load_balancer":
		return decodeSection(dec, &doc.LoadBalancer, se)
	case "ntpd":
		return decodeSection(dec, &doc.Ntpd, se)
	case "widgets":
		return decodeSection(dec, &doc.Widgets, se)
	case "revision":
		return decodeSection(dec, &doc.Revision, se)
	case "gateways":
		return decodeSection(dec, &doc.Gateways, se)
	case "hasync":
		return decodeSection(dec, &doc.HighAvailabilitySync, se)
	case "ifgroups":
		return decodeSection(dec, &doc.InterfaceGroups, se)
	case "gifs":
		return decodeSection(dec, &doc.GIFInterfaces, se)
	case "gres":
		return decodeSection(dec, &doc.GREInterfaces, se)
	case "laggs":
		return decodeSection(dec, &doc.LAGGInterfaces, se)
	case "virtualip":
		return decodeSection(dec, &doc.VirtualIP, se)
	case "vlans":
		return decodeSection(dec, &doc.VLANs, se)
	case "openvpn":
		return decodeSection(dec, &doc.OpenVPN, se)
	case "staticroutes":
		return decodeSection(dec, &doc.StaticRoutes, se)
	case "bridges":
		return decodeSection(dec, &doc.Bridges, se)
	case "ppps":
		return decodeSection(dec, &doc.PPPInterfaces, se)
	case "wireless":
		return decodeSection(dec, &doc.Wireless, se)
	case "ca":
		return decodeSection(dec, &doc.CertificateAuthority, se)
	case "dhcpdv6":
		return decodeSection(dec, &doc.DHCPv6Server, se)
	case "cert":
		return decodeSection(dec, &doc.Cert, se)
	case "dnsmasq":
		return decodeSection(dec, &doc.DNSMasquerade, se)
	case "syslog":
		return decodeSection(dec, &doc.Syslog, se)
	case "OPNsense":
		return decodeSection(dec, &doc.OPNsense, se)
	default:
		return skipElement(dec)
	}
}

// decodeElement decodes a simple element into the target.
func decodeElement(dec *xml.Decoder, target any, se xml.StartElement) error {
	return dec.DecodeElement(target, &se)
}

// decodeSection handles larger sections and triggers garbage collection.
func decodeSection(dec *xml.Decoder, target any, se xml.StartElement) error {
	if err := dec.DecodeElement(target, &se); err != nil {
		return err
	}
	runtime.GC()
	return nil
}

// decodeSysctl handles the special sysctl section format.
func decodeSysctl(dec *xml.Decoder, doc *model.OpnSenseDocument, se xml.StartElement) error {
	var container struct {
		Items []model.SysctlItem `xml:"item"`
	}
	if err := dec.DecodeElement(&container, &se); err == nil {
		doc.Sysctl = append(doc.Sysctl, container.Items...)
	} else {
		// Skip non-standard direct format
		if err := skipElement(dec); err != nil {
			return fmt.Errorf("failed to skip sysctl element: %w", err)
		}
	}
	runtime.GC()
	return nil
}

// Validate validates the given OPNsense configuration and returns an error if validation fails.
// Returns an AggregatedValidationError containing all validation failures with element paths.
func (p *XMLParser) Validate(cfg *model.OpnSenseDocument) error {
	validationErrors := validator.ValidateOpnSenseDocument(cfg)
	if len(validationErrors) > 0 {
		return NewAggregatedValidationError(convertValidatorToParserValidationErrors(validationErrors))
	}

	return nil
}

// ParseAndValidate parses and validates the given OPNsense configuration from an io.Reader.
// Returns an error if parsing or validation fails.
func (p *XMLParser) ParseAndValidate(ctx context.Context, r io.Reader) (*model.OpnSenseDocument, error) {
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
