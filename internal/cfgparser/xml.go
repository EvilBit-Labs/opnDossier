// Package cfgparser provides functionality to parse OPNsense configuration files.
package cfgparser

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/EvilBit-Labs/opnDossier/internal/validator"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// Parser size limits to prevent XML bomb attacks.
const (
	// DefaultMaxInputSize is the default maximum size in bytes for XML input to prevent XML bombs.
	DefaultMaxInputSize = 10 * 1024 * 1024 // 10MB
)

// ErrMissingOpnSenseDocumentRoot is returned when the XML document is missing the required opnsense root element.
var ErrMissingOpnSenseDocumentRoot = errors.New("invalid XML: missing opnsense root element")

// Parser is the interface for parsing OPNsense configuration files.
type Parser interface {
	Parse(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)

	Validate(cfg *schema.OpnSenseDocument) error
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

// Parse parses an OPNsense configuration file with security protections using streaming to minimize memory usage.
// The streaming approach processes XML tokens individually rather than loading the entire document into memory,
// providing better memory efficiency for large configuration files while maintaining security protections
// against XML bombs, XXE attacks, and excessive entity expansion.
// The context is checked periodically to support cancellation of long-running parse operations.
func (p *XMLParser) Parse(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error) {
	dec := parser.NewSecureXMLDecoder(r, p.MaxInputSize)
	// OPNsense-specific decoder settings for streaming token parsing.
	dec.DefaultSpace = ""
	dec.AutoClose = xml.HTMLAutoClose

	var doc schema.OpnSenseDocument
	for {
		// Check for context cancellation to support timeouts and cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

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
func handleStartElement(dec *xml.Decoder, doc *schema.OpnSenseDocument, se xml.StartElement) error {
	if se.Name.Local == "opnsense" {
		doc.XMLName = se.Name
		return nil
	}

	if doc.XMLName.Local == "" {
		return nil
	}

	switch se.Name.Local {
	case "version":
		return decodeChild(dec, &doc.Version, se)
	case "trigger_initial_wizard":
		return decodeChild(dec, &doc.TriggerInitialWizard, se)
	case "theme":
		return decodeChild(dec, &doc.Theme, se)
	case "system":
		return decodeChild(dec, &doc.System, se)
	case "interfaces":
		return decodeChild(dec, &doc.Interfaces, se)
	case "dhcpd":
		return decodeChild(dec, &doc.Dhcpd, se)
	case "sysctl":
		return decodeSysctl(dec, doc, se)
	case "unbound":
		return decodeChild(dec, &doc.Unbound, se)
	case "snmpd":
		return decodeChild(dec, &doc.Snmpd, se)
	case "nat":
		return decodeChild(dec, &doc.Nat, se)
	case "filter":
		return decodeChild(dec, &doc.Filter, se)
	case "rrd":
		return decodeChild(dec, &doc.Rrd, se)
	case "load_balancer":
		return decodeChild(dec, &doc.LoadBalancer, se)
	case "ntpd":
		return decodeChild(dec, &doc.Ntpd, se)
	case "widgets":
		return decodeChild(dec, &doc.Widgets, se)
	case "revision":
		return decodeChild(dec, &doc.Revision, se)
	case "gateways":
		return decodeChild(dec, &doc.Gateways, se)
	case "hasync":
		return decodeChild(dec, &doc.HighAvailabilitySync, se)
	case "ifgroups":
		return decodeChild(dec, &doc.InterfaceGroups, se)
	case "gifs":
		return decodeChild(dec, &doc.GIFInterfaces, se)
	case "gres":
		return decodeChild(dec, &doc.GREInterfaces, se)
	case "laggs":
		return decodeChild(dec, &doc.LAGGInterfaces, se)
	case "virtualip":
		return decodeChild(dec, &doc.VirtualIP, se)
	case "vlans":
		return decodeChild(dec, &doc.VLANs, se)
	case "openvpn":
		return decodeChild(dec, &doc.OpenVPN, se)
	case "staticroutes":
		return decodeChild(dec, &doc.StaticRoutes, se)
	case "bridges":
		return decodeChild(dec, &doc.Bridges, se)
	case "ppps":
		return decodeChild(dec, &doc.PPPInterfaces, se)
	case "wireless":
		return decodeChild(dec, &doc.Wireless, se)
	case "ca":
		var ca schema.CertificateAuthority
		if err := decodeChild(dec, &ca, se); err != nil {
			return err
		}
		doc.CAs = append(doc.CAs, ca)
		return nil
	case "dhcpdv6":
		return decodeChild(dec, &doc.DHCPv6Server, se)
	case "cert":
		var cert schema.Cert
		if err := decodeChild(dec, &cert, se); err != nil {
			return err
		}
		doc.Certs = append(doc.Certs, cert)
		return nil
	case "dnsmasq":
		return decodeChild(dec, &doc.DNSMasquerade, se)
	case "syslog":
		return decodeChild(dec, &doc.Syslog, se)
	case "OPNsense":
		return decodeChild(dec, &doc.OPNsense, se)
	default:
		return skipElement(dec)
	}
}

// decodeChild decodes a child element of <opnsense> into the target. Decode
// errors are annotated via [parser.WrapDecodeError] with the enclosing section
// path (e.g., "/opnsense/system") — not the leaf field that failed. Even so,
// the message is far more useful than a bare "strconv.ParseInt" with no
// context: the operator can narrow the offending field by grepping that
// section. Deeper path accuracy requires section-by-section decoding; tracked
// for follow-up.
func decodeChild(dec *xml.Decoder, target any, se xml.StartElement) error {
	return parser.WrapDecodeError(dec.DecodeElement(target, &se), "/opnsense/"+se.Name.Local)
}

// decodeSysctl handles the special sysctl section format.
func decodeSysctl(dec *xml.Decoder, doc *schema.OpnSenseDocument, se xml.StartElement) error {
	var container struct {
		Items []schema.SysctlItem `xml:"item"`
	}
	if err := dec.DecodeElement(&container, &se); err == nil {
		doc.Sysctl = append(doc.Sysctl, container.Items...)
	} else {
		// Skip non-standard direct format
		if err := skipElement(dec); err != nil {
			return fmt.Errorf("failed to skip sysctl element: %w", err)
		}
	}
	return nil
}

// Validate validates the given OPNsense configuration and returns an error if validation fails.
// Returns an AggregatedValidationError containing all validation failures with element paths.
func (p *XMLParser) Validate(cfg *schema.OpnSenseDocument) error {
	validationErrors := validator.ValidateOpnSenseDocument(cfg)
	if len(validationErrors) > 0 {
		return NewAggregatedValidationError(convertValidatorToParserValidationErrors(validationErrors))
	}

	return nil
}

// ParseAndValidate parses and validates the given OPNsense configuration from an io.Reader.
// Returns an error if parsing or validation fails.
func (p *XMLParser) ParseAndValidate(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error) {
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
