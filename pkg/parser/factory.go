package parser

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	schema "github.com/EvilBit-Labs/opnDossier/pkg/schema/opnsense"
)

// DefaultMaxInputSize is the default maximum size in bytes for XML input.
// This prevents XML bomb attacks by limiting how much data is read during
// root-element detection and parsing.
const DefaultMaxInputSize = 10 * 1024 * 1024 // 10MB

// XMLDecoder parses raw XML input into an OpnSenseDocument. Implementations
// must handle charset detection, entity expansion protection, and input size
// limits. The cfgparser.XMLParser in internal/cfgparser provides the default
// implementation used by the CLI.
type XMLDecoder interface {
	// Parse reads XML from r and returns a parsed OpnSenseDocument.
	Parse(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
	// ParseAndValidate reads XML from r, parses it, and applies semantic validation.
	ParseAndValidate(ctx context.Context, r io.Reader) (*schema.OpnSenseDocument, error)
}

// DeviceParser is the interface for device-specific parsers.
// Implementations return non-fatal conversion warnings alongside the parsed
// device model. Callers should log or surface these warnings without treating
// them as errors.
type DeviceParser interface {
	// Parse reads and converts the configuration, returning non-fatal conversion warnings.
	Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
	// ParseAndValidate reads, converts, and validates the configuration, returning non-fatal conversion warnings.
	ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
}

// Factory detects device type and delegates to the appropriate DeviceParser.
// The XMLDecoder is injected at construction to keep pkg/ free of internal/
// imports. The registry defaults to DefaultRegistry() unless overridden via
// NewFactoryWithRegistry (e.g., for isolated tests).
type Factory struct {
	xmlDecoder XMLDecoder
	registry   *DeviceParserRegistry
}

// NewFactory returns a new Factory that uses the given XMLDecoder for parsing
// and the global DefaultRegistry() for parser lookup.
// Pass cfgparser.NewXMLParser() from internal/cfgparser at the call site.
func NewFactory(decoder XMLDecoder) *Factory {
	if decoder == nil {
		panic("parser: NewFactory requires a non-nil XMLDecoder")
	}

	return &Factory{xmlDecoder: decoder, registry: DefaultRegistry()}
}

// NewFactoryWithRegistry returns a Factory that uses a custom registry instead
// of the global singleton. This is primarily useful for tests that need
// isolated registry state without polluting the global registry.
func NewFactoryWithRegistry(decoder XMLDecoder, reg *DeviceParserRegistry) *Factory {
	if decoder == nil {
		panic("parser: NewFactoryWithRegistry requires a non-nil XMLDecoder")
	}

	if reg == nil {
		panic("parser: NewFactoryWithRegistry requires a non-nil DeviceParserRegistry")
	}

	return &Factory{xmlDecoder: decoder, registry: reg}
}

// ensureInitialized validates that the Factory has been constructed correctly.
// It returns a descriptive error instead of allowing nil-pointer dereferences
// when a zero-valued Factory is used without going through NewFactory.
func (f *Factory) ensureInitialized() error {
	if f == nil {
		return errors.New("parser: Factory is nil; use parser.NewFactory to construct a Factory")
	}

	if f.xmlDecoder == nil {
		return errors.New("parser: Factory has nil XMLDecoder; use parser.NewFactory to construct a Factory")
	}

	if f.registry == nil {
		return errors.New(
			"parser: Factory has nil DeviceParserRegistry; use parser.NewFactory or parser.NewFactoryWithRegistry to construct a Factory",
		)
	}

	return nil
}

// CreateDevice reads from r, detects (or uses the override) device type, and
// returns a fully converted CommonDevice along with any non-fatal conversion
// warnings. When validateMode is true, semantic validation is applied in
// addition to structural parsing.
func (f *Factory) CreateDevice(
	ctx context.Context,
	r io.Reader,
	deviceTypeOverride common.DeviceType,
	validateMode bool,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	if err := f.ensureInitialized(); err != nil {
		return nil, nil, err
	}

	if deviceTypeOverride != "" && deviceTypeOverride != common.DeviceTypeUnknown {
		return f.createWithOverride(ctx, r, deviceTypeOverride, validateMode)
	}

	return f.createWithAutoDetect(ctx, r, validateMode)
}

// createWithOverride skips root-element detection and directly delegates to the
// parser matching deviceTypeOverride.
func (f *Factory) createWithOverride(
	ctx context.Context,
	r io.Reader,
	override common.DeviceType,
	validateMode bool,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	fn, ok := f.registry.Get(override.String())
	if !ok {
		return nil, nil, fmt.Errorf(
			"unsupported device type override: %q; supported: %s",
			override, f.registry.SupportedDevices(),
		)
	}

	return parseDevice(ctx, fn(f.xmlDecoder), r, validateMode)
}

// createWithAutoDetect peeks the XML root element using a bounded, context-aware
// reader and delegates to the matching parser.
func (f *Factory) createWithAutoDetect(
	ctx context.Context,
	r io.Reader,
	validateMode bool,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	rootElem, fullReader, err := peekRootElementBounded(ctx, r)
	if err != nil {
		return nil, nil, err
	}

	fn, ok := f.registry.Get(rootElem)
	if !ok {
		return nil, nil, fmt.Errorf(
			"unsupported device type: root element <%s> is not recognized; supported: %s",
			rootElem, f.registry.SupportedDevices(),
		)
	}

	return parseDevice(ctx, fn(f.xmlDecoder), fullReader, validateMode)
}

// parseDevice delegates to the parser's Parse or ParseAndValidate method based
// on validateMode.
func parseDevice(
	ctx context.Context,
	p DeviceParser,
	r io.Reader,
	validateMode bool,
) (*common.CommonDevice, []common.ConversionWarning, error) {
	if validateMode {
		return p.ParseAndValidate(ctx, r)
	}

	return p.Parse(ctx, r)
}

// peekResult holds the outcome of the root-element detection goroutine.
type peekResult struct {
	name string
	err  error
}

// peekRootElementBounded reads just enough of r to find the first XML start
// element, using a bounded LimitReader (capped at DefaultMaxInputSize) and a
// TeeReader to buffer consumed bytes. It returns the root element name, a
// reader that replays the buffered bytes followed by the remainder of r, and
// any error. The decode loop runs in a single goroutine so the caller can
// select on ctx.Done() to abort when the reader blocks. The reader is wrapped
// in a ctxReader so the goroutine exits promptly after context cancellation.
func peekRootElementBounded(ctx context.Context, r io.Reader) (string, io.Reader, error) {
	var buf bytes.Buffer

	limited := io.LimitReader(newCtxReader(ctx, r), DefaultMaxInputSize)
	tee := io.TeeReader(limited, &buf)
	dec := xml.NewDecoder(tee)
	dec.CharsetReader = simpleCharsetReader

	ch := make(chan peekResult, 1)

	go func() {
		for {
			tok, err := dec.Token()
			if err != nil {
				ch <- peekResult{err: fmt.Errorf("unsupported device type: no root XML element found: %w", err)}
				return
			}

			if se, ok := tok.(xml.StartElement); ok {
				ch <- peekResult{name: se.Name.Local}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return "", nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return "", nil, res.err
		}

		fullReader := io.MultiReader(bytes.NewReader(buf.Bytes()), r)
		return res.name, fullReader, nil
	}
}

// readerFunc adapts a function to the io.Reader interface.
type readerFunc func(p []byte) (int, error)

// Read delegates to the underlying function, satisfying the io.Reader interface.
func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// newCtxReader wraps an io.Reader so that each Read call checks ctx for
// cancellation before delegating. This ensures goroutines reading from the
// returned reader exit promptly after context cancellation.
func newCtxReader(ctx context.Context, r io.Reader) io.Reader {
	return readerFunc(func(p []byte) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		return r.Read(p)
	})
}

// simpleCharsetReader handles common XML charset declarations for root-element
// detection. Only charsets whose ASCII subset matches UTF-8 are accepted, which
// is sufficient because XML element names use only ASCII-range characters.
func simpleCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "us-ascii", "iso-8859-1", "latin-1", "utf-8":
		return input, nil
	default:
		return nil, fmt.Errorf("unsupported XML charset: %s", charset)
	}
}
