package model

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
	"github.com/EvilBit-Labs/opnDossier/internal/model/opnsense"
)

// DeviceParser is the interface for device-specific parsers.
type DeviceParser interface {
	Parse(ctx context.Context, r io.Reader) (*common.CommonDevice, error)
	ParseAndValidate(ctx context.Context, r io.Reader) (*common.CommonDevice, error)
}

// ParserFactory detects device type and delegates to the appropriate DeviceParser.
type ParserFactory struct{}

// NewParserFactory returns a new ParserFactory.
func NewParserFactory() *ParserFactory {
	return &ParserFactory{}
}

// CreateDevice reads from r, detects (or uses the override) device type, and
// returns a fully converted CommonDevice. When validateMode is true, semantic
// validation is applied in addition to structural parsing.
func (f *ParserFactory) CreateDevice(
	ctx context.Context,
	r io.Reader,
	deviceTypeOverride string,
	validateMode bool,
) (*common.CommonDevice, error) {
	if deviceTypeOverride != "" {
		return f.createWithOverride(ctx, r, deviceTypeOverride, validateMode)
	}

	return f.createWithAutoDetect(ctx, r, validateMode)
}

// createWithOverride skips root-element detection and directly delegates to the
// parser matching deviceTypeOverride.
func (f *ParserFactory) createWithOverride(
	ctx context.Context,
	r io.Reader,
	override string,
	validateMode bool,
) (*common.CommonDevice, error) {
	if strings.EqualFold(override, "opnsense") {
		return parseDevice(ctx, opnsense.NewParser(), r, validateMode)
	}

	return nil, fmt.Errorf("unsupported device type override: %s; supported: opnsense", override)
}

// createWithAutoDetect peeks the XML root element using a bounded, context-aware
// reader and delegates to the matching parser.
func (f *ParserFactory) createWithAutoDetect(
	ctx context.Context,
	r io.Reader,
	validateMode bool,
) (*common.CommonDevice, error) {
	rootElem, fullReader, err := peekRootElementBounded(ctx, r)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(rootElem) {
	case "opnsense":
		return parseDevice(ctx, opnsense.NewParser(), fullReader, validateMode)
	default:
		return nil, fmt.Errorf(
			"unsupported device type: root element <%s> is not recognized; supported: opnsense",
			rootElem,
		)
	}
}

// parseDevice delegates to the parser's Parse or ParseAndValidate method based
// on validateMode.
func parseDevice(ctx context.Context, p DeviceParser, r io.Reader, validateMode bool) (*common.CommonDevice, error) {
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

	limited := io.LimitReader(newCtxReader(ctx, r), cfgparser.DefaultMaxInputSize)
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
// detection. Only known-safe charsets that are compatible with UTF-8 for
// element name detection are accepted.
func simpleCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "us-ascii", "iso-8859-1", "latin-1", "utf-8":
		return input, nil
	default:
		return nil, fmt.Errorf("unsupported XML charset: %s", charset)
	}
}
