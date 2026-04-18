package parser_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // triggers init() self-registration
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"  // triggers init() self-registration
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validOPNsenseXML = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>test</hostname>
    <domain>test.local</domain>
    <webgui><protocol>https</protocol></webgui>
    <ssh><group>admins</group></ssh>
  </system>
</opnsense>`

func TestFactory_ValidOPNsense(t *testing.T) {
	t.Parallel()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
	assert.Equal(t, "test", device.System.Hostname)
	assert.Equal(t, "test.local", device.System.Domain)
}

func TestFactory_UnknownRootElement(t *testing.T) {
	t.Parallel()

	xml := `<?xml version="1.0"?><unknowndevice><system><hostname>test</hostname></system></unknowndevice>`
	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(xml),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported device type")
	assert.Contains(t, err.Error(), "unknowndevice")
	assert.Contains(t, err.Error(), "supported:")
	assert.Contains(t, err.Error(), "opnsense")
	assert.Contains(t, err.Error(), "pfsense")
}

func TestFactory_Override_OPNsense(t *testing.T) {
	t.Parallel()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		common.DeviceTypeOPNsense,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
}

func TestFactory_Override_CaseInsensitive(t *testing.T) {
	t.Parallel()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		common.ParseDeviceType("OPNsense"),
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
}

func TestFactory_Override_Unsupported(t *testing.T) {
	t.Parallel()

	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		common.DeviceType("unsupported_device"),
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported device type override")
	assert.Contains(t, err.Error(), "unsupported_device")
	assert.Contains(t, err.Error(), "supported:")
	assert.Contains(t, err.Error(), "opnsense")
}

func TestFactory_EmptyReader(t *testing.T) {
	t.Parallel()

	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(""),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root XML element found")
}

func TestFactory_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		ctx,
		strings.NewReader(validOPNsenseXML),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
}

func TestFactory_ContextCancelled_BlockingReader(t *testing.T) {
	t.Parallel()

	// io.Pipe blocks Read until data is written; we never write, so the
	// XML decoder would block forever without context-aware reads.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(ctx, pr, common.DeviceTypeUnknown, false)
		done <- err
	}()

	// Cancel after a short delay to ensure the goroutine is blocked in Read.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("CreateDevice did not return after context cancellation; blocked on reader")
	}
}

func TestFactory_MalformedXML(t *testing.T) {
	t.Parallel()

	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader("<<<not xml at all"),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root XML element found")
}

func TestFactory_ErrorWrapsOriginal(t *testing.T) {
	t.Parallel()

	// Empty input causes io.EOF from the decoder, which should be wrapped.
	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(""),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, io.EOF, "original decoder error should be wrapped")
}

// TestFactory_EmptyRegistry_HintSurfaced verifies that when a Factory is
// constructed with an isolated, empty registry (no blank imports have run),
// the error surfaced to callers contains the actionable hint telling end
// users to import parser packages. The assertion pins the stable substring
// "ensure parser packages are imported" — the wider hint string may be
// refined, but this substring must continue to appear in the CLI error so
// consumers who forget the blank imports get a fixable signal.
func TestFactory_EmptyRegistry_HintSurfaced(t *testing.T) {
	t.Parallel()

	emptyReg := parser.NewDeviceParserRegistry()
	factory := parser.NewFactoryWithRegistry(cfgparser.NewXMLParser(), emptyReg)

	t.Run("auto-detect path", func(t *testing.T) {
		t.Parallel()

		_, _, err := factory.CreateDevice(
			context.Background(),
			strings.NewReader(validOPNsenseXML),
			common.DeviceTypeUnknown,
			false,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported device type")
		assert.Contains(t, err.Error(), "ensure parser packages are imported")
	})

	t.Run("override path", func(t *testing.T) {
		t.Parallel()

		_, _, err := factory.CreateDevice(
			context.Background(),
			strings.NewReader(validOPNsenseXML),
			common.DeviceTypeOPNsense,
			false,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported device type override")
		assert.Contains(t, err.Error(), "ensure parser packages are imported")
	})
}

func TestFactory_UnsupportedCharset(t *testing.T) {
	t.Parallel()

	// XML with a charset the parser doesn't accept.
	xmlData := `<?xml version="1.0" encoding="EBCDIC"?><opnsense/>`
	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(xmlData),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported XML charset")
}

func TestFactory_AcceptedCharsets(t *testing.T) {
	t.Parallel()

	charsets := []string{"US-ASCII", "ISO-8859-1", "Latin-1", "UTF-8"}
	for _, charset := range charsets {
		t.Run(charset, func(t *testing.T) {
			t.Parallel()

			xmlData := `<?xml version="1.0" encoding="` + charset + `"?>` + "\n" +
				`<opnsense><system><hostname>test</hostname><domain>test.local</domain></system></opnsense>`
			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(),
				strings.NewReader(xmlData),
				common.DeviceTypeUnknown,
				false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)
			assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
		})
	}
}

func TestFactory_LargeInput_BoundedRead(t *testing.T) {
	t.Parallel()

	// Build input that exceeds the default max input size without a root element.
	// The decoder should stop at the limit and return an error.
	bigInput := strings.Repeat("<!-- padding -->", int(cfgparser.DefaultMaxInputSize)/15+1)
	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(bigInput),
		common.DeviceTypeUnknown,
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root XML element found")
}

// semanticOnlyInvalidXML is structurally valid XML but will fail semantic
// validation (e.g., validator checks for required fields like hostname).
const semanticOnlyInvalidXML = `<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname></hostname>
    <domain></domain>
  </system>
</opnsense>`

func TestFactory_ValidateMode_False_SemanticErrorsIgnored(t *testing.T) {
	t.Parallel()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(semanticOnlyInvalidXML),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
}

func TestFactory_ValidateMode_True_SemanticErrorsFail(t *testing.T) {
	t.Parallel()

	_, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(semanticOnlyInvalidXML),
		common.DeviceTypeUnknown,
		true,
	)
	require.Error(t, err)

	var aggErr *cfgparser.AggregatedValidationError
	assert.ErrorAs(t, err, &aggErr, "expected an AggregatedValidationError, got: %v", err)
}

// --- pfSense factory tests ---

const validPfSenseXML = `<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>pf-test</hostname>
    <domain>pf.local</domain>
  </system>
</pfsense>`

func TestFactory_ValidPfSense(t *testing.T) {
	t.Parallel()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(validPfSenseXML),
		common.DeviceTypeUnknown,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
	assert.Equal(t, "pf-test", device.System.Hostname)
	assert.Equal(t, "pf.local", device.System.Domain)
}

func TestFactory_Override_PfSense(t *testing.T) {
	t.Parallel()

	device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
		context.Background(),
		strings.NewReader(validPfSenseXML),
		common.DeviceTypePfSense,
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
}

func TestFactory_PfSense_AcceptedCharsets(t *testing.T) {
	t.Parallel()

	charsets := []string{"US-ASCII", "ISO-8859-1", "Latin-1", "UTF-8"}
	for _, charset := range charsets {
		t.Run(charset, func(t *testing.T) {
			t.Parallel()

			xmlData := `<?xml version="1.0" encoding="` + charset + `"?>` + "\n" +
				`<pfsense><system><hostname>test</hostname><domain>test.local</domain></system></pfsense>`
			device, _, err := parser.NewFactory(cfgparser.NewXMLParser()).CreateDevice(
				context.Background(),
				strings.NewReader(xmlData),
				common.DeviceTypeUnknown,
				false,
			)
			require.NoError(t, err)
			require.NotNil(t, device)
			assert.Equal(t, common.DeviceTypePfSense, device.DeviceType)
		})
	}
}
