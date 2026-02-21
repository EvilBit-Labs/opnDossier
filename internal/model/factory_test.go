package model_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/EvilBit-Labs/opnDossier/internal/model/common"
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

	device, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		"",
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

	xml := `<?xml version="1.0"?><pfsense><system><hostname>test</hostname></system></pfsense>`
	_, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(xml),
		"",
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported device type")
	assert.Contains(t, err.Error(), "pfsense")
}

func TestFactory_Override_OPNsense(t *testing.T) {
	t.Parallel()

	device, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		"opnsense",
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
}

func TestFactory_Override_CaseInsensitive(t *testing.T) {
	t.Parallel()

	device, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		"OPNsense",
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, common.DeviceTypeOPNsense, device.DeviceType)
}

func TestFactory_Override_Unsupported(t *testing.T) {
	t.Parallel()

	_, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(validOPNsenseXML),
		"pfsense",
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported device type override")
	assert.Contains(t, err.Error(), "pfsense")
}

func TestFactory_EmptyReader(t *testing.T) {
	t.Parallel()

	_, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(""),
		"",
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root XML element found")
}

func TestFactory_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := model.NewParserFactory().CreateDevice(
		ctx,
		strings.NewReader(validOPNsenseXML),
		"",
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
		_, err := model.NewParserFactory().CreateDevice(ctx, pr, "", false)
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

	device, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(semanticOnlyInvalidXML),
		"",
		false,
	)
	require.NoError(t, err)
	require.NotNil(t, device)
}

func TestFactory_ValidateMode_True_SemanticErrorsFail(t *testing.T) {
	t.Parallel()

	_, err := model.NewParserFactory().CreateDevice(
		context.Background(),
		strings.NewReader(semanticOnlyInvalidXML),
		"",
		true,
	)
	require.Error(t, err)

	var aggErr *cfgparser.AggregatedValidationError
	assert.ErrorAs(t, err, &aggErr, "expected an AggregatedValidationError, got: %v", err)
}
