package converter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	_ "github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense" // self-registers OPNsense parser via init()
	"github.com/stretchr/testify/require"
)

// TestGenerate_Markdown_MarksNegatedEndpointFromXML drives a config with a
// negated destination through parse and convert to the firewall rules table.
// The struct-built table tests cannot see a converter that stops setting
// Negated (GOTCHAS §3.4).
func TestGenerate_Markdown_MarksNegatedEndpointFromXML(t *testing.T) {
	t.Parallel()

	xmlData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "opnsense-mvc-rules.xml"))
	require.NoError(t, err)

	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(string(xmlData)),
		common.DeviceTypeOPNsense,
		false,
	)
	require.NoError(t, err)

	gen := newTestGenerator(t)
	result, err := gen.Generate(context.Background(), device, DefaultOptions())
	require.NoError(t, err)

	require.Contains(
		t,
		result,
		"| !192.168.0.0/16 |",
		"negated destination must carry the marker in the firewall rules table",
	)
	require.NotContains(t, result, "| 192.168.0.0/16 |", "the negated destination must not also be listed bare")
}
