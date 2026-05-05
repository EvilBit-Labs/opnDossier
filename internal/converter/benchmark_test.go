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
)

func BenchmarkMarkdownConverter_ToMarkdown(b *testing.B) {
	// Load a medium-sized config.xml for realistic testing
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.1.xml")

	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		b.Fatalf("Failed to read testdata XML file: %v", err)
	}

	// Parse using the parser factory
	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(string(xmlData)),
		common.DeviceTypeUnknown,
		false,
	)
	if err != nil {
		b.Fatalf("XML parsing failed: %v", err)
	}

	converter := NewMarkdownConverter()
	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		_, err := converter.ToMarkdown(ctx, device)
		if err != nil {
			b.Fatalf("ToMarkdown failed: %v", err)
		}
	}
}

// BenchmarkMultiFormatExport measures the per-format cost of preparing a single
// device for multiple output formats (markdown + JSON + YAML, sequential). Two
// variant pairs run side-by-side:
//
//   - Generate_Recompute / Generate_Enriched: realistic CLI workload —
//     full Generate() per format including markdown rendering and JSON/YAML
//     marshaling. _Recompute is the pre-memoization baseline (no
//     EnrichForExport); _Enriched calls EnrichForExport before the format loop.
//   - Prepare_Recompute / Prepare_Enriched: bare prepareForExport calls only,
//     isolating the analysis cost from rendering and serialization noise.
//
// The benchmark uses both a medium config (sample.config.2.xml, ~17KB) and the
// large config (sample.config.6.xml, ~119KB) so reviewers can see how the
// memoization win scales with input size — small configs amortize too quickly
// for the difference to be measurable.
func BenchmarkMultiFormatExport(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"Medium", filepath.Join("..", "..", "testdata", "sample.config.2.xml")},
		{"Large", filepath.Join("..", "..", "testdata", "sample.config.6.xml")},
	}

	formats := []Format{FormatMarkdown, FormatJSON, FormatYAML}

	for _, tc := range cases {
		xmlData, err := os.ReadFile(tc.path)
		if err != nil {
			b.Fatalf("Failed to read %s: %v", tc.path, err)
		}
		factory := parser.NewFactory(cfgparser.NewXMLParser())
		device, _, err := factory.CreateDevice(
			context.Background(),
			strings.NewReader(string(xmlData)),
			common.DeviceTypeUnknown,
			false,
		)
		if err != nil {
			b.Fatalf("XML parsing failed for %s: %v", tc.path, err)
		}

		// Precondition: the parsed device must start with nil enrichment fields
		// so the _Recompute variants genuinely re-run analysis on each call. If
		// a future parser change pre-populates these, both _Recompute and
		// _Enriched sub-benchmarks would silently degenerate to the same
		// workload and the speedup signal would vanish without a test failure.
		if device.Statistics != nil || device.Analysis != nil {
			b.Fatalf("benchmark precondition violated: parsed device must have nil Statistics/Analysis")
		}

		gen, err := NewMarkdownGenerator(nil, Options{})
		if err != nil {
			b.Fatalf("NewMarkdownGenerator failed: %v", err)
		}
		ctx := context.Background()

		// Headline sub-benchmarks: realistic multi-format CLI workload, including
		// markdown rendering and JSON/YAML marshaling.
		b.Run(tc.name+"/Generate_Recompute", runMultiFormatGenerate(ctx, gen, device, formats, false))
		b.Run(tc.name+"/Generate_Enriched", runMultiFormatGenerate(ctx, gen, device, formats, true))

		// Bare prepareForExport sub-benchmarks: isolate the analysis cost from
		// rendering and marshaling, so the memoization savings are visible
		// without serialization noise diluting the signal.
		b.Run(tc.name+"/Prepare_Recompute", runMultiFormatPrepare(device, formats, false, false))
		b.Run(tc.name+"/Prepare_Enriched", runMultiFormatPrepare(device, formats, true, false))
		// Redact-path variant on the memoized prepare: surfaces the clone-on-write
		// cost in redactStatisticsServiceDetails (Statistics + ServiceDetails +
		// Details map) on the production audit/export path.
		b.Run(tc.name+"/Prepare_Enriched_Redact", runMultiFormatPrepare(device, formats, true, true))
	}
}

func runMultiFormatGenerate(
	ctx context.Context,
	gen Generator,
	device *common.CommonDevice,
	formats []Format,
	preEnrich bool,
) func(*testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			d := *device
			if preEnrich {
				EnrichForExport(&d)
			}
			for _, f := range formats {
				opts := DefaultOptions()
				opts.Format = f
				if _, err := gen.Generate(ctx, &d, opts); err != nil {
					b.Fatalf("Generate %s failed: %v", f, err)
				}
			}
		}
	}
}

func runMultiFormatPrepare(device *common.CommonDevice, formats []Format, preEnrich, redact bool) func(*testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			d := *device
			if preEnrich {
				EnrichForExport(&d)
			}
			for range formats {
				_ = prepareForExport(&d, redact)
			}
		}
	}
}

func BenchmarkMarkdownConverter_ToMarkdown_Large(b *testing.B) {
	// Use the larger sample config for stress testing
	xmlPath := filepath.Join("..", "..", "testdata", "sample.config.2.xml")

	xmlData, err := os.ReadFile(xmlPath)
	if err != nil {
		b.Fatalf("Failed to read large testdata XML file: %v", err)
	}

	// Parse using the parser factory
	factory := parser.NewFactory(cfgparser.NewXMLParser())
	device, _, err := factory.CreateDevice(
		context.Background(),
		strings.NewReader(string(xmlData)),
		common.DeviceTypeUnknown,
		false,
	)
	if err != nil {
		b.Fatalf("XML parsing failed: %v", err)
	}

	converter := NewMarkdownConverter()
	ctx := context.Background()

	b.ReportAllocs()

	for b.Loop() {
		_, err := converter.ToMarkdown(ctx, device)
		if err != nil {
			b.Fatalf("ToMarkdown failed: %v", err)
		}
	}
}
