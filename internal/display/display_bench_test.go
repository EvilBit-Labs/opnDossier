package display

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func BenchmarkTerminalDisplay_Display(b *testing.B) {
	markdownContent := buildDisplayBenchmarkMarkdown(500)
	opts := Options{
		Theme:        DarkTheme(),
		WrapWidth:    120,
		EnableTables: true,
		EnableColors: true,
	}
	td := NewTerminalDisplayWithOptions(opts)

	restoreStdout := discardStdout(b)
	defer restoreStdout()

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := td.Display(ctx, markdownContent); err != nil {
			b.Fatalf("Display failed: %v", err)
		}
	}
}

func buildDisplayBenchmarkMarkdown(ruleCount int) string {
	var sb strings.Builder
	sb.Grow(ruleCount * 96)
	sb.WriteString("# opnDossier Display Benchmark\n\n")
	sb.WriteString("| Rule | Interface | Source | Destination | Action | Description |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for i := range ruleCount {
		fmt.Fprintf(
			&sb,
			"| %05d | wan | 10.%d.%d.0/24 | 192.0.2.%d:443 | pass | display rendering benchmark row %05d |\n",
			i,
			(i/256)%256,
			i%256,
			i%256,
			i,
		)
	}
	return sb.String()
}

func discardStdout(b *testing.B) func() {
	b.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		b.Fatalf("pipe stdout: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return
		}
	}()

	os.Stdout = writer

	return func() {
		os.Stdout = originalStdout
		_ = writer.Close()
		<-done
		_ = reader.Close()
	}
}
