// Benchmarks for EscapeTableContent dispatch paths.
//
// EscapeTableContent has three meaningful paths: nil, the unnamed-string
// fast path (covers the per-row markdown table callers), the
// reflect-based string-kind path (covers named string types like
// FirewallRuleType, IPProtocol, VIPMode), and the fmt.Sprintf fallback
// (covers ints, bools, etc.). The benchmarks below pin the relative
// alloc costs so a future refactor reordering the type switch surfaces
// the regression on its own.
package formatters

import "testing"

type benchNamedString string

func BenchmarkEscapeTableContent_String(b *testing.B) {
	const s = "rule 42 | allow *web* [_HTTPS_]"
	b.ReportAllocs()
	for b.Loop() {
		_ = EscapeTableContent(s)
	}
}

func BenchmarkEscapeTableContent_NamedString(b *testing.B) {
	const s benchNamedString = "rule 42 | allow *web* [_HTTPS_]"
	b.ReportAllocs()
	for b.Loop() {
		_ = EscapeTableContent(s)
	}
}

func BenchmarkEscapeTableContent_Int(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = EscapeTableContent(42)
	}
}

func BenchmarkEscapeTableContent_Nil(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = EscapeTableContent(nil)
	}
}
