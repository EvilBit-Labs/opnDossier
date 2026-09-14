package sanitizer

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestEscapeXMLText_PoolReuseDoesNotLeak guards the reset-on-checkout
// invariant for escapeBufPool directly. escapeXMLText is the sole consumer
// of the pooled buffer (formerly internal/pool.GetBytesBuffer/PutBytesBuffer);
// if a future edit drops the Reset() call, a pooled buffer would still hold
// bytes written by the previous call, and bytes.Buffer.Write appends rather
// than overwrites -- the next result would come back with the prior call's
// text prepended.
func TestEscapeXMLText_PoolReuseDoesNotLeak(t *testing.T) {
	const priorCallMarker = "PRIORCALL-9f3a7c1e"

	first := escapeXMLText(priorCallMarker)
	if first != priorCallMarker {
		t.Fatalf("escapeXMLText(%q) = %q, want unchanged (no special chars)", priorCallMarker, first)
	}

	const benign = "hostname-value"

	second := escapeXMLText(benign)
	if second != benign {
		t.Errorf("escapeXMLText(%q) = %q, want %q", benign, second, benign)
	}

	if strings.Contains(second, priorCallMarker) {
		t.Errorf("pooled buffer leaked prior call's content: got %q", second)
	}
}

// TestSanitizeXML_SequentialReuseNoCrossConfigBleed sanitizes a config
// containing a secret-shaped value, then an unrelated benign config, and
// asserts no byte of the first result appears in the second. This is the
// regression test for the sync.Pool -> internal/sanitizer migration: the
// pool is a package-level global, so two sequential SanitizeXML calls (even
// from different Sanitizer instances) can be handed the very same
// underlying buffer.
func TestSanitizeXML_SequentialReuseNoCrossConfigBleed(t *testing.T) {
	const priorConfigMarker = "PRIORCONFIG-9f3a7c1e"

	secretConfig := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <widgetid>%s</widgetid>
</opnsense>`, priorConfigMarker)

	s1 := NewSanitizer(ModeMinimal)

	var out1 bytes.Buffer
	if err := s1.SanitizeXML(strings.NewReader(secretConfig), &out1); err != nil {
		t.Fatalf("SanitizeXML(secretConfig) error = %v", err)
	}

	if !strings.Contains(out1.String(), priorConfigMarker) {
		t.Fatalf("test setup invalid: secret marker not present in first output: %q", out1.String())
	}

	benignConfig := `<?xml version="1.0"?>
<opnsense>
  <hostname>firewall</hostname>
</opnsense>`

	s2 := NewSanitizer(ModeMinimal)

	var out2 bytes.Buffer
	if err := s2.SanitizeXML(strings.NewReader(benignConfig), &out2); err != nil {
		t.Fatalf("SanitizeXML(benignConfig) error = %v", err)
	}

	if strings.Contains(out2.String(), priorConfigMarker) {
		t.Errorf("secret from a prior sanitize leaked into an unrelated result via a pooled buffer: %q", out2.String())
	}
}

// TestSanitizeXML_ConcurrentCallsIndependentOutput drives SanitizeXML from
// many goroutines simultaneously, each with a distinct marker value, and
// verifies every result contains only its own marker. This guards against
// the pooled escape buffer being shared unsafely across goroutines --
// sync.Pool itself is concurrency-safe, but a bug that returned the same
// *bytes.Buffer to two callers at once would show up as cross-contaminated
// output here.
func TestSanitizeXML_ConcurrentCallsIndependentOutput(t *testing.T) {
	const goroutines = 16

	var wg sync.WaitGroup

	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()

			marker := fmt.Sprintf("MARKER-%d-uniquevalue", idx)
			cfg := fmt.Sprintf(`<?xml version="1.0"?>
<opnsense>
  <unmatched-field>%s</unmatched-field>
</opnsense>`, marker)

			s := NewSanitizer(ModeMinimal)

			var out bytes.Buffer

			err := s.SanitizeXML(strings.NewReader(cfg), &out)
			errs[idx] = err
			results[idx] = out.String()
		}(i)
	}

	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: SanitizeXML() error = %v", i, errs[i])
		}

		ownMarker := fmt.Sprintf("MARKER-%d-uniquevalue", i)
		if !strings.Contains(results[i], ownMarker) {
			t.Errorf("goroutine %d: result missing its own marker: %q", i, results[i])
		}

		for j := range goroutines {
			if j == i {
				continue
			}

			otherMarker := fmt.Sprintf("MARKER-%d-uniquevalue", j)
			if strings.Contains(results[i], otherMarker) {
				t.Errorf(
					"goroutine %d: result contains goroutine %d's marker (cross-contamination): %q",
					i, j, results[i],
				)
			}
		}
	}
}
