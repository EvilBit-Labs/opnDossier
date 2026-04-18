package cfgparser_test

import (
	"context"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXMLParser_DecodeErrorIncludesElementPath verifies that when a schema
// field fails to decode (e.g., non-numeric value in an int field), the
// returned error names the element path so users can identify the offending
// field without reading source.
func TestXMLParser_DecodeErrorIncludesElementPath(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		wantSub string
	}{
		{
			name:    "malformed int in system subtree",
			xml:     `<opnsense><system><nextuid>banana</nextuid><hostname>h</hostname><domain>d</domain></system></opnsense>`,
			wantSub: "/opnsense/system",
		},
		{
			name:    "malformed int in second system field (nextgid)",
			xml:     `<opnsense><system><nextgid>xyz</nextgid><hostname>h</hostname><domain>d</domain></system></opnsense>`,
			wantSub: "/opnsense/system",
		},
		// Note: the original reporter scenario (<dnsallowoverride>on</dnsallowoverride>)
		// no longer errors — it parses cleanly now that dnsallowoverride is BoolFlag.
		// That's the fix for #558. The element-path annotation remains important for
		// the fields that ARE still integer-typed (NextUID, NextGID, etc.).
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := cfgparser.NewXMLParser()
			_, err := p.Parse(context.Background(), strings.NewReader(tt.xml))
			require.Error(t, err, "expected decode error")
			assert.Contains(t, err.Error(), tt.wantSub,
				"error should name element path: %q", err.Error())
		})
	}
}
