package stig_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/plugins/stig"
	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/opnsense"
	"github.com/EvilBit-Labs/opnDossier/pkg/parser/pfsense"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSTIG_UnboundDNSSECHardening_NotAnUnnecessaryService covers "Harden
// DNSSEC Data". Both vendors write it as dnssecstripped and render it as
// harden-dnssec-stripped: yes, which makes Unbound refuse a signed zone's
// answer with its DNSSEC records removed. It is the secure setting, so it must
// not fail V-206690. The configs carry nothing else V-206690 looks at.
func TestSTIG_UnboundDNSSECHardening_NotAnUnnecessaryService(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		parse  func(context.Context, *strings.Reader) (*common.CommonDevice, []common.ConversionWarning, error)
		config string
	}{
		{
			name: "OPNsense model",
			parse: func(ctx context.Context, r *strings.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
				return opnsense.NewParser(cfgparser.NewXMLParser()).Parse(ctx, r)
			},
			config: `<?xml version="1.0"?><opnsense><system><hostname>fw</hostname></system><OPNsense>` +
				`<unboundplus version="1.0.15"><general><enabled>1</enabled><dnssec>1</dnssec></general>` +
				`<advanced><dnssecstripped>1</dnssecstripped></advanced></unboundplus></OPNsense></opnsense>`,
		},
		{
			name: "pfSense",
			parse: func(ctx context.Context, r *strings.Reader) (*common.CommonDevice, []common.ConversionWarning, error) {
				return pfsense.NewParser(nil).Parse(ctx, r)
			},
			config: `<?xml version="1.0"?><pfsense><system><hostname>fw</hostname></system>` +
				`<unbound><enable></enable><dnssec></dnssec><dnssecstripped></dnssecstripped></unbound></pfsense>`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			device, _, err := tc.parse(context.Background(), strings.NewReader(tc.config))
			require.NoError(t, err)
			require.True(t, device.DNS.Unbound.Enabled)
			require.True(t, device.DNS.Unbound.DNSSECStripped)

			findings, _, err := stig.NewPlugin().RunChecks(device)
			require.NoError(t, err)

			for _, f := range findings {
				assert.False(t, slices.Contains(f.References, "V-206690"), "unexpected finding %q", f.Title)
			}
		})
	}
}
