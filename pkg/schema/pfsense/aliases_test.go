package pfsense

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAliasList_XMLRoundTrip proves the net-new pfSense <aliases><alias>
// schema type survives a marshal/unmarshal round trip, including a
// space-separated multi-value <address> element (pfSense's member
// convention, unlike OPNsense's newline-separated <content>).
func TestAliasList_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := AliasList{
		Alias: []Alias{
			{
				Name:    "WEB_SERVERS",
				Type:    "host",
				Address: "10.20.30.40 10.20.30.41",
				Descr:   "Web server hosts",
				Detail:  "srv1||srv2",
			},
			{
				Name:    "INTERNAL_NET",
				Type:    "network",
				Address: "10.20.0.0/16",
				Descr:   "Internal network",
			},
		},
	}

	out, err := xml.Marshal(&original)
	require.NoError(t, err)

	var decoded AliasList
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded.Alias, 2, "round-trip must preserve exact alias count")

	assert.Equal(t, "WEB_SERVERS", decoded.Alias[0].Name)
	assert.Equal(t, "host", decoded.Alias[0].Type)
	assert.Equal(t, "10.20.30.40 10.20.30.41", decoded.Alias[0].Address)
	assert.Equal(t, "Web server hosts", decoded.Alias[0].Descr)
	assert.Equal(t, "srv1||srv2", decoded.Alias[0].Detail)

	assert.Equal(t, "INTERNAL_NET", decoded.Alias[1].Name)
	assert.Equal(t, "network", decoded.Alias[1].Type)
	assert.Equal(t, "10.20.0.0/16", decoded.Alias[1].Address)
}

// TestAliasList_XMLRoundTrip_Empty proves that an empty <aliases></aliases>
// element round-trips to a zero-length (nil) Alias slice — no spurious
// entries are introduced.
func TestAliasList_XMLRoundTrip_Empty(t *testing.T) {
	t.Parallel()

	var decoded AliasList
	err := xml.Unmarshal([]byte(`<aliases></aliases>`), &decoded)
	require.NoError(t, err)
	assert.Empty(t, decoded.Alias)
}

// TestDocument_Aliases_XMLRoundTrip proves the Document.Aliases field
// integrates correctly with the pfSense root document round trip.
func TestDocument_Aliases_XMLRoundTrip(t *testing.T) {
	t.Parallel()

	doc := NewDocument()
	doc.Aliases.Alias = []Alias{
		{Name: "WEB_SERVERS", Type: "host", Address: "10.20.30.40 10.20.30.41"},
	}

	out, err := xml.Marshal(doc)
	require.NoError(t, err)

	var decoded Document
	err = xml.Unmarshal(out, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded.Aliases.Alias, 1)
	assert.Equal(t, "WEB_SERVERS", decoded.Aliases.Alias[0].Name)
	assert.Equal(t, "10.20.30.40 10.20.30.41", decoded.Aliases.Alias[0].Address)
}
