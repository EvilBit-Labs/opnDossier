package parser_test

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCharsetReader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		charset string
		wantErr bool
	}{
		{name: "utf-8", charset: "utf-8"},
		{name: "UTF-8 uppercase", charset: "UTF-8"},
		{name: "utf8 no hyphen", charset: "utf8"},
		{name: "us-ascii", charset: "us-ascii"},
		{name: "ascii", charset: "ascii"},
		{name: "iso-8859-1", charset: "iso-8859-1"},
		{name: "iso8859-1", charset: "iso8859-1"},
		{name: "latin1", charset: "latin1"},
		{name: "latin-1", charset: "latin-1"},
		{name: "windows-1252", charset: "windows-1252"},
		{name: "windows1252", charset: "windows1252"},
		{name: "cp1252", charset: "cp1252"},
		{name: "ISO_8859-1:1987 suffix", charset: "ISO_8859-1:1987"},
		{name: "unsupported EBCDIC", charset: "EBCDIC", wantErr: true},
		{name: "unsupported Shift_JIS", charset: "Shift_JIS", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := strings.NewReader("test data")
			reader, err := parser.CharsetReader(tc.charset, input)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported charset")

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, reader)

			data, readErr := io.ReadAll(reader)
			require.NoError(t, readErr)
			assert.NotEmpty(t, data)
		})
	}
}

func TestNewSecureXMLDecoder(t *testing.T) {
	t.Parallel()

	t.Run("decodes valid XML", func(t *testing.T) {
		t.Parallel()

		xmlData := `<?xml version="1.0"?><root><name>test</name></root>`
		dec := parser.NewSecureXMLDecoder(strings.NewReader(xmlData), parser.DefaultMaxInputSize)

		var result struct {
			XMLName xml.Name `xml:"root"`
			Name    string   `xml:"name"`
		}
		err := dec.Decode(&result)

		require.NoError(t, err)
		assert.Equal(t, "test", result.Name)
	})

	t.Run("rejects entity expansion", func(t *testing.T) {
		t.Parallel()

		// XML with entity reference — should fail because entity map is empty.
		xmlData := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "pwned">]><root>&xxe;</root>`
		dec := parser.NewSecureXMLDecoder(strings.NewReader(xmlData), parser.DefaultMaxInputSize)

		var result struct {
			XMLName xml.Name `xml:"root"`
		}
		err := dec.Decode(&result)

		require.Error(t, err)
	})

	t.Run("enforces size limit", func(t *testing.T) {
		t.Parallel()

		// Create input larger than the limit.
		const limit int64 = 100
		largeData := bytes.Repeat([]byte("x"), int(limit)+1000)
		xmlData := append([]byte("<r>"), largeData...)
		xmlData = append(xmlData, []byte("</r>")...)

		dec := parser.NewSecureXMLDecoder(bytes.NewReader(xmlData), limit)

		var result struct {
			XMLName xml.Name `xml:"r"`
		}
		err := dec.Decode(&result)

		require.Error(t, err)
	})
}
