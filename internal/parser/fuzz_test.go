package parser

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzXMLParserParse(f *testing.F) {
	// Seed corpus from testdata XML files
	testdataDir := filepath.Join("..", "..", "testdata")
	seeds, err := filepath.Glob(filepath.Join(testdataDir, "sample.config.*.xml"))
	if err == nil {
		for _, seed := range seeds {
			data, err := os.ReadFile(seed)
			if err == nil {
				f.Add(data)
			}
		}
	}

	// Minimal valid and invalid XML seeds
	f.Add([]byte(`<?xml version="1.0"?><opnsense><version>1.0</version></opnsense>`))
	f.Add([]byte(`<opnsense><system><hostname>test</hostname></system></opnsense>`))
	f.Add([]byte(`not xml at all`))
	f.Add([]byte{})

	parser := NewXMLParser()

	//nolint:revive // t is required by the fuzz API signature
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; errors are expected and acceptable
		//nolint:errcheck,gosec // fuzz tests intentionally discard errors
		parser.Parse(context.Background(), bytes.NewReader(data))
	})
}

func FuzzCharsetReader(f *testing.F) {
	f.Add("utf-8")
	f.Add("UTF-8")
	f.Add("us-ascii")
	f.Add("iso-8859-1")
	f.Add("ISO_8859-1:1987")
	f.Add("windows-1252")
	f.Add("latin1")
	f.Add("cp1252")
	f.Add("")
	f.Add("bogus-charset")

	//nolint:revive // t is required by the fuzz API signature
	f.Fuzz(func(t *testing.T, charset string) {
		// Must not panic; unsupported charset errors are expected
		//nolint:errcheck,gosec // fuzz tests intentionally discard errors
		charsetReader(charset, bytes.NewReader([]byte("test input")))
	})
}
