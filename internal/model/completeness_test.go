//go:build completeness
// +build completeness

package model

import (
	"os"
	"path/filepath"
	"testing"
)

// TestModelCompleteness tests that our OpnSenseDocument model can fully represent
// all XML elements and attributes found in the test configuration files.
// This test will fail if any XML field is not represented in our Go model.
//
// To run this test: go test -tags=completeness ./internal/model
func TestModelCompleteness(t *testing.T) {
	testDir := "../../testdata"
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read testdata directory: %v", err)
	}

	var xmlFiles []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".xml" {
			xmlFiles = append(xmlFiles, filepath.Join(testDir, f.Name()))
		}
	}

	if len(xmlFiles) == 0 {
		t.Fatalf("no XML files found in testdata directory")
	}

			for _, file := range xmlFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			_, _, missingPaths, err := GetModelCompletenessDetails(file)
			if err != nil {
				t.Errorf("model completeness check failed for %s: %v", file, err)
				return
			}

			if len(missingPaths) > 0 {
				t.Errorf("model completeness check failed for %s: %d missing fields", file, len(missingPaths))
				t.Logf("Missing fields for %s:", file)
				for i, path := range missingPaths {
					if i < 50 { // Show first 50 missing fields
						t.Logf("  - %s", path)
					} else if i == 50 {
						t.Logf("  ... and %d more fields", len(missingPaths)-50)
						break
					}
				}
			}
		})
	}
}
