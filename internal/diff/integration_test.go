//go:build integration

package diff

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/cfgparser"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_CompareRealConfigs tests the diff engine with real config files.
func TestIntegration_CompareRealConfigs(t *testing.T) {
	// Find testdata directory
	testdataDir := findTestdataDir(t)

	// Test comparing sample.config.1.xml with sample.config.2.xml
	oldPath := filepath.Join(testdataDir, "sample.config.1.xml")
	newPath := filepath.Join(testdataDir, "sample.config.2.xml")

	if !fileExists(oldPath) || !fileExists(newPath) {
		t.Skip("Test config files not found, skipping integration test")
	}

	oldConfig := parseConfigFile(t, oldPath)
	newConfig := parseConfigFile(t, newPath)

	engine := NewEngine(oldConfig, newConfig, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Metadata)

	// Log what was found for debugging
	t.Logf("Found %d total changes", result.Summary.Total)
	t.Logf("  Added: %d, Removed: %d, Modified: %d",
		result.Summary.Added, result.Summary.Removed, result.Summary.Modified)

	for _, change := range result.Changes {
		t.Logf("  [%s] %s: %s", change.Type.Symbol(), change.Section, change.Description)
	}
}

// TestIntegration_CompareSameConfig tests that comparing a config with itself yields no changes.
func TestIntegration_CompareSameConfig(t *testing.T) {
	testdataDir := findTestdataDir(t)
	configPath := filepath.Join(testdataDir, "sample.config.1.xml")

	if !fileExists(configPath) {
		t.Skip("Test config file not found, skipping integration test")
	}

	config := parseConfigFile(t, configPath)

	engine := NewEngine(config, config, Options{}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)
	assert.False(t, result.HasChanges(), "Comparing a config with itself should yield no changes")
	assert.Equal(t, 0, result.Summary.Total)
}

// TestIntegration_SectionFiltering tests section filtering with real configs.
func TestIntegration_SectionFiltering(t *testing.T) {
	testdataDir := findTestdataDir(t)
	oldPath := filepath.Join(testdataDir, "sample.config.1.xml")
	newPath := filepath.Join(testdataDir, "sample.config.2.xml")

	if !fileExists(oldPath) || !fileExists(newPath) {
		t.Skip("Test config files not found, skipping integration test")
	}

	oldConfig := parseConfigFile(t, oldPath)
	newConfig := parseConfigFile(t, newPath)

	// Compare only system section
	engine := NewEngine(oldConfig, newConfig, Options{
		Sections: []string{"system"},
	}, nil)
	result, err := engine.Compare(context.Background())

	require.NoError(t, err)

	// All changes should be in the system section
	for _, change := range result.Changes {
		assert.Equal(t, SectionSystem, change.Section,
			"Expected only system section changes, got %s", change.Section)
	}
}

// TestIntegration_AllConfigPairs tests comparing all pairs of config files.
func TestIntegration_AllConfigPairs(t *testing.T) {
	testdataDir := findTestdataDir(t)

	// Get all sample config files
	configs := []string{}
	for i := 1; i <= 7; i++ {
		path := filepath.Join(testdataDir, fmt.Sprintf("sample.config.%d.xml", i))
		if fileExists(path) {
			configs = append(configs, path)
		}
	}

	if len(configs) < 2 {
		t.Skip("Not enough config files found for pair comparison")
	}

	// Compare adjacent pairs
	for i := 0; i < len(configs)-1; i++ {
		oldPath := configs[i]
		newPath := configs[i+1]

		t.Run(filepath.Base(oldPath)+"_vs_"+filepath.Base(newPath), func(t *testing.T) {
			oldConfig := parseConfigFile(t, oldPath)
			newConfig := parseConfigFile(t, newPath)

			engine := NewEngine(oldConfig, newConfig, Options{}, nil)
			result, err := engine.Compare(context.Background())

			require.NoError(t, err)
			assert.NotNil(t, result)

			t.Logf("Changes: %d (added=%d, removed=%d, modified=%d)",
				result.Summary.Total, result.Summary.Added,
				result.Summary.Removed, result.Summary.Modified)
		})
	}
}

// Helper functions

func findTestdataDir(t *testing.T) string {
	t.Helper()

	// Try relative paths from different locations
	candidates := []string{
		"../../testdata",
		"../../../testdata",
		"testdata",
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}

	// Try from working directory
	wd, _ := os.Getwd()
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		testdata := filepath.Join(dir, "testdata")
		if info, err := os.Stat(testdata); err == nil && info.IsDir() {
			return testdata
		}
	}

	t.Fatal("Could not find testdata directory")
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parseConfigFile(t *testing.T, path string) *model.OpnSenseDocument {
	t.Helper()

	file, err := os.Open(path)
	require.NoError(t, err, "Failed to open config file: %s", path)
	defer file.Close()

	p := cfgparser.NewXMLParser()
	doc, err := p.Parse(context.Background(), file)
	require.NoError(t, err, "Failed to parse config file: %s", path)

	return doc
}
