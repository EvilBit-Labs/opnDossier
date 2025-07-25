package tests

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGoModFileExists verifies that the go.mod file exists in the project root
func TestGoModFileExists(t *testing.T) {
	_, err := os.Stat("go.mod")
	assert.NoError(t, err, "go.mod file should exist in the project root")
}

// TestGoModFileReadable ensures the go.mod file is readable
func TestGoModFileReadable(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err, "go.mod file should be readable")
	assert.NotEmpty(t, content, "go.mod file should not be empty")
}

// TestModuleDeclaration validates the module declaration
func TestModuleDeclaration(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	
	// Find module declaration
	var moduleFound bool
	var moduleName string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "module ") {
			moduleFound = true
			moduleName = strings.TrimSpace(strings.TrimPrefix(trimmed, "module "))
			break
		}
	}
	
	assert.True(t, moduleFound, "Module declaration should be present")
	assert.Equal(t, "github.com/unclesp1d3r/opnFocus", moduleName, "Module name should match expected value")
}

// TestGoVersionDeclaration validates the Go version specification
func TestGoVersionDeclaration(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	assert.Contains(t, contentStr, "go 1.24.0", "Go version should be specified as 1.24.0") 
	assert.Contains(t, contentStr, "toolchain go1.24.5", "Toolchain should be specified as go1.24.5")
}

// TestGoVersionIsMinimum validates that the Go version meets minimum requirements
func TestGoVersionIsMinimum(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Extract go version
	goVersionRegex := regexp.MustCompile(`go\s+(\d+\.\d+\.\d+)`)
	matches := goVersionRegex.FindStringSubmatch(contentStr)
	require.Len(t, matches, 2, "Go version should be found in go.mod")
	
	version := matches[1]
	// Ensure it's at least Go 1.21 (minimum for modern Go features)
	assert.True(t, version >= "1.21.0", "Go version should be at least 1.21.0, got %s", version)
}

// TestRequiredDependencies validates that all expected dependencies are present
func TestRequiredDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	expectedDeps := map[string]string{
		"github.com/charmbracelet/fang":    "v0.3.0",
		"github.com/charmbracelet/glamour": "v0.10.0", 
		"github.com/charmbracelet/lipgloss": "v1.1.1-0.20250404203927-76690c660834",
		"github.com/charmbracelet/log":     "v0.4.2",
		"github.com/spf13/cobra":           "v1.9.1",
		"github.com/spf13/pflag":           "v1.0.7",
		"github.com/spf13/viper":           "v1.20.1",
		"github.com/stretchr/testify":      "v1.10.0",
	}
	
	for dep, version := range expectedDeps {
		depLine := dep + " " + version
		assert.Contains(t, contentStr, depLine, "Required dependency should be present: %s %s", dep, version)
	}
}

// TestIndirectDependencies validates that critical indirect dependencies are present
func TestIndirectDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	criticalIndirectDeps := []string{
		"github.com/alecthomas/chroma/v2", 
		"github.com/davecgh/go-spew",
		"github.com/pmezard/go-difflib",
		"gopkg.in/yaml.v3",
	}
	
	for _, dep := range criticalIndirectDeps {
		assert.Contains(t, contentStr, dep+" ", "Critical indirect dependency should be present: %s", dep)
	}
	
	// Verify indirect markers are present
	assert.Contains(t, contentStr, "// indirect", "Indirect dependencies should be marked as indirect")
}

// TestModuleStructure validates the overall structure of the go.mod file
func TestModuleStructure(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Check for proper sections in order
	moduleIndex := strings.Index(contentStr, "module ")
	goVersionIndex := strings.Index(contentStr, "go ")
	requireIndex := strings.Index(contentStr, "require (")
	
	assert.True(t, moduleIndex >= 0, "Module declaration should be present")
	assert.True(t, goVersionIndex >= 0, "Go version should be present")  
	assert.True(t, requireIndex >= 0, "Require section should be present")
	
	// Validate ordering
	assert.True(t, moduleIndex < goVersionIndex, "Module should come before go version")
	assert.True(t, goVersionIndex < requireIndex, "Go version should come before require section")
	
	// Count require blocks
	requireOpenCount := strings.Count(contentStr, "require (")
	assert.Equal(t, 2, requireOpenCount, "Should have exactly 2 require blocks (direct and indirect)")
	
	// Basic bracket matching for require blocks
	openParens := strings.Count(contentStr, "(")
	closeParens := strings.Count(contentStr, ")")
	assert.Equal(t, openParens, closeParens, "Parentheses should be balanced")
}

// TestVersionFormats validates that all version strings follow proper semver format
func TestVersionFormats(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	
	// Regex for basic semantic version validation
	semverRegex := regexp.MustCompile(`^v\d+\.\d+\.\d+`)
	pseudoVersionRegex := regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-[a-f0-9]{12}`)
	preReleaseRegex := regexp.MustCompile(`^v\d+\.\d+\.\d+-[a-zA-Z0-9.-]+`)
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, " v") && !strings.HasPrefix(trimmed, "//") && 
		   !strings.HasPrefix(trimmed, "module ") && !strings.HasPrefix(trimmed, "go ") &&
		   !strings.HasPrefix(trimmed, "toolchain ") {
			
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				version := parts[1]
				
				// Basic version format validation
				isValid := semverRegex.MatchString(version) || 
						  pseudoVersionRegex.MatchString(version) ||
						  preReleaseRegex.MatchString(version)
				
				assert.True(t, isValid, 
					"Version should follow semantic versioning: %s in line: %s", version, trimmed)
			}
		}
	}
}

// TestNoDuplicateDependencies ensures no dependencies are listed multiple times
func TestNoDuplicateDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	
	seenDeps := make(map[string]int)
	
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, " v") && !strings.HasPrefix(trimmed, "//") && 
		   !strings.HasPrefix(trimmed, "module ") && !strings.HasPrefix(trimmed, "go ") &&
		   !strings.HasPrefix(trimmed, "toolchain ") {
			
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				depName := parts[0]
				if prevLine, exists := seenDeps[depName]; exists {
					t.Errorf("Duplicate dependency found: %s at line %d (previously seen at line %d)", 
						depName, lineNum+1, prevLine+1)
				}
				seenDeps[depName] = lineNum
			}
		}
	}
}

// TestGoModFileNotCorrupted performs basic corruption checks
func TestGoModFileNotCorrupted(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Check for basic syntax elements
	assert.NotContains(t, contentStr, "\x00", "File should not contain null bytes")
	assert.NotContains(t, contentStr, "\xFF", "File should not contain invalid UTF-8")
	
	// Check that file ends with newline
	assert.True(t, strings.HasSuffix(contentStr, "\n"), "File should end with newline")
	
	// Check for proper UTF-8 encoding
	assert.True(t, validUTF8(contentStr), "File should be valid UTF-8")
}

// TestRequiredTestFramework specifically validates testify is present
func TestRequiredTestFramework(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "github.com/stretchr/testify", 
		"testify testing framework should be present")
		
	// Ensure it's a reasonably recent version
	assert.Contains(t, contentStr, "github.com/stretchr/testify v1.10.0",
		"testify should be version 1.10.0 or compatible")
}

// TestCharmbraceeletDependencies validates Charm Bracelet ecosystem dependencies
func TestCharmbraceeletDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	charmDeps := []string{
		"github.com/charmbracelet/fang",
		"github.com/charmbracelet/glamour", 
		"github.com/charmbracelet/lipgloss",
		"github.com/charmbracelet/log",
	}
	
	for _, dep := range charmDeps {
		assert.Contains(t, contentStr, dep, 
			"Charmbracelet dependency should be present: %s", dep)
	}
	
	// Ensure we have multiple charmbracelet dependencies (indicates CLI/TUI app)
	charmCount := strings.Count(contentStr, "github.com/charmbracelet/")
	assert.GreaterOrEqual(t, charmCount, 4, "Should have at least 4 charmbracelet dependencies")
}

// TestSpfDependencies validates Spf13 ecosystem dependencies  
func TestSpfDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	spfDeps := []string{
		"github.com/spf13/cobra",
		"github.com/spf13/pflag", 
		"github.com/spf13/viper",
	}
	
	for _, dep := range spfDeps {
		assert.Contains(t, contentStr, dep, 
			"Spf13 dependency should be present: %s", dep)
	}
	
	// This combination suggests a CLI application
	assert.Contains(t, contentStr, "github.com/spf13/cobra", "Should use Cobra for CLI")
	assert.Contains(t, contentStr, "github.com/spf13/viper", "Should use Viper for configuration")
}

// TestModuleFilePermissions checks file permissions are appropriate
func TestModuleFilePermissions(t *testing.T) {
	fileInfo, err := os.Stat("go.mod")
	require.NoError(t, err)
	
	mode := fileInfo.Mode()
	
	// Should be readable by all
	assert.True(t, mode.Perm()&0444 != 0, "go.mod should be readable")
	
	// Should not have execute permissions
	assert.True(t, mode.Perm()&0111 == 0, "go.mod should not be executable")
}

// TestModuleFileSize ensures the file is reasonable size
func TestModuleFileSize(t *testing.T) {
	fileInfo, err := os.Stat("go.mod")
	require.NoError(t, err)
	
	size := fileInfo.Size()
	
	// Reasonable size bounds for a CLI application
	assert.Greater(t, size, int64(500), "go.mod should be at least 500 bytes for a real project")
	assert.Less(t, size, int64(50000), "go.mod should be less than 50KB to avoid bloat")
}

// TestGoSumFileConsistency validates go.sum exists and is consistent
func TestGoSumFileConsistency(t *testing.T) {
	// go.sum should exist for a project with dependencies
	if _, err := os.Stat("go.sum"); err == nil {
		content, err := os.ReadFile("go.sum")
		require.NoError(t, err)
		
		contentStr := string(content)
		
		// Basic validation that go.sum has content and proper format
		assert.NotEmpty(t, contentStr, "go.sum should not be empty if it exists")
		
		lines := strings.Split(contentStr, "\n")
		validLines := 0
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				// Each line should have module name, version, and hash
				parts := strings.Fields(line)
				assert.GreaterOrEqual(t, len(parts), 3, 
					"go.sum line should have at least 3 parts: %s", line)
				
				// Hash should be the right format
				if len(parts) >= 3 {
					hash := parts[len(parts)-1]
					assert.True(t, strings.HasPrefix(hash, "h1:"), 
						"Hash should start with h1: %s", hash)
				}
				validLines++
			}
		}
		
		assert.Greater(t, validLines, 0, "go.sum should have valid entries")
	} else {
		t.Log("go.sum file not found - this is acceptable but unusual for a project with dependencies")
	}
}

// TestRelativePathInModule ensures no relative paths in module definition
func TestRelativePathInModule(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Should not contain relative path indicators
	assert.NotContains(t, contentStr, "../", "Module file should not contain relative paths")
	assert.NotContains(t, contentStr, "./", "Module file should not contain current directory references")
}

// TestWorkspaceFileHandling checks for Go workspace files
func TestWorkspaceFileHandling(t *testing.T) {
	// Check if go.work exists and validate basic structure if present
	if _, err := os.Stat("go.work"); err == nil {
		content, err := os.ReadFile("go.work")
		require.NoError(t, err)
		
		contentStr := string(content)
		assert.Contains(t, contentStr, "go ", "go.work should specify Go version")
		
		t.Log("Found go.work file - workspace mode detected")
	}
}

// TestModuleLineEndings ensures consistent line endings
func TestModuleLineEndings(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Should use Unix line endings
	assert.NotContains(t, contentStr, "\r\n", "Should use Unix line endings (LF), not Windows (CRLF)")
	assert.NotContains(t, contentStr, "\r", "Should not contain carriage returns")
}

// TestNoReplaceDependencies ensures no replace directives (usually for development)
func TestNoReplaceDependencies(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Replace directives should not be present in production code
	assert.NotContains(t, contentStr, "replace ", "Should not contain replace directives in production")
}

// TestValidModuleNameFormat validates the module name follows Go conventions
func TestValidModuleNameFormat(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Extract module name
	moduleRegex := regexp.MustCompile(`module\s+([^\s]+)`)
	matches := moduleRegex.FindStringSubmatch(contentStr)
	require.Len(t, matches, 2, "Module name should be found")
	
	moduleName := matches[1]
	
	// Should be a valid module path
	assert.True(t, strings.Contains(moduleName, "/"), "Module name should contain path separators")
	assert.True(t, strings.HasPrefix(moduleName, "github.com/"), "Module should be hosted on GitHub")
	assert.False(t, strings.Contains(moduleName, " "), "Module name should not contain spaces")
	assert.False(t, strings.Contains(moduleName, "\t"), "Module name should not contain tabs")
}

// TestModuleFileBackups checks for backup files that shouldn't exist
func TestModuleFileBackups(t *testing.T) {
	backupPatterns := []string{"go.mod.bak", "go.mod.backup", "go.mod~", "go.mod.orig"}
	
	for _, pattern := range backupPatterns {
		if _, err := os.Stat(pattern); err == nil {
			t.Logf("Found backup file: %s - consider cleaning up", pattern)
		}
	}
}

// TestToolchainVersion validates the toolchain version is compatible
func TestToolchainVersion(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	contentStr := string(content)
	
	// Extract toolchain version
	toolchainRegex := regexp.MustCompile(`toolchain\s+go(\d+\.\d+\.\d+)`)
	matches := toolchainRegex.FindStringSubmatch(contentStr)
	
	if len(matches) == 2 {
		toolchainVersion := matches[1]
		// Toolchain should be at least as recent as the go version
		assert.True(t, toolchainVersion >= "1.24.0", 
			"Toolchain version should be at least 1.24.0, got %s", toolchainVersion)
	}
}

// BenchmarkGoModParsing benchmarks the parsing of go.mod file
func BenchmarkGoModParsing(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		content, err := os.ReadFile("go.mod")
		if err != nil {
			b.Fatal(err)
		}
		
		// Simple parsing simulation
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			strings.TrimSpace(line)
		}
	}
}

// TestLoadGoModAsScanner tests parsing go.mod line by line
func TestLoadGoModAsScanner(t *testing.T) {
	file, err := os.Open("go.mod")
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++
		
		// Basic validation of each line
		assert.True(t, len(line) < 200, "Line %d should not be excessively long: %s", lineCount, line)
	}
	
	require.NoError(t, scanner.Err(), "Should be able to scan entire file")
	assert.Greater(t, lineCount, 10, "Should have reasonable number of lines")
}

// TestGoModFileIntegrity performs comprehensive integrity checks
func TestGoModFileIntegrity(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, content string)
	}{
		{
			name: "proper_module_declaration",
			testFunc: func(t *testing.T, content string) {
				assert.Regexp(t, `^module\s+\S+`, content, "Module declaration should be at the beginning")
			},
		},
		{
			name: "go_version_present",
			testFunc: func(t *testing.T, content string) {
				assert.Regexp(t, `go\s+\d+\.\d+\.\d+`, content, "Go version should be specified")
			},
		},
		{
			name: "require_blocks_present",
			testFunc: func(t *testing.T, content string) {
				assert.Contains(t, content, "require (", "Require blocks should be present")
			},
		},
		{
			name: "no_empty_lines_in_require_blocks",
			testFunc: func(t *testing.T, content string) {
				lines := strings.Split(content, "\n")
				inRequireBlock := false
				for _, line := range lines {
					if strings.Contains(line, "require (") {
						inRequireBlock = true
						continue
					}
					if inRequireBlock && strings.TrimSpace(line) == ")" {
						inRequireBlock = false
						continue
					}
					if inRequireBlock {
						trimmed := strings.TrimSpace(line)
						if trimmed == "" {
							t.Error("Empty lines should not be present within require blocks")
						}
					}
				}
			},
		},
	}

	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)
	contentStr := string(content)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t, contentStr)
		})
	}
}

// Helper function to validate UTF-8
func validUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}