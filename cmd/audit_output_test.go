package cmd

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmitAuditResult_MultiFileAutoNaming verifies that multi-file audit runs
// derive unique per-input output paths instead of falling back to stdout or
// resolving to a shared config-driven output path.
func TestEmitAuditResult_MultiFileAutoNaming(t *testing.T) {
	// Do NOT use t.Parallel() — modifies package-level flag variables.
	originalOutputFile := outputFile
	originalFormat := format
	originalForce := force
	t.Cleanup(func() {
		outputFile = originalOutputFile
		format = originalFormat
		force = originalForce
	})

	outputFile = "" // No CLI --output
	format = "markdown"
	force = true

	// Two different input files with the same parent directory
	result1 := auditResult{inputFile: "/tmp/config1.xml"}
	result2 := auditResult{inputFile: "/tmp/config2.xml"}

	// Multi-file auto-naming derives unique per-input paths
	path1 := deriveAuditOutputPath(result1.inputFile, ".md")
	path2 := deriveAuditOutputPath(result2.inputFile, ".md")

	assert.Equal(t, "~a_tmp_config1-audit.md", path1)
	assert.Equal(t, "~a_tmp_config2-audit.md", path2)
	assert.NotEqual(t, path1, path2, "multi-file audit must produce distinct output paths")

	// Verify the derived paths pass through determineOutputPath correctly
	// (treated as explicit CLI outputFile, so config is ignored)
	resolvedPath1, err1 := determineOutputPath(result1.inputFile, path1, ".md", nil, force)
	resolvedPath2, err2 := determineOutputPath(result2.inputFile, path2, ".md", nil, force)
	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, "~a_tmp_config1-audit.md", resolvedPath1)
	assert.Equal(t, "~a_tmp_config2-audit.md", resolvedPath2)
}

// TestEmitAuditResult_MultiFileConfigOutputFileIgnored verifies that when
// cmdConfig.OutputFile is set during a multi-file audit, the shared config
// destination is ignored in favor of per-input auto-named paths.
func TestEmitAuditResult_MultiFileConfigOutputFileIgnored(t *testing.T) {
	// Do NOT use t.Parallel() — modifies package-level flag variables.
	originalOutputFile := outputFile
	originalFormat := format
	originalForce := force
	t.Cleanup(func() {
		outputFile = originalOutputFile
		format = originalFormat
		force = originalForce
	})

	outputFile = "" // No CLI --output
	format = "markdown"
	force = true

	// Simulate multi-file run with config OutputFile set
	cfgWithOutput := &config.Config{OutputFile: "/tmp/shared-report.md"}

	// Without the fix, both inputs would resolve to the shared config path
	pathA, errA := determineOutputPath("/tmp/config1.xml", "", ".md", cfgWithOutput, true)
	pathB, errB := determineOutputPath("/tmp/config2.xml", "", ".md", cfgWithOutput, true)
	require.NoError(t, errA)
	require.NoError(t, errB)
	assert.Equal(t, pathA, pathB, "raw config OutputFile causes collision")

	// With the fix, deriveAuditOutputPath produces unique paths and nil config
	// is passed to determineOutputPath, preventing the config path from being used.
	derivedA := deriveAuditOutputPath("/tmp/config1.xml", ".md")
	derivedB := deriveAuditOutputPath("/tmp/config2.xml", ".md")

	resolvedA, errResolvedA := determineOutputPath("/tmp/config1.xml", derivedA, ".md", nil, true)
	resolvedB, errResolvedB := determineOutputPath("/tmp/config2.xml", derivedB, ".md", nil, true)
	require.NoError(t, errResolvedA)
	require.NoError(t, errResolvedB)

	assert.Equal(t, "~a_tmp_config1-audit.md", resolvedA)
	assert.Equal(t, "~a_tmp_config2-audit.md", resolvedB)
	assert.NotEqual(t, resolvedA, resolvedB, "multi-file audit must not resolve to same output path")
}

// TestDeriveAuditOutputPath verifies per-input filename derivation for multi-file audit.
func TestDeriveAuditOutputPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputFile string
		fileExt   string
		want      string
	}{
		{"markdown from xml", "/path/to/config.xml", ".md", "~a_path_to_config-audit.md"},
		{"json from xml", "/path/to/config.xml", ".json", "~a_path_to_config-audit.json"},
		{"yaml from xml", "/path/to/config.xml", ".yaml", "~a_path_to_config-audit.yaml"},
		{"html from xml", "config.xml", ".html", "config-audit.html"},
		{"txt from xml", "config.xml", ".txt", "config-audit.txt"},
		{"nested path", "/a/b/c/firewall-prod.xml", ".md", "~a_a_b_c_firewall-prod-audit.md"},
		{"no extension input", "/path/to/config", ".json", "~a_path_to_config-audit.json"},
		{"relative path", "configs/backup.xml", ".md", "configs_backup-audit.md"},
		{"bare filename no dir", "config.xml", ".md", "config-audit.md"},
		{"underscore in segment", "a_b/config.xml", ".md", "a~ub_config-audit.md"},
		{"underscore in bare filename", "my_config.xml", ".md", "my~uconfig-audit.md"},
		{"tilde in segment", "a~b/config.xml", ".md", "a~~b_config-audit.md"},
		{"tilde in bare filename", "my~config.xml", ".md", "my~~config-audit.md"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := deriveAuditOutputPath(tt.inputFile, tt.fileExt)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDeriveAuditOutputPath_BasenameCollision verifies that inputs with the same
// basename but different parent directories produce distinct output paths,
// preventing overwrite prompts or silent clobbering during multi-file audit.
func TestDeriveAuditOutputPath_BasenameCollision(t *testing.T) {
	t.Parallel()

	pathA := deriveAuditOutputPath("site-a/config.xml", ".md")
	pathB := deriveAuditOutputPath("site-b/config.xml", ".md")

	assert.Equal(t, "site-a_config-audit.md", pathA, "site-a dir prefix preserved")
	assert.Equal(t, "site-b_config-audit.md", pathB, "site-b dir prefix preserved")
	assert.NotEqual(t, pathA, pathB,
		"inputs with same basename but different directories must produce distinct output paths")
}

// TestDeriveAuditOutputPath_SameParentBasenameCollision verifies that inputs under
// different directory trees that share both the same basename and the same immediate
// parent directory name still produce distinct output paths. This prevents the
// collision that would occur if only the immediate parent were used as disambiguator
// (e.g., /prod/site-a/config.xml and /dr/site-a/config.xml both resolving to
// "site-a-config-audit.md").
func TestDeriveAuditOutputPath_SameParentBasenameCollision(t *testing.T) {
	t.Parallel()

	pathA := deriveAuditOutputPath("/prod/site-a/config.xml", ".md")
	pathB := deriveAuditOutputPath("/dr/site-a/config.xml", ".md")

	assert.Equal(t, "~a_prod_site-a_config-audit.md", pathA)
	assert.Equal(t, "~a_dr_site-a_config-audit.md", pathB)
	assert.NotEqual(t, pathA, pathB,
		"inputs with same basename AND same parent basename under different trees must produce distinct output paths")

	// Deeper nesting: verify three-level disambiguation
	pathC := deriveAuditOutputPath("/us-east/prod/fw/config.xml", ".md")
	pathD := deriveAuditOutputPath("/eu-west/prod/fw/config.xml", ".md")

	assert.Equal(t, "~a_us-east_prod_fw_config-audit.md", pathC)
	assert.Equal(t, "~a_eu-west_prod_fw_config-audit.md", pathD)
	assert.NotEqual(t, pathC, pathD,
		"deeply nested inputs with shared parent segments must still produce distinct output paths")
}

// TestDeriveAuditOutputPath_AbsoluteVsRelativeCollision verifies that distinct
// cleaned absolute and relative paths never collapse to the same derived output
// filename. Absolute paths carry an explicit marker segment to preserve root
// information after flattening.
func TestDeriveAuditOutputPath_AbsoluteVsRelativeCollision(t *testing.T) {
	t.Parallel()

	absPath := deriveAuditOutputPath("/tmp/site-a/config.xml", ".md")
	relPath := deriveAuditOutputPath("tmp/site-a/config.xml", ".md")

	assert.Equal(t, "~a_tmp_site-a_config-audit.md", absPath)
	assert.Equal(t, "tmp_site-a_config-audit.md", relPath)
	assert.NotEqual(t, absPath, relPath,
		"absolute and relative inputs with identical segments must produce distinct output paths")

	deepAbsPath := deriveAuditOutputPath("/tmp/site-a/edge/config.xml", ".md")
	deepRelPath := deriveAuditOutputPath("tmp/site-a/edge/config.xml", ".md")

	assert.Equal(t, "~a_tmp_site-a_edge_config-audit.md", deepAbsPath)
	assert.Equal(t, "tmp_site-a_edge_config-audit.md", deepRelPath)
	assert.NotEqual(t, deepAbsPath, deepRelPath,
		"deeply nested absolute and relative inputs with identical segments must produce distinct output paths")
}

// TestDeriveAuditOutputPath_SeparatorPlacementCollision verifies that paths which
// differ only in the placement of dashes versus directory separators produce
// distinct output filenames. Without lossless separator encoding, "a-b/c/config.xml"
// and "a/b-c/config.xml" would both flatten to the same name.
func TestDeriveAuditOutputPath_SeparatorPlacementCollision(t *testing.T) {
	t.Parallel()

	// Two-level collision: dash in first segment vs dash in second segment.
	pathA := deriveAuditOutputPath("a-b/c/config.xml", ".md")
	pathB := deriveAuditOutputPath("a/b-c/config.xml", ".md")

	assert.Equal(t, "a-b_c_config-audit.md", pathA)
	assert.Equal(t, "a_b-c_config-audit.md", pathB)
	assert.NotEqual(t, pathA, pathB,
		"paths differing only in dash vs separator placement must produce distinct output filenames")

	// Deeper nesting: three segments with varied dash placement.
	pathC := deriveAuditOutputPath("x-y/z/w/config.xml", ".md")
	pathD := deriveAuditOutputPath("x/y-z/w/config.xml", ".md")
	pathE := deriveAuditOutputPath("x/y/z-w/config.xml", ".md")

	assert.Equal(t, "x-y_z_w_config-audit.md", pathC)
	assert.Equal(t, "x_y-z_w_config-audit.md", pathD)
	assert.Equal(t, "x_y_z-w_config-audit.md", pathE)
	assert.NotEqual(t, pathC, pathD,
		"deeper nesting: dash in first vs second segment must differ")
	assert.NotEqual(t, pathD, pathE,
		"deeper nesting: dash in second vs third segment must differ")
	assert.NotEqual(t, pathC, pathE,
		"deeper nesting: dash in first vs third segment must differ")
}

// TestDeriveAuditOutputPath_UnderscoreCollision verifies that paths containing
// literal underscores in segment names produce distinct output filenames from
// paths where the underscore position falls on a directory boundary. Without
// lossless underscore escaping, "a_b/c/config.xml" and "a/b_c/config.xml" would
// both flatten to "a_b_c_config-audit.md".
//
//nolint:dupl // Structurally similar to BoundaryUnderscoreCollision but tests mid-segment underscores.
func TestDeriveAuditOutputPath_UnderscoreCollision(t *testing.T) {
	t.Parallel()

	// Two-level collision: underscore in first segment vs second segment.
	pathA := deriveAuditOutputPath("a_b/c/config.xml", ".md")
	pathB := deriveAuditOutputPath("a/b_c/config.xml", ".md")

	assert.Equal(t, "a~ub_c_config-audit.md", pathA)
	assert.Equal(t, "a_b~uc_config-audit.md", pathB)
	assert.NotEqual(t, pathA, pathB,
		"paths differing only in underscore vs separator placement must produce distinct output filenames")

	// Deeper nesting: three segments with varied underscore placement.
	pathC := deriveAuditOutputPath("x_y/z/w/config.xml", ".md")
	pathD := deriveAuditOutputPath("x/y_z/w/config.xml", ".md")
	pathE := deriveAuditOutputPath("x/y/z_w/config.xml", ".md")

	assert.Equal(t, "x~uy_z_w_config-audit.md", pathC)
	assert.Equal(t, "x_y~uz_w_config-audit.md", pathD)
	assert.Equal(t, "x_y_z~uw_config-audit.md", pathE)
	assert.NotEqual(t, pathC, pathD,
		"deeper nesting: underscore in first vs second segment must differ")
	assert.NotEqual(t, pathD, pathE,
		"deeper nesting: underscore in second vs third segment must differ")
	assert.NotEqual(t, pathC, pathE,
		"deeper nesting: underscore in first vs third segment must differ")

	// Mixed: underscore in filename stem with directory underscores.
	pathF := deriveAuditOutputPath("a_b/my_config.xml", ".md")
	pathG := deriveAuditOutputPath("a/b_my_config.xml", ".md")

	assert.Equal(t, "a~ub_my~uconfig-audit.md", pathF)
	assert.Equal(t, "a_b~umy~uconfig-audit.md", pathG)
	assert.NotEqual(t, pathF, pathG,
		"underscore in stem combined with directory underscores must not collide")
}

// TestDeriveAuditOutputPath_BoundaryUnderscoreCollision verifies that paths where
// one segment ends with "_" and the next begins with "_" produce distinct output
// filenames. The old double-underscore escaping scheme collapsed "a_/b/config.xml"
// and "a/_b/config.xml" to the same "a___b_config-audit.md" because escaped
// underscores at segment boundaries were indistinguishable from the separator.
//
//nolint:dupl // Structurally similar to UnderscoreCollision but tests boundary underscores.
func TestDeriveAuditOutputPath_BoundaryUnderscoreCollision(t *testing.T) {
	t.Parallel()

	// Trailing underscore in first segment vs leading underscore in second segment.
	pathA := deriveAuditOutputPath("a_/b/config.xml", ".md")
	pathB := deriveAuditOutputPath("a/_b/config.xml", ".md")

	assert.Equal(t, "a~u_b_config-audit.md", pathA)
	assert.Equal(t, "a_~ub_config-audit.md", pathB)
	assert.NotEqual(t, pathA, pathB,
		"trailing underscore in segment vs leading underscore in next segment must produce distinct filenames")

	// Deeper nesting with multiple boundary underscores.
	pathC := deriveAuditOutputPath("x_/y_/z/config.xml", ".md")
	pathD := deriveAuditOutputPath("x/_y/z_/config.xml", ".md")
	pathE := deriveAuditOutputPath("x/_y/_z/config.xml", ".md")

	assert.Equal(t, "x~u_y~u_z_config-audit.md", pathC)
	assert.Equal(t, "x_~uy_z~u_config-audit.md", pathD)
	assert.Equal(t, "x_~uy_~uz_config-audit.md", pathE)
	assert.NotEqual(t, pathC, pathD,
		"deeper nesting: trailing underscores vs leading underscores must differ")
	assert.NotEqual(t, pathD, pathE,
		"deeper nesting: mixed boundary positions must differ")
	assert.NotEqual(t, pathC, pathE,
		"deeper nesting: all-trailing vs all-leading must differ")

	// Combined: trailing underscore meets leading underscore at same boundary.
	pathF := deriveAuditOutputPath("a_/_b/config.xml", ".md")
	pathG := deriveAuditOutputPath("a__b/config.xml", ".md")

	assert.Equal(t, "a~u_~ub_config-audit.md", pathF)
	assert.Equal(t, "a~u~ub_config-audit.md", pathG)
	assert.NotEqual(t, pathF, pathG,
		"a_/_b (two segments) vs a__b (one segment) must produce distinct filenames")
}
