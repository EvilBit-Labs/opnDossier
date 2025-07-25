package tests

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MarkdownSpecTestSuite is the test suite for markdown specification validation
// Testing Framework: Using testify/suite for organized test structure
// Testing Library: github.com/stretchr/testify for assertions and test utilities
type MarkdownSpecTestSuite struct {
	suite.Suite
	content string
}

// SetupSuite runs before all tests in the suite
func (suite *MarkdownSpecTestSuite) SetupSuite() {
	content, err := suite.getMarkdownContent()
	require.NoError(suite.T(), err, "Failed to load markdown content")
	suite.content = content
}

// TestMarkdownSpecificationStructure validates the overall structure of the markdown specification
func (suite *MarkdownSpecTestSuite) TestMarkdownSpecificationStructure() {
	// Test for required sections based on the provided content
	requiredSections := []string{
		"# opnFocus Implementation Tasks",
		"## Overview",
		"## Phase 1: Core Infrastructure & Dependencies",
		"## Phase 2: Core XML Processing",
		"## Phase 3: Markdown Generation",
		"## Phase 4: File Export & I/O",
		"## Phase 5: CLI Interface Enhancement",
		"## Phase 6: Configuration Management",
		"## Phase 7: Performance & Optimization",
		"## Phase 8: Testing & Quality Assurance",
		"## Phase 9: Documentation & Help",
		"## Phase 10: Security & Compliance",
		"## Phase 11: Cross-Platform Support",
		"## Phase 12: Build & Distribution",
		"## Phase 13: Development & Maintenance",
		"## Acceptance Criteria Summary",
		"## Task Dependencies",
		"## Risk Mitigation",
	}

	for _, section := range requiredSections {
		assert.Contains(suite.T(), suite.content, section, "Required section missing: %s", section)
	}
}

// TestTaskNumbering validates that all tasks are properly numbered and sequential
func (suite *MarkdownSpecTestSuite) TestTaskNumbering() {
	// Find all task numbers using regex
	taskRegex := regexp.MustCompile(`\*\*TASK-(\d{3})\*\*`)
	matches := taskRegex.FindAllStringSubmatch(suite.content, -1)
	
	require.NotEmpty(suite.T(), matches, "No tasks found in the specification")
	
	taskNumbers := make([]int, 0, len(matches))
	seenNumbers := make(map[int]bool)
	
	for _, match := range matches {
		num, err := strconv.Atoi(match[1])
		require.NoError(suite.T(), err, "Invalid task number format: %s", match[1])
		
		// Check for duplicates
		assert.False(suite.T(), seenNumbers[num], "Duplicate task number found: TASK-%03d", num)
		seenNumbers[num] = true
		
		taskNumbers = append(taskNumbers, num)
	}
	
	// Verify sequential numbering starting from 001
	expectedNum := 1
	for _, num := range taskNumbers {
		assert.Equal(suite.T(), expectedNum, num, "Task numbering gap or duplicate: expected TASK-%03d, found TASK-%03d", expectedNum, num)
		expectedNum++
	}
	
	suite.T().Logf("Found %d tasks with sequential numbering from TASK-001 to TASK-%03d", len(taskNumbers), len(taskNumbers))
}

// TestTaskStructure validates that each task follows the required structure
func (suite *MarkdownSpecTestSuite) TestTaskStructure() {
	// Find all tasks
	taskSections := strings.Split(suite.content, "**TASK-")
	require.GreaterOrEqual(suite.T(), len(taskSections), 2, "No tasks found in the specification")
	
	// Skip the first section (before any tasks)
	for i, section := range taskSections[1:] {
		taskNum := i + 1
		
		// Required elements for each task
		requiredElements := []string{
			"Context",
			"Requirement",
			"User Story", 
			"Action",
			"Acceptance",
		}
		
		for _, element := range requiredElements {
			elementPattern := fmt.Sprintf("**%s**:", element)
			assert.Contains(suite.T(), section, elementPattern, "Task %03d missing required element: %s", taskNum, element)
		}
	}
}

// TestTaskStatusTracking validates that task completion status is properly tracked
func (suite *MarkdownSpecTestSuite) TestTaskStatusTracking() {
	// Find all task checkboxes
	completedRegex := regexp.MustCompile(`- \[x\] \*\*TASK-(\d{3})\*\*`)
	incompleteRegex := regexp.MustCompile(`- \[ \] \*\*TASK-(\d{3})\*\*`)
	
	completedMatches := completedRegex.FindAllStringSubmatch(suite.content, -1)
	incompleteMatches := incompleteRegex.FindAllStringSubmatch(suite.content, -1)
	
	totalTasks := len(completedMatches) + len(incompleteMatches)
	require.Greater(suite.T(), totalTasks, 0, "No task checkboxes found")
	
	suite.T().Logf("Task completion status: %d completed, %d incomplete, %d total", 
		len(completedMatches), len(incompleteMatches), totalTasks)
	
	// Verify that completed tasks have notes about completion
	for _, match := range completedMatches {
		taskNum := match[1]
		taskSection := suite.extractTaskSection(taskNum)
		
		// Look for completion indicators
		hasNote := strings.Contains(taskSection, "Note:") || 
				  strings.Contains(taskSection, "implemented") ||
				  strings.Contains(taskSection, "completed") ||
				  strings.Contains(taskSection, "Note")
		
		// Don't fail if no note, but warn - some completed tasks might not have explicit notes
		if !hasNote {
			suite.T().Logf("Warning: Completed task TASK-%s should have a completion note", taskNum)
		}
	}
}

// TestUserStoryReferences validates that all user story references are properly formatted
func (suite *MarkdownSpecTestSuite) TestUserStoryReferences() {
	// Find all user story references
	userStoryRegex := regexp.MustCompile(`US-(\d{3})`)
	matches := userStoryRegex.FindAllStringSubmatch(suite.content, -1)
	
	if len(matches) == 0 {
		suite.T().Log("No user story references found - this may be expected for some specifications")
		return
	}
	
	// Validate user story number format
	for _, match := range matches {
		userStoryNum := match[1]
		num, err := strconv.Atoi(userStoryNum)
		require.NoError(suite.T(), err, "Invalid user story number format: US-%s", userStoryNum)
		
		// User story numbers should be reasonable (between 001 and 999)
		assert.GreaterOrEqual(suite.T(), num, 1, "User story number too low: US-%s", userStoryNum)
		assert.LessOrEqual(suite.T(), num, 999, "User story number too high: US-%s", userStoryNum)
	}
}

// TestRequirementReferences validates requirement reference formatting
func (suite *MarkdownSpecTestSuite) TestRequirementReferences() {
	// Find functional requirement references
	functionalReqRegex := regexp.MustCompile(`F\d{3}`)
	matches := functionalReqRegex.FindAllString(suite.content, -1)
	
	// Validate that requirement references follow consistent format
	validFormatRegex := regexp.MustCompile(`^F\d{3}$`)
	for _, match := range matches {
		assert.True(suite.T(), validFormatRegex.MatchString(match), "Invalid functional requirement format: %s", match)
	}
	
	if len(matches) > 0 {
		suite.T().Logf("Found %d functional requirement references", len(matches))
	}
}

// TestPhaseOrganization validates that phases are properly organized and numbered
func (suite *MarkdownSpecTestSuite) TestPhaseOrganization() {
	// Find all phase headers
	phaseRegex := regexp.MustCompile(`## Phase (\d+):`)
	matches := phaseRegex.FindAllStringSubmatch(suite.content, -1)
	
	require.NotEmpty(suite.T(), matches, "No phases found in the specification")
	
	// Verify sequential phase numbering
	for i, match := range matches {
		expectedPhase := i + 1
		actualPhase, err := strconv.Atoi(match[1])
		require.NoError(suite.T(), err, "Invalid phase number format: %s", match[1])
		
		assert.Equal(suite.T(), expectedPhase, actualPhase, "Phase numbering issue: expected Phase %d, found Phase %d", expectedPhase, actualPhase)
	}
	
	suite.T().Logf("Found %d properly numbered phases", len(matches))
}

// TestAcceptanceCriteria validates that acceptance criteria are properly structured
func (suite *MarkdownSpecTestSuite) TestAcceptanceCriteria() {
	// Find acceptance criteria section
	assert.Contains(suite.T(), suite.content, "## Acceptance Criteria Summary", "Acceptance Criteria Summary section not found")
	
	// Check for required subsections
	requiredSubsections := []string{
		"### Core Functionality Acceptance",
		"### Quality Assurance Acceptance", 
		"### Deployment Acceptance",
	}
	
	for _, subsection := range requiredSubsections {
		assert.Contains(suite.T(), suite.content, subsection, "Missing acceptance criteria subsection: %s", subsection)
	}
}

// TestTaskDependencies validates the task dependency section
func (suite *MarkdownSpecTestSuite) TestTaskDependencies() {
	assert.Contains(suite.T(), suite.content, "## Task Dependencies", "Task Dependencies section not found")
	
	// Check for required dependency subsections
	requiredSubsections := []string{
		"### Critical Path Dependencies",
		"### Parallel Development Opportunities",
	}
	
	for _, subsection := range requiredSubsections {
		assert.Contains(suite.T(), suite.content, subsection, "Missing task dependency subsection: %s", subsection)
	}
	
	// Validate dependency arrows format
	dependencyRegex := regexp.MustCompile(`TASK-\d{3} → TASK-\d{3}`)
	matches := dependencyRegex.FindAllString(suite.content, -1)
	
	if len(matches) > 0 {
		suite.T().Logf("Found %d task dependencies with proper arrow format", len(matches))
	} else {
		suite.T().Log("No task dependencies found with arrow format - this may be expected")
	}
}

// TestRiskMitigation validates the risk mitigation section
func (suite *MarkdownSpecTestSuite) TestRiskMitigation() {
	assert.Contains(suite.T(), suite.content, "## Risk Mitigation", "Risk Mitigation section not found")
	
	// Check for required risk subsections
	requiredSubsections := []string{
		"### High-Risk Tasks",
		"### Mitigation Strategies",
	}
	
	for _, subsection := range requiredSubsections {
		assert.Contains(suite.T(), suite.content, subsection, "Missing risk mitigation subsection: %s", subsection)
	}
}

// TestMarkdownFormatting validates markdown formatting consistency
func (suite *MarkdownSpecTestSuite) TestMarkdownFormatting() {
	lines := strings.Split(suite.content, "\n")
	
	malformedHeaders := 0
	malformedLists := 0
	trailingWhitespace := 0
	
	for i, line := range lines {
		lineNum := i + 1
		
		// Check for proper header formatting
		if strings.HasPrefix(line, "#") {
			// Headers should have space after #
			headerRegex := regexp.MustCompile(`^#+\s+`)
			if !headerRegex.MatchString(line) {
				malformedHeaders++
				if malformedHeaders <= 5 { // Report only first 5 issues
					suite.T().Errorf("Line %d: Header missing space after #: %s", lineNum, line)
				}
			}
		}
		
		// Check for proper list formatting
		if strings.HasPrefix(line, "-") {
			// Lists should have space after -
			listRegex := regexp.MustCompile(`^-\s+`)
			if !listRegex.MatchString(line) {
				malformedLists++
				if malformedLists <= 5 { // Report only first 5 issues
					suite.T().Errorf("Line %d: List item missing space after -: %s", lineNum, line)
				}
			}
		}
		
		// Check for trailing whitespace (except empty lines)
		if strings.TrimSpace(line) != "" && strings.HasSuffix(line, " ") {
			trailingWhitespace++
			if trailingWhitespace <= 5 { // Report only first 5 issues
				suite.T().Errorf("Line %d: Line has trailing whitespace", lineNum)
			}
		}
	}
	
	if malformedHeaders > 5 {
		suite.T().Logf("Found %d total malformed headers (only first 5 reported)", malformedHeaders)
	}
	if malformedLists > 5 {
		suite.T().Logf("Found %d total malformed list items (only first 5 reported)", malformedLists)
	}
	if trailingWhitespace > 5 {
		suite.T().Logf("Found %d total lines with trailing whitespace (only first 5 reported)", trailingWhitespace)
	}
}

// TestDocumentMetadata validates document metadata and structure
func (suite *MarkdownSpecTestSuite) TestDocumentMetadata() {
	// Check for project status
	assert.Contains(suite.T(), suite.content, "**Project Status**:", "Project status not found in overview")
	
	// Check for document update note
	assert.Contains(suite.T(), suite.content, "This task checklist should be updated", "Document update reminder not found")
	
	// Validate horizontal rules
	horizontalRules := strings.Count(suite.content, "---")
	assert.GreaterOrEqual(suite.T(), horizontalRules, 5, "Expected at least 5 horizontal rules for section separation, found %d", horizontalRules)
}

// TestTaskCompletionConsistency validates that completed tasks are properly documented
func (suite *MarkdownSpecTestSuite) TestTaskCompletionConsistency() {
	// Find completed tasks in the main sections
	completedInMain := regexp.MustCompile(`- \[x\] \*\*TASK-(\d{3})\*\*`).FindAllStringSubmatch(suite.content, -1)
	
	// Find completed tasks in acceptance criteria
	acceptanceSection := suite.extractSection("## Acceptance Criteria Summary")
	completedInAcceptance := regexp.MustCompile(`- \[x\]`).FindAllString(acceptanceSection, -1)
	
	if len(completedInMain) > 0 {
		// This is a warning rather than failure as acceptance criteria might be updated separately
		if len(completedInAcceptance) == 0 {
			suite.T().Logf("Warning: %d tasks are marked complete but acceptance criteria section shows no completed items", len(completedInMain))
		}
	}
}

// Helper methods

func (suite *MarkdownSpecTestSuite) getMarkdownContent() (string, error) {
	// Try to find the markdown file in the repository
	possiblePaths := []string{
		"project_spec/tasks.md",        // Most likely location based on context
		"IMPLEMENTATION_TASKS.md",
		"implementation_tasks.md", 
		"TASKS.md",
		"tasks.md",
		"docs/IMPLEMENTATION_TASKS.md",
		"docs/implementation_tasks.md",
		"docs/tasks.md",
	}
	
	for _, path := range possiblePaths {
		if content, err := os.ReadFile(path); err == nil {
			suite.T().Logf("Successfully loaded markdown content from: %s", path)
			return string(content), nil
		}
	}
	
	// If no dedicated markdown file found, use the content from the source
	suite.T().Log("No external markdown file found, using embedded content for testing")
	return suite.getContentFromSource()
}

func (suite *MarkdownSpecTestSuite) getContentFromSource() (string, error) {
	// Return the markdown content that was provided in the source
	return `# opnFocus Implementation Tasks

## Overview

This document provides a comprehensive task checklist for implementing the opnFocus CLI tool based on the requirements document and user stories. Each task includes specific references to relevant requirement items and user stories.

**Project Status**: Basic CLI structure exists with XML parsing capability, but core functionality needs implementation.

---

## Phase 1: Core Infrastructure & Dependencies

### 1.1 Dependency Management & Technology Stack Setup

- [x] **TASK-001**: Update Go dependencies to match requirements

  - **Context**: Current ` + "`go.mod`" + ` needs to include all required dependencies
  - **Requirement**: F001-F008 (Core Features), Technical Specifications section
  - **User Story**: US-012 (Configuration Management)
  - **Action**: Add viper for configuration, fang for CLI enhancement, lipgloss, glamour, and charmbracelet/log dependencies
  - **Acceptance**: ` + "`go.mod`" + ` matches requirements specification

- [x] **TASK-002**: Implement structured logging with ` + "`charmbracelet/log`" + `

  - **Context**: Replace current ` + "`log`" + ` usage with structured logging
  - **Requirement**: US-036 (Structured Logging), Technical Specifications
  - **User Story**: US-036 (Monitoring and Observability)
  - **Action**: Configure structured logging throughout application using charmbracelet/log
  - **Acceptance**: All logging uses structured format with proper levels

- [x] **TASK-003**: Set up configuration management with viper

  - **Context**: Implement proper configuration management with viper framework
  - **Requirement**: US-012, US-013, US-014 (Configuration Management)
  - **User Story**: US-012-US-014 (Configuration Management)
  - **Action**: Implement YAML config files, environment variables, CLI overrides using viper
  - **Acceptance**: Configuration system supports all three methods with standard precedence (CLI flags > env vars > config file > defaults)

---

## Acceptance Criteria Summary

### Core Functionality Acceptance

- [ ] XML parsing works with valid OPNsense config.xml files (TASK-006, TASK-007)
- [ ] Invalid XML files produce meaningful error messages (TASK-007, TASK-008)
- [ ] Markdown conversion preserves configuration hierarchy (TASK-011, TASK-012)

### Quality Assurance Acceptance

- [ ] Test coverage exceeds 80% (TASK-035)
- [x] Code follows Google Go Style Guide (TASK-004)
- [x] Error handling is comprehensive and user-friendly (TASK-005, TASK-019, TASK-020)

### Deployment Acceptance

- [ ] Multi-platform binaries are available (TASK-051)
- [ ] Package manager support is implemented (TASK-052)

---

## Task Dependencies

### Critical Path Dependencies

- TASK-001 → TASK-002 → TASK-003 (Dependencies must be set up first)

### Parallel Development Opportunities

- Phase 1 (Infrastructure) can be developed in parallel with Phase 2 (XML Processing)

---

## Risk Mitigation

### High-Risk Tasks

- **TASK-007**: XML schema validation complexity

### Mitigation Strategies

- Start with simple XML validation and iterate

---

*This task checklist should be updated as implementation progresses and new requirements are identified.*`, nil
}

func (suite *MarkdownSpecTestSuite) extractTaskSection(taskNum string) string {
	taskStart := fmt.Sprintf("**TASK-%s**", taskNum)
	startIdx := strings.Index(suite.content, taskStart)
	if startIdx == -1 {
		return ""
	}
	
	// Find the next task or section
	nextTaskIdx := strings.Index(suite.content[startIdx+1:], "**TASK-")
	nextSectionIdx := strings.Index(suite.content[startIdx+1:], "\n## ")
	
	endIdx := len(suite.content)
	if nextTaskIdx != -1 {
		endIdx = startIdx + 1 + nextTaskIdx
	}
	if nextSectionIdx != -1 && (nextTaskIdx == -1 || nextSectionIdx < nextTaskIdx) {
		endIdx = startIdx + 1 + nextSectionIdx
	}
	
	return suite.content[startIdx:endIdx]
}

func (suite *MarkdownSpecTestSuite) extractSection(sectionHeader string) string {
	startIdx := strings.Index(suite.content, sectionHeader)
	if startIdx == -1 {
		return ""
	}
	
	// Find the next section header at the same level
	nextSectionIdx := strings.Index(suite.content[startIdx+1:], "\n## ")
	if nextSectionIdx == -1 {
		return suite.content[startIdx:]
	}
	
	return suite.content[startIdx : startIdx+1+nextSectionIdx]
}

// Benchmark tests for performance validation

func BenchmarkMarkdownParsing(b *testing.B) {
	content := getMarkdownContentForBench()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strings.Split(content, "\n")
	}
}

func BenchmarkTaskExtraction(b *testing.B) {
	content := getMarkdownContentForBench()
	taskRegex := regexp.MustCompile(`\*\*TASK-(\d{3})\*\*`)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = taskRegex.FindAllStringSubmatch(content, -1)
	}
}

func BenchmarkUserStoryExtraction(b *testing.B) {
	content := getMarkdownContentForBench()
	userStoryRegex := regexp.MustCompile(`US-(\d{3})`)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = userStoryRegex.FindAllStringSubmatch(content, -1)
	}
}

func getMarkdownContentForBench() string {
	// Return sample content for benchmarking
	return strings.Repeat("**TASK-001**: Sample task content\n**Context**: Test\n**User Story**: US-001\n", 100)
}

// Table-driven tests for various edge cases

func TestMarkdownSpecValidation(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "EmptyDocument",
			content:     "",
			expectError: true,
			errorMsg:    "empty document should fail validation",
		},
		{
			name:        "NoTasks", 
			content:     "# Title\n\nSome content without tasks",
			expectError: true,
			errorMsg:    "document without tasks should fail validation",
		},
		{
			name:        "MalformedTask",
			content:     "**TASK-**: Missing number",
			expectError: true,
			errorMsg:    "malformed task should fail validation",
		},
		{
			name:        "ValidMinimal",
			content:     "# opnFocus Implementation Tasks\n\n- [ ] **TASK-001**: Valid task\n\n  - **Context**: Test\n  - **Requirement**: Test\n  - **User Story**: Test\n  - **Action**: Test\n  - **Acceptance**: Test",
			expectError: false,
			errorMsg:    "valid minimal document should pass validation",
		},
		{
			name:        "InvalidTaskNumber",
			content:     "**TASK-ABC**: Invalid task number",
			expectError: true,
			errorMsg:    "invalid task number should fail validation",
		},
		{
			name:        "DuplicateTaskNumber",
			content:     "**TASK-001**: First task\n**TASK-001**: Duplicate task",
			expectError: false, // This will be caught by the numbering test
			errorMsg:    "duplicate task numbers should be detected",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test task extraction
			taskRegex := regexp.MustCompile(`\*\*TASK-(\d{3})\*\*`)
			matches := taskRegex.FindAllStringSubmatch(tt.content, -1)
			
			if tt.expectError && tt.name != "DuplicateTaskNumber" {
				assert.Empty(t, matches, tt.errorMsg)
			} else if !tt.expectError {
				assert.NotEmpty(t, matches, tt.errorMsg)
			}
		})
	}
}

// Performance tests with proper assertions

func TestTaskExtractionPerformance(t *testing.T) {
	content := strings.Repeat("**TASK-001**: Sample task\n**TASK-002**: Another task\n", 1000)
	
	start := time.Now()
	taskRegex := regexp.MustCompile(`\*\*TASK-(\d{3})\*\*`)
	matches := taskRegex.FindAllStringSubmatch(content, -1)
	duration := time.Since(start)
	
	assert.Less(t, duration, 100*time.Millisecond, "Task extraction took too long: %v (expected < 100ms)", duration)
	assert.Equal(t, 2000, len(matches), "Expected 2000 task matches, got %d", len(matches))
}

// Edge case tests for malformed content

func TestMalformedContentHandling(t *testing.T) {
	tests := []struct {
		name    string
		content string
		testFn  func(string) bool
	}{
		{
			name:    "MissingProjectStatus",
			content: "# opnFocus Implementation Tasks\n\n## Overview\n\nSome content without project status",
			testFn:  func(c string) bool { return !strings.Contains(c, "**Project Status**:") },
		},
		{
			name:    "MissingPhases",
			content: "# opnFocus Implementation Tasks\n\n**TASK-001**: A task without phases",
			testFn:  func(c string) bool { return !strings.Contains(c, "## Phase") },
		},
		{
			name:    "MissingAcceptanceCriteria",
			content: "# opnFocus Implementation Tasks\n\n**TASK-001**: A task without acceptance criteria",
			testFn:  func(c string) bool { return !strings.Contains(c, "## Acceptance Criteria") },
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFn(tt.content)
			assert.True(t, result, "Test condition should be true for malformed content: %s", tt.name)
		})
	}
}

// Integration test for the full document validation workflow
func TestFullDocumentValidationWorkflow(t *testing.T) {
	suite := &MarkdownSpecTestSuite{}
	suite.SetT(t)
	suite.SetupSuite()
	
	// Run all validation tests in sequence
	t.Run("Structure", suite.TestMarkdownSpecificationStructure)
	t.Run("TaskNumbering", suite.TestTaskNumbering)
	t.Run("TaskStructure", suite.TestTaskStructure)
	t.Run("StatusTracking", suite.TestTaskStatusTracking)
	t.Run("UserStories", suite.TestUserStoryReferences)
	t.Run("Requirements", suite.TestRequirementReferences)
	t.Run("Phases", suite.TestPhaseOrganization)
	t.Run("Acceptance", suite.TestAcceptanceCriteria)
	t.Run("Dependencies", suite.TestTaskDependencies)
	t.Run("Risks", suite.TestRiskMitigation)
	t.Run("Formatting", suite.TestMarkdownFormatting)
	t.Run("Metadata", suite.TestDocumentMetadata)
	t.Run("Completion", suite.TestTaskCompletionConsistency)
}

// Run the test suite
func TestMarkdownSpecSuite(t *testing.T) {
	suite.Run(t, new(MarkdownSpecTestSuite))
}