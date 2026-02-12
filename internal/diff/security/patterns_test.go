package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultPatterns_NotEmpty(t *testing.T) {
	patterns := DefaultPatterns()
	assert.NotEmpty(t, patterns)
}

func TestDefaultPatterns_AllHaveRequiredFields(t *testing.T) {
	for _, p := range DefaultPatterns() {
		t.Run(p.Name, func(t *testing.T) {
			assert.NotEmpty(t, p.Name, "pattern must have a name")
			assert.NotEmpty(t, p.Description, "pattern must have a description")
			assert.NotEmpty(t, p.Impact, "pattern must have an impact level")
			assert.Contains(t, []string{"high", "medium", "low"}, p.Impact,
				"impact must be high, medium, or low")
		})
	}
}

func TestDefaultPatterns_NamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range DefaultPatterns() {
		assert.False(t, seen[p.Name], "duplicate pattern name: %s", p.Name)
		seen[p.Name] = true
	}
}
