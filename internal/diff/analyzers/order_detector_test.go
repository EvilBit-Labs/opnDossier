package analyzers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOrderDetector_DetectReorders(t *testing.T) {
	d := NewOrderDetector()

	tests := []struct {
		name     string
		oldIDs   []string
		newIDs   []string
		expected int // number of reordered elements
	}{
		{
			name:     "identical order",
			oldIDs:   []string{"a", "b", "c"},
			newIDs:   []string{"a", "b", "c"},
			expected: 0,
		},
		{
			name:     "reversed order",
			oldIDs:   []string{"a", "b", "c"},
			newIDs:   []string{"c", "b", "a"},
			expected: 2, // a and c changed, b stayed at index 1
		},
		{
			name:     "single swap",
			oldIDs:   []string{"a", "b"},
			newIDs:   []string{"b", "a"},
			expected: 2,
		},
		{
			name:     "element added does not count as reorder",
			oldIDs:   []string{"a", "b"},
			newIDs:   []string{"a", "c", "b"},
			expected: 1, // b moved from 1 to 2
		},
		{
			name:     "element removed does not count as reorder",
			oldIDs:   []string{"a", "b", "c"},
			newIDs:   []string{"a", "c"},
			expected: 1, // c moved from 2 to 1
		},
		{
			name:     "empty lists",
			oldIDs:   []string{},
			newIDs:   []string{},
			expected: 0,
		},
		{
			name:     "no overlap",
			oldIDs:   []string{"a", "b"},
			newIDs:   []string{"c", "d"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reorders := d.DetectReorders(tt.oldIDs, tt.newIDs)
			assert.Len(t, reorders, tt.expected)
		})
	}
}

func TestOrderDetector_DetectReorders_PositionValues(t *testing.T) {
	d := NewOrderDetector()

	reorders := d.DetectReorders(
		[]string{"uuid-1", "uuid-2", "uuid-3"},
		[]string{"uuid-3", "uuid-1", "uuid-2"},
	)

	// Build map for easy lookup
	byID := make(map[string]OrderChange)
	for _, r := range reorders {
		byID[r.ID] = r
	}

	// uuid-1 moved from 0 to 1
	assert.Equal(t, 0, byID["uuid-1"].OldPosition)
	assert.Equal(t, 1, byID["uuid-1"].NewPosition)

	// uuid-3 moved from 2 to 0
	assert.Equal(t, 2, byID["uuid-3"].OldPosition)
	assert.Equal(t, 0, byID["uuid-3"].NewPosition)
}

func TestOrderDetector_HasReorders(t *testing.T) {
	d := NewOrderDetector()

	assert.False(t, d.HasReorders([]string{"a", "b"}, []string{"a", "b"}))
	assert.True(t, d.HasReorders([]string{"a", "b"}, []string{"b", "a"}))
}
