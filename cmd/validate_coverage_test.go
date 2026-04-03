package cmd

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUpdateMaxExitCode verifies the atomic max-exit-code update logic
// used by the validate command for concurrent file processing.
func TestUpdateMaxExitCode(t *testing.T) {
	tests := []struct {
		name    string
		initial int32
		newCode int
		wantMax int32
	}{
		{"higher code updates", 0, 3, 3},
		{"equal code is noop", 3, 3, 3},
		{"lower code is noop", 3, 1, 3},
		{"zero to zero is noop", 0, 0, 0},
		{"first update from zero", 0, 4, 4},
		{"sequential increases", 1, 2, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var maxCode atomic.Int32
			maxCode.Store(tt.initial)

			updateMaxExitCode(&maxCode, tt.newCode)

			assert.Equal(t, tt.wantMax, maxCode.Load())
		})
	}

	t.Run("multiple sequential updates converge to max", func(t *testing.T) {
		var maxCode atomic.Int32

		codes := []int{1, 4, 2, 3, 0, 4, 1}
		for _, code := range codes {
			updateMaxExitCode(&maxCode, code)
		}

		assert.Equal(t, int32(4), maxCode.Load())
	})
}
