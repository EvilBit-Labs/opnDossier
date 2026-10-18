package opnsense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNaturalCompareFold pins the cases where PHP's natural sort and a byte
// comparison disagree. Each pair is checked in both directions.
func TestNaturalCompareFold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "empty strings", a: "", b: "", want: 0},
		{name: "empty sorts first", a: "", b: "a", want: -1},
		{name: "numbers compare by value", a: "img2", b: "img12", want: -1},
		{name: "longer number is larger", a: "x9", b: "x10", want: -1},
		{name: "equal length numbers compare by digit", a: "img10", b: "img12", want: -1},
		{name: "case is ignored", a: "abc", b: "ABC", want: 0},
		{name: "case is ignored before digits", a: "A1", b: "a2", want: -1},
		{name: "leading zeros at the start are skipped", a: "007", b: "7", want: 0},
		{name: "a run starting with 0 compares digit by digit", a: "x01", b: "x1", want: -1},
		{name: "whitespace is skipped", a: "  5", b: "5", want: 0},
		{name: "prefix sorts first", a: "ab", b: "abc", want: -1},
		{
			name: "uuid tie-break in a sort key",
			a:    "                           100,9aaaaaaa-0000-4000-8000-000000000000",
			b:    "                           100,10aaaaaa-0000-4000-8000-000000000000",
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, naturalCompareFold(tt.a, tt.b))
			assert.Equal(t, -tt.want, naturalCompareFold(tt.b, tt.a))
		})
	}
}
