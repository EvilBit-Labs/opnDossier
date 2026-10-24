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
		{name: "identical strings", a: "abc", b: "abc", want: 0},
		{name: "the first letter that differs decides", a: "abc", b: "abd", want: -1},
		{name: "numbers compare by value", a: "img2", b: "img12", want: -1},
		{name: "numbers alone compare by value", a: "9", b: "10", want: -1},
		{name: "longer number is larger", a: "x9", b: "x10", want: -1},
		{name: "equal length numbers compare by digit", a: "img10", b: "img12", want: -1},
		{name: "between numbers of one length the first digit that differs decides", a: "19", b: "21", want: -1},
		{name: "text after equal numbers decides", a: "a10b", b: "a10c", want: -1},
		{name: "a digit sorts before a letter", a: "1a2b", b: "f3aa", want: -1},
		{name: "a uuid's leading digits compare as a number", a: "2a2b", b: "10aa", want: -1},
		{name: "case is ignored", a: "abc", b: "ABC", want: 0},
		{name: "case is ignored at the end of the alphabet", a: "z", b: "Z", want: 0},
		{name: "case is ignored before digits", a: "A1", b: "a2", want: -1},
		{name: "leading zeros at the start are skipped", a: "007", b: "7", want: 0},
		{name: "so a number with them is its value", a: "05", b: "1", want: 1},
		{name: "a run of zeros is zero", a: "0", b: "00", want: 0},
		{name: "a run starting with 0 compares digit by digit", a: "x01", b: "x1", want: -1},
		{name: "and is not read as a number", a: "a010", b: "a02", want: -1},
		{name: "a shorter run of zeros sorts first", a: "a0", b: "a00", want: -1},
		{name: "a zero sorts before a run starting with zero", a: "a0", b: "a01", want: -1},
		{name: "whitespace is skipped", a: "  5", b: "5", want: 0},
		{name: "a tab is whitespace", a: "\t5", b: "5", want: 0},
		{name: "whitespace inside is skipped", a: "a  5", b: "a 4", want: 1},
		{name: "prefix sorts first", a: "ab", b: "abc", want: -1},
		{name: "a number that ends one string sorts it first", a: "a1", b: "a1b", want: -1},
		{name: "a longer number wins over a letter", a: "a12", b: "a1b", want: 1},
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
