package opnsense

import "cmp"

// naturalCompareFold orders two strings the way PHP's ksort does with
// SORT_NATURAL | SORT_FLAG_CASE, which is how OPNsense's sortedBy orders its
// keys. It ports strnatcmp_ex from php-src: runs of digits compare as numbers,
// a run starting with 0 compares digit by digit, whitespace is skipped, and
// letters compare without case.
func naturalCompareFold(a, b string) int {
	if a == "" || b == "" {
		return cmp.Compare(len(a), len(b))
	}

	ai, bi := skipLeadingZeros(a), skipLeadingZeros(b)
	for {
		for isSpace(byteAt(a, ai)) {
			ai++
		}
		for isSpace(byteAt(b, bi)) {
			bi++
		}

		ca, cb := byteAt(a, ai), byteAt(b, bi)
		if isDigit(ca) && isDigit(cb) {
			var order int
			if ca == '0' || cb == '0' {
				order = compareDigitsLeft(a, &ai, b, &bi)
			} else {
				order = compareDigitsRight(a, &ai, b, &bi)
			}

			switch {
			case order != 0:
				return order
			case ai == len(a) && bi == len(b):
				return 0
			case ai == len(a):
				return -1
			case bi == len(b):
				return 1
			}

			ca, cb = a[ai], b[bi]
		}

		if order := cmp.Compare(toUpper(ca), toUpper(cb)); order != 0 {
			return order
		}

		ai++
		bi++
		switch {
		case ai >= len(a) && bi >= len(b):
			return 0
		case ai >= len(a):
			return -1
		case bi >= len(b):
			return 1
		}
	}
}

// compareDigitsRight compares two runs of digits as numbers: the longer run is
// larger, and runs of equal length compare by their first differing digit. It
// leaves ai and bi where it stopped, as the C original does.
func compareDigitsRight(a string, ai *int, b string, bi *int) int {
	bias := 0
	for ; ; *ai, *bi = *ai+1, *bi+1 {
		aDigit, bDigit := isDigit(byteAt(a, *ai)), isDigit(byteAt(b, *bi))
		switch {
		case !aDigit && !bDigit:
			return bias
		case !aDigit:
			return -1
		case !bDigit:
			return 1
		case bias == 0:
			bias = cmp.Compare(a[*ai], b[*bi])
		}
	}
}

// compareDigitsLeft compares two runs of digits digit by digit, so the first
// difference decides and a shorter run is smaller. It leaves ai and bi where
// it stopped.
func compareDigitsLeft(a string, ai *int, b string, bi *int) int {
	for ; ; *ai, *bi = *ai+1, *bi+1 {
		aDigit, bDigit := isDigit(byteAt(a, *ai)), isDigit(byteAt(b, *bi))
		switch {
		case !aDigit && !bDigit:
			return 0
		case !aDigit:
			return -1
		case !bDigit:
			return 1
		case a[*ai] != b[*bi]:
			return cmp.Compare(a[*ai], b[*bi])
		}
	}
}

// skipLeadingZeros returns the index of the first character after the zeros
// that lead a number at the start of s, keeping the last digit.
func skipLeadingZeros(s string) int {
	i := 0
	for i+1 < len(s) && s[i] == '0' && isDigit(s[i+1]) {
		i++
	}

	return i
}

// byteAt returns s[i], or 0 past the end, as C reads the terminator.
func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}

	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isSpace(c byte) bool { return c == ' ' || (c >= '\t' && c <= '\r') }

func toUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}

	return c
}
