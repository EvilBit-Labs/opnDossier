package pfsense

// collectNonEmpty returns a slice containing only non-empty strings from the input.
// Duplicated from the opnsense package since the function is unexported.
func collectNonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			result = append(result, v)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}
