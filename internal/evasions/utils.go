package evasions

// uniqueStrings removes duplicate strings from the input slice
func UniqueStrings(input []string) []string {
	seen := map[string]struct{}{}
	var result []string

	for _, s := range input {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}

	return result
}
