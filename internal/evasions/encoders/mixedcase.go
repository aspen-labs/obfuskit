package encoders

import (
	"obfuskit/internal/evasions"
	"obfuskit/types"
	"strings"
	"unicode"
)

// MixedCaseVariants generates mixed case variants of the input payload
// based on the specified obfuscation level
func MixedCaseVariants(payload string, level types.EvasionLevel) []string {
	var variants []string

	// Basic mixed case patterns
	variants = append(variants,
		alternatingCase(payload),   // aLtErNaTiNg CaSe
		randomCase(payload, 0.5),   // Random 50% case changes
		firstLetterUpper(payload),  // First letter uppercase
		lastLetterUpper(payload),   // Last letter uppercase
		wordBoundaryUpper(payload), // First letter of each word uppercase
	)

	// Return basic variants if level is Basic
	if level == types.EvasionLevelBasic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more sophisticated case manipulation
	variants = append(variants,
		randomCase(payload, 0.3),    // Random 30% case changes
		randomCase(payload, 0.7),    // Random 70% case changes
		vowelUppercase(payload),     // Uppercase vowels only
		consonantUppercase(payload), // Uppercase consonants only
		reverseCase(payload),        // Opposite of normal case
		camelCase(payload),          // camelCase style
		snakeToUpperCase(payload),   // SNAKE_CASE style
	)

	// Return medium variants if level is Medium
	if level == types.EvasionLevelMedium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds Unicode and complex case manipulations
	variants = append(variants,
		unicodeCaseVariants(payload), // Unicode case transformations
		leetSpeakCase(payload),       // L33t speak with case
		zebraCase(payload),           // zEbRa CaSe pattern
		inverseZebraCase(payload),    // ZeBrA cAsE pattern
		randomWordCase(payload),      // Random case per word
		preserveSpecialCase(payload), // Preserve special chars, vary letters
	)

	return evasions.UniqueStrings(variants)
}

// alternatingCase creates alternating upper/lower case
func alternatingCase(s string) string {
	var result strings.Builder
	upper := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if upper {
				result.WriteRune(unicode.ToUpper(r))
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
			upper = !upper
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// randomCase randomly changes case of characters
func randomCase(s string, ratio float64) string {
	var result strings.Builder
	runes := []rune(s)
	changeCount := int(float64(len(runes)) * ratio)
	changed := 0

	for i, r := range runes {
		if unicode.IsLetter(r) && changed < changeCount && i%2 == 0 {
			if unicode.IsLower(r) {
				result.WriteRune(unicode.ToUpper(r))
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
			changed++
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// firstLetterUpper makes the first letter uppercase
func firstLetterUpper(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsLetter(r) {
			runes[i] = unicode.ToUpper(r)
			break
		}
	}
	return string(runes)
}

// lastLetterUpper makes the last letter uppercase
func lastLetterUpper(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	for i := len(runes) - 1; i >= 0; i-- {
		if unicode.IsLetter(runes[i]) {
			runes[i] = unicode.ToUpper(runes[i])
			break
		}
	}
	return string(runes)
}

// wordBoundaryUpper makes the first letter of each word uppercase
func wordBoundaryUpper(s string) string {
	var result strings.Builder
	wordStart := true
	for _, r := range s {
		if unicode.IsLetter(r) {
			if wordStart {
				result.WriteRune(unicode.ToUpper(r))
				wordStart = false
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
		} else {
			result.WriteRune(r)
			if unicode.IsSpace(r) {
				wordStart = true
			}
		}
	}
	return result.String()
}

// vowelUppercase makes only vowels uppercase
func vowelUppercase(s string) string {
	var result strings.Builder
	vowels := "aeiouAEIOU"
	for _, r := range s {
		if strings.ContainsRune(vowels, unicode.ToLower(r)) {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(unicode.ToLower(r))
		}
	}
	return result.String()
}

// consonantUppercase makes only consonants uppercase
func consonantUppercase(s string) string {
	var result strings.Builder
	vowels := "aeiouAEIOU"
	for _, r := range s {
		if unicode.IsLetter(r) && !strings.ContainsRune(vowels, unicode.ToLower(r)) {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(unicode.ToLower(r))
		}
	}
	return result.String()
}

// reverseCase inverts the normal case
func reverseCase(s string) string {
	var result strings.Builder
	for _, r := range s {
		if unicode.IsUpper(r) {
			result.WriteRune(unicode.ToLower(r))
		} else if unicode.IsLower(r) {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// camelCase converts to camelCase style
func camelCase(s string) string {
	var result strings.Builder
	wordStart := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if wordStart {
				result.WriteRune(unicode.ToUpper(r))
				wordStart = false
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
		} else if unicode.IsSpace(r) {
			wordStart = true
			// Skip spaces in camelCase
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// snakeToUpperCase converts to UPPER_CASE style
func snakeToUpperCase(s string) string {
	var result strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) {
			result.WriteRune('_')
		} else {
			result.WriteRune(unicode.ToUpper(r))
		}
	}
	return result.String()
}

// unicodeCaseVariants creates Unicode case transformations
func unicodeCaseVariants(s string) string {
	var result strings.Builder
	for i, r := range s {
		if unicode.IsLetter(r) {
			switch i % 3 {
			case 0:
				result.WriteRune(unicode.ToUpper(r))
			case 1:
				result.WriteRune(unicode.ToLower(r))
			case 2:
				result.WriteRune(unicode.ToTitle(r))
			}
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// leetSpeakCase combines leet speak with case variations
func leetSpeakCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		switch unicode.ToLower(r) {
		case 'a':
			if i%2 == 0 {
				result.WriteRune('@')
			} else {
				result.WriteRune('A')
			}
		case 'e':
			if i%2 == 0 {
				result.WriteRune('3')
			} else {
				result.WriteRune('E')
			}
		case 'i':
			if i%2 == 0 {
				result.WriteRune('1')
			} else {
				result.WriteRune('I')
			}
		case 'o':
			if i%2 == 0 {
				result.WriteRune('0')
			} else {
				result.WriteRune('O')
			}
		case 's':
			if i%2 == 0 {
				result.WriteRune('$')
			} else {
				result.WriteRune('S')
			}
		default:
			if unicode.IsLetter(r) {
				if i%2 == 0 {
					result.WriteRune(unicode.ToLower(r))
				} else {
					result.WriteRune(unicode.ToUpper(r))
				}
			} else {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}

// zebraCase creates zebra striping pattern
func zebraCase(s string) string {
	var result strings.Builder
	letterCount := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			if letterCount%2 == 0 {
				result.WriteRune(unicode.ToLower(r))
			} else {
				result.WriteRune(unicode.ToUpper(r))
			}
			letterCount++
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// inverseZebraCase creates inverse zebra striping pattern
func inverseZebraCase(s string) string {
	var result strings.Builder
	letterCount := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			if letterCount%2 == 0 {
				result.WriteRune(unicode.ToUpper(r))
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
			letterCount++
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// randomWordCase applies random case to each word
func randomWordCase(s string) string {
	words := strings.Fields(s)
	var result []string
	for i, word := range words {
		switch i % 4 {
		case 0:
			result = append(result, strings.ToUpper(word))
		case 1:
			result = append(result, strings.ToLower(word))
		case 2:
			result = append(result, wordBoundaryUpper(word))
		case 3:
			result = append(result, alternatingCase(word))
		}
	}
	return strings.Join(result, " ")
}

// preserveSpecialCase preserves special characters, varies letter case
func preserveSpecialCase(s string) string {
	var result strings.Builder
	letterIndex := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			if letterIndex%3 == 0 {
				result.WriteRune(unicode.ToUpper(r))
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
			letterIndex++
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}
