package encoders

import (
	"fmt"
	"math/rand"
	"obfuskit/internal/constants"
	"obfuskit/internal/evasions"
	"strings"
	"unicode"
)

// UnicodeVariants generates various unicode encoded variants of the input payload
// based on the specified obfuscation level
func UnicodeVariants(payload string, level constants.Level) []string {
	var variants []string

	// Define string builders for different unicode encoding styles
	var (
		// Full encodings (every character)
		jsEscape      strings.Builder // \uXXXX
		jsCurlyEscape strings.Builder // \u{XXXX}
		htmlHexEntity strings.Builder // &#xXXXX;
		htmlDecEntity strings.Builder // &#DDDD;
		legacyEscape  strings.Builder // %uXXXX
		unicodeCodePt strings.Builder // U+XXXX

		// Partial encodings (only special characters)
		jsEscapePartly      strings.Builder // \uXXXX
		jsCurlyEscapePartly strings.Builder // \u{XXXX}
		htmlHexEntityPartly strings.Builder // &#xXXXX;
		htmlDecEntityPartly strings.Builder // &#DDDD;
		legacyEscapePartly  strings.Builder // %uXXXX
		unicodeCodePtPartly strings.Builder // U+XXXX
	)

	// Generate full encodings (encode every character)
	for _, r := range payload {
		code := fmt.Sprintf("%04X", r)

		jsEscape.WriteString(`\u` + code)
		jsCurlyEscape.WriteString(fmt.Sprintf(`\u{%X}`, r))
		htmlHexEntity.WriteString(`&#x` + code + `;`)
		htmlDecEntity.WriteString(fmt.Sprintf("&#%d;", r))
		legacyEscape.WriteString(`%u` + code)
		unicodeCodePt.WriteString(`U+` + code + ` `)
	}

	// Add basic variants
	variants = append(variants,
		jsEscape.String(),
		jsCurlyEscape.String(),
		htmlHexEntity.String(),
		htmlDecEntity.String(),
		legacyEscape.String(),
		strings.TrimSpace(unicodeCodePt.String()),
	)

	// Return basic variants if level is Basic
	if level == constants.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Generate partial encodings (only encode special characters)
	for _, r := range payload {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			// Don't encode alphanumeric characters
			jsEscapePartly.WriteRune(r)
			jsCurlyEscapePartly.WriteRune(r)
			htmlHexEntityPartly.WriteRune(r)
			htmlDecEntityPartly.WriteRune(r)
			legacyEscapePartly.WriteRune(r)
			unicodeCodePtPartly.WriteRune(r)
			continue
		}

		// Encode special characters
		code := fmt.Sprintf("%04X", r)
		jsEscapePartly.WriteString(`\u` + code)
		jsCurlyEscapePartly.WriteString(fmt.Sprintf(`\u{%X}`, r))
		htmlHexEntityPartly.WriteString(`&#x` + code + `;`)
		htmlDecEntityPartly.WriteString(fmt.Sprintf("&#%d;", r))
		legacyEscapePartly.WriteString(`%u` + code)
		unicodeCodePtPartly.WriteString(`U+` + code + ` `)
	}

	// Add medium variants (partial encodings)
	variants = append(variants,
		jsEscapePartly.String(),
		jsCurlyEscapePartly.String(),
		htmlHexEntityPartly.String(),
		htmlDecEntityPartly.String(),
		legacyEscapePartly.String(),
		strings.TrimSpace(unicodeCodePtPartly.String()),
	)

	// Return medium variants if level is Medium
	if level == constants.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Add advanced bypasses for Unicode

	// 1. Zero-width space insertions
	variants = append(variants, insertZeroWidthSpaces(payload))

	// 2. Mixed encoding strategies
	variants = append(variants,
		mixedEncodingStrategy(payload),
		mixedEncodingStrategyAdvanced(payload),
	)

	// 3. Bidirectional override characters
	variants = append(variants,
		addBidirectionalOverrides(payload),
	)

	// 4. Homoglyphs substitution
	variants = append(variants,
		substituteHomoglyphs(payload),
	)

	// 5. Combining characters
	variants = append(variants,
		addCombiningMarks(payload),
	)

	// 6. Invisible control characters
	variants = append(variants,
		addInvisibleControls(payload),
	)

	// 7. Unicode normalization exploits
	variants = append(variants,
		normalizedVariants(payload),
	)

	// 8. Case folding
	variants = append(variants,
		caseFolding(payload),
	)

	// 9. Right-to-left override
	variants = append(variants,
		rtlOverride(payload),
	)

	return evasions.UniqueStrings(variants)
}

// insertZeroWidthSpaces inserts zero-width spaces between characters
func insertZeroWidthSpaces(s string) string {
	// Zero-width space (U+200B)
	zwsp := "\u200B"

	var result strings.Builder
	for i, r := range s {
		result.WriteRune(r)
		// Don't add after the last character
		if i < len([]rune(s))-1 {
			result.WriteString(zwsp)
		}
	}
	return result.String()
}

// mixedEncodingStrategy creates a string with mixed encoding strategies
func mixedEncodingStrategy(s string) string {
	var result strings.Builder
	encodingTypes := []int{0, 1, 2, 3} // Different encoding types

	for _, r := range s {
		encodingType := encodingTypes[rand.Intn(len(encodingTypes))]
		switch encodingType {
		case 0:
			result.WriteRune(r) // Raw character
		case 1:
			result.WriteString(fmt.Sprintf(`\u%04X`, r)) // JS Unicode
		case 2:
			result.WriteString(fmt.Sprintf(`&#x%X;`, r)) // HTML hex entity
		case 3:
			result.WriteString(fmt.Sprintf(`&#%d;`, r)) // HTML decimal entity
		}
	}
	return result.String()
}

// mixedEncodingStrategyAdvanced creates a string with mixed encoding including advanced bypasses
func mixedEncodingStrategyAdvanced(s string) string {
	var result strings.Builder
	encodingTypes := []int{0, 1, 2, 3, 4, 5} // Different encoding types

	for _, r := range s {
		encodingType := encodingTypes[rand.Intn(len(encodingTypes))]
		switch encodingType {
		case 0:
			result.WriteRune(r) // Raw character
		case 1:
			result.WriteString(fmt.Sprintf(`\u%04X`, r)) // JS Unicode
		case 2:
			result.WriteString(fmt.Sprintf(`&#x%X;`, r)) // HTML hex entity
		case 3:
			result.WriteString(fmt.Sprintf(`&#%d;`, r)) // HTML decimal entity
		case 4:
			// Double encoding - HTML entity inside a JS Unicode escape
			result.WriteString(fmt.Sprintf(`\u%04X`, []rune("&#" + fmt.Sprintf("%d", r) + ";")[0]))
		case 5:
			// CSS Unicode escape
			result.WriteString(fmt.Sprintf(`\\%X `, r))
		}
	}
	return result.String()
}

// addBidirectionalOverrides adds bidirectional text control characters
func addBidirectionalOverrides(s string) string {
	// Left-to-right override (U+202D)
	lro := "\u202D"
	// Right-to-left override (U+202E)
	rlo := "\u202E"
	// Pop directional formatting (U+202C)
	pdf := "\u202C"

	return lro + s + pdf + rlo + s + pdf
}

// substituteHomoglyphs replaces characters with similar-looking Unicode characters
func substituteHomoglyphs(s string) string {
	homoglyphs := map[rune]rune{
		'a': 'а', // Cyrillic 'а' instead of Latin 'a'
		'e': 'е', // Cyrillic 'е' instead of Latin 'e'
		'o': 'о', // Cyrillic 'о' instead of Latin 'o'
		'p': 'р', // Cyrillic 'р' instead of Latin 'p'
		'c': 'с', // Cyrillic 'с' instead of Latin 'c'
		'x': 'х', // Cyrillic 'х' instead of Latin 'x'
		'i': 'і', // Ukrainian 'і' instead of Latin 'i'
		'j': 'ј', // Cyrillic 'ј' instead of Latin 'j'
		'n': 'ո', // Armenian 'ո' instead of Latin 'n'
		'y': 'у', // Cyrillic 'у' instead of Latin 'y'
	}

	var result strings.Builder
	for _, r := range s {
		if replacement, ok := homoglyphs[r]; ok && rand.Intn(2) == 0 {
			result.WriteRune(replacement)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// addCombiningMarks adds combining diacritical marks to characters
func addCombiningMarks(s string) string {
	combiningMarks := []rune{
		'\u0300', // Combining grave accent
		'\u0301', // Combining acute accent
		'\u0302', // Combining circumflex accent
		'\u0303', // Combining tilde
		'\u0304', // Combining macron
		'\u0305', // Combining overline
		'\u0306', // Combining breve
		'\u0307', // Combining dot above
		'\u0308', // Combining diaeresis
		'\u0309', // Combining hook above
	}

	var result strings.Builder
	for _, r := range s {
		result.WriteRune(r)
		// Randomly add 1-3 combining marks
		numMarks := rand.Intn(3) + 1
		for i := 0; i < numMarks; i++ {
			mark := combiningMarks[rand.Intn(len(combiningMarks))]
			result.WriteRune(mark)
		}
	}
	return result.String()
}

// addInvisibleControls adds invisible control characters between visible characters
func addInvisibleControls(s string) string {
	controls := []string{
		"\u200B", // Zero-width space
		"\u200C", // Zero-width non-joiner
		"\u200D", // Zero-width joiner
		"\u2060", // Word joiner
		"\u200E", // Left-to-right mark
		"\u200F", // Right-to-left mark
		"\uFEFF", // Zero-width no-break space (BOM)
	}

	var result strings.Builder
	for i, r := range s {
		result.WriteRune(r)
		// Don't add after the last character
		if i < len([]rune(s))-1 {
			// Add 1-3 control characters
			numControls := rand.Intn(3) + 1
			for j := 0; j < numControls; j++ {
				control := controls[rand.Intn(len(controls))]
				result.WriteString(control)
			}
		}
	}
	return result.String()
}

func normalizedVariants(s string) string {
	var result strings.Builder
	for _, r := range s {
		// TODO: Add more here !!
		normalizedMap := map[string]string{
			"a\u0301": "á", // a + combining acute → precomposed á
			"e\u0301": "é", // e + combining acute → precomposed é
			"i\u0301": "í", // i + combining acute → precomposed í
			"o\u0301": "ó", // o + combining acute → precomposed ó
			"u\u0301": "ú", // u + combining acute → precomposed ú
			"n\u0303": "ñ", // n + combining tilde → precomposed ñ
		}
		switch r {
		case 'a', 'e', 'i', 'o', 'u', 'n':
			// Decompose selected characters with a 50% chance
			if rand.Intn(2) == 0 {
				switch r {
				case 'a':
					result.WriteString(normalizedMap["a\\u0301"])
				case 'e':
					result.WriteString(normalizedMap["e\\u0301"])
				case 'i':
					result.WriteString(normalizedMap["i\\u0301"])
				case 'o':
					result.WriteString(normalizedMap["o\\u0301"])
				case 'u':
					result.WriteString(normalizedMap["u\\u0301"])
				case 'n':
					result.WriteString(normalizedMap["n\\u0303"])
				}
			} else {
				result.WriteRune(r)
			}
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// caseFolding replaces characters with their case folding equivalents
func caseFolding(s string) string {
	specialCaseFolding := map[rune]string{
		'ß': "ss",  // German sharp s → ss
		'ı': "i",   // Dotless i → i
		'İ': "i",   // Dotted I → i
		'ſ': "s",   // Long s → s
		'ﬀ': "ff",  // Latin small ligature ff → ff
		'ﬁ': "fi",  // Latin small ligature fi → fi
		'ﬂ': "fl",  // Latin small ligature fl → fl
		'ﬃ': "ffi", // Latin small ligature ffi → ffi
		'ﬄ': "ffl", // Latin small ligature ffl → ffl
	}

	var result strings.Builder
	for _, r := range s {
		if replacement, ok := specialCaseFolding[r]; ok {
			result.WriteString(replacement)
		} else if unicode.IsUpper(r) {
			result.WriteRune(unicode.ToLower(r))
		} else if unicode.IsLower(r) {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// rtlOverride adds right-to-left override characters to reverse text
func rtlOverride(s string) string {
	// Right-to-left override (U+202E)
	rlo := "\u202E"
	// Pop directional formatting (U+202C)
	pdf := "\u202C"

	// Reverse the string and add RTL control characters
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	reversed := string(runes)

	return rlo + reversed + pdf
}
