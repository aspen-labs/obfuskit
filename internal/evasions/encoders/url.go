package encoders

import (
	"fmt"
	"net/url"
	"obfuskit/internal/evasions"
	"obfuskit/types"
	"strings"
)

// URLVariants generates various URL encoded variants of the input payload
// based on the specified obfuscation level
func URLVariants(payload string, level types.EvasionLevel) []string {
	var variants []string

	// Basic URL encoding
	urlEncoded := url.QueryEscape(payload)
	pathEncoded := url.PathEscape(payload)

	// Manual URL encoding with different cases
	manualLower := manualURLEncode(payload, false)
	manualUpper := manualURLEncode(payload, true)

	// Basic variants
	variants = append(variants,
		urlEncoded,  // Standard URL encoding
		pathEncoded, // Path encoding
		manualLower, // Manual lowercase %xx
		manualUpper, // Manual uppercase %XX
	)

	// For safe strings, add forced encodings
	if urlEncoded == payload {
		// Force encode all characters
		variants = append(variants, forceURLEncode(payload, false))
		variants = append(variants, forceURLEncode(payload, true))
	}

	// Return basic variants if level is Basic
	if level == types.EvasionLevelBasic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds partial encoding and mixed case
	variants = append(variants,
		partialURLEncode(payload, 0.5), // Encode ~50% of characters
		partialURLEncode(payload, 0.3), // Encode ~30% of characters
		mixedCaseURLEncode(payload),    // Mixed case encoding
		unicodeURLEncode(payload),      // Unicode URL encoding
		plusSpaceEncode(payload),       // Encode spaces as + instead of %20
	)

	// Return medium variants if level is Medium
	if level == types.EvasionLevelMedium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds double encoding and malformed encodings
	variants = append(variants,
		url.QueryEscape(urlEncoded),         // Double URL encoding
		url.QueryEscape(manualUpper),        // Double encode manual version
		malformedURLEncode(payload),         // Malformed encoding attempts
		overloadedURLEncode(payload),        // Overloaded encoding
		nullByteURLEncode(payload),          // Null byte injection attempts
		tabNewlineURLEncode(payload),        // Tab and newline variations
		backslashURLEncode(payload),         // Backslash encoding variations
		unicodeNormalizationEncode(payload), // Unicode normalization attacks
	)

	return evasions.UniqueStrings(variants)
}

// manualURLEncode manually URL encodes characters with specified case
func manualURLEncode(s string, uppercase bool) string {
	var result strings.Builder
	for _, b := range []byte(s) {
		if shouldEncode(b) {
			if uppercase {
				result.WriteString(fmt.Sprintf("%%%02X", b))
			} else {
				result.WriteString(fmt.Sprintf("%%%02x", b))
			}
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// shouldEncode determines if a character should be URL encoded
func shouldEncode(b byte) bool {
	return !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~')
}

// forceURLEncode forces URL encoding of all characters, even safe ones
func forceURLEncode(s string, uppercase bool) string {
	var result strings.Builder
	for _, b := range []byte(s) {
		if uppercase {
			result.WriteString(fmt.Sprintf("%%%02X", b))
		} else {
			result.WriteString(fmt.Sprintf("%%%02x", b))
		}
	}
	return result.String()
}

// partialURLEncode encodes only a percentage of characters
func partialURLEncode(s string, ratio float64) string {
	var result strings.Builder
	bytes := []byte(s)
	encodeCount := int(float64(len(bytes)) * ratio)
	encoded := 0

	for i, b := range bytes {
		if shouldEncode(b) && encoded < encodeCount && i%2 == 0 {
			result.WriteString(fmt.Sprintf("%%%02x", b))
			encoded++
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// mixedCaseURLEncode creates mixed case URL encoding
func mixedCaseURLEncode(s string) string {
	var result strings.Builder
	for i, b := range []byte(s) {
		if shouldEncode(b) {
			if i%2 == 0 {
				result.WriteString(fmt.Sprintf("%%%02x", b))
			} else {
				result.WriteString(fmt.Sprintf("%%%02X", b))
			}
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// unicodeURLEncode encodes using Unicode percent encoding
func unicodeURLEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r > 127 {
			// Encode non-ASCII as UTF-8 percent encoding
			utf8Bytes := []byte(string(r))
			for _, b := range utf8Bytes {
				result.WriteString(fmt.Sprintf("%%%02X", b))
			}
		} else if shouldEncode(byte(r)) {
			result.WriteString(fmt.Sprintf("%%%02X", byte(r)))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// plusSpaceEncode encodes spaces as + instead of %20
func plusSpaceEncode(s string) string {
	encoded := manualURLEncode(s, false)
	return strings.ReplaceAll(encoded, "%20", "+")
}

// malformedURLEncode creates malformed URL encodings
func malformedURLEncode(s string) string {
	var result strings.Builder
	for _, b := range []byte(s) {
		if shouldEncode(b) {
			switch b % 4 {
			case 0:
				result.WriteString(fmt.Sprintf("%%%02x", b)) // Normal
			case 1:
				result.WriteString(fmt.Sprintf("%%0%x", b)) // Missing leading zero
			case 2:
				result.WriteString(fmt.Sprintf("%%%x", b)) // Single digit
			case 3:
				result.WriteString(fmt.Sprintf("%%%02X", b)) // Uppercase
			}
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// overloadedURLEncode creates overloaded URL encodings
func overloadedURLEncode(s string) string {
	var result strings.Builder
	for _, b := range []byte(s) {
		if shouldEncode(b) {
			result.WriteString(fmt.Sprintf("%%%02x", b))
		} else {
			// Encode even safe characters sometimes
			if b%3 == 0 {
				result.WriteString(fmt.Sprintf("%%%02x", b))
			} else {
				result.WriteByte(b)
			}
		}
	}
	return result.String()
}

// nullByteURLEncode injects null bytes in URL encoding
func nullByteURLEncode(s string) string {
	encoded := manualURLEncode(s, false)
	// Insert %00 at strategic positions
	if len(encoded) > 4 {
		mid := len(encoded) / 2
		return encoded[:mid] + "%00" + encoded[mid:]
	}
	return encoded + "%00"
}

// tabNewlineURLEncode uses tab and newline in encoding
func tabNewlineURLEncode(s string) string {
	var result strings.Builder
	for i, b := range []byte(s) {
		if shouldEncode(b) {
			if i%5 == 0 {
				result.WriteString(fmt.Sprintf("%%09%%%02x", b)) // Tab prefix
			} else if i%7 == 0 {
				result.WriteString(fmt.Sprintf("%%0A%%%02x", b)) // Newline prefix
			} else {
				result.WriteString(fmt.Sprintf("%%%02x", b))
			}
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// backslashURLEncode uses backslash variations
func backslashURLEncode(s string) string {
	var result strings.Builder
	for _, b := range []byte(s) {
		if shouldEncode(b) {
			result.WriteString(fmt.Sprintf("\\x%02x", b))
		} else {
			result.WriteByte(b)
		}
	}
	return result.String()
}

// unicodeNormalizationEncode uses Unicode normalization attacks
func unicodeNormalizationEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			result.WriteString("%u003c") // Unicode encoding
		case '>':
			result.WriteString("%u003e")
		case '"':
			result.WriteString("%u0022")
		case '\'':
			result.WriteString("%u0027")
		case '&':
			result.WriteString("%u0026")
		default:
			if shouldEncode(byte(r)) {
				result.WriteString(fmt.Sprintf("%%%02x", byte(r)))
			} else {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}
