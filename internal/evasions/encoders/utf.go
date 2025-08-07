package encoders

import (
	"fmt"
	"obfuskit/internal/evasions"
	"obfuskit/types"
	"strings"
	"unicode/utf8"
)

// UTF8Variants generates various UTF-8 encoded variants of the input payload
// based on the specified obfuscation level
func UTF8Variants(payload string, level types.EvasionLevel) []string {
	var variants []string

	// Basic UTF-8 encoding variants
	variants = append(variants,
		utf8HexEncoding(payload),     // UTF-8 hex encoding
		utf8OctalEncoding(payload),   // UTF-8 octal encoding
		utf8DecimalEncoding(payload), // UTF-8 decimal encoding
		utf8BinaryEncoding(payload),  // UTF-8 binary encoding
		utf8PercentEncoding(payload), // UTF-8 percent encoding
	)

	// Return basic variants if level is Basic
	if level == types.EvasionLevelBasic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds normalization and overlong encodings
	variants = append(variants,
		utf8OverlongEncoding(payload), // Overlong UTF-8 sequences
		utf8NormalizationC(payload),   // NFC normalization variants
		utf8NormalizationD(payload),   // NFD normalization variants
		utf8MixedEncoding(payload),    // Mixed encoding styles
		utf8NullByteEncoding(payload), // Null byte injection
		utf8BOMVariants(payload),      // BOM variants
	)

	// Return medium variants if level is Medium
	if level == types.EvasionLevelMedium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds malformed sequences and edge cases
	variants = append(variants,
		utf8MalformedSequences(payload),  // Malformed UTF-8 sequences
		utf8SurrogateEncoding(payload),   // Surrogate pair encoding
		utf8ReplacementChar(payload),     // Replacement character variants
		utf8ControlCharEncoding(payload), // Control character encoding
		utf8ZeroWidthEncoding(payload),   // Zero-width character injection
		utf8DirectionalMarks(payload),    // Bidirectional text marks
		utf8CompatibilityChars(payload),  // Compatibility characters
	)

	return evasions.UniqueStrings(variants)
}

// utf8HexEncoding encodes UTF-8 bytes as hex
func utf8HexEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		utf8Bytes := []byte(string(r))
		for _, b := range utf8Bytes {
			result.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return result.String()
}

// utf8OctalEncoding encodes UTF-8 bytes as octal
func utf8OctalEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		utf8Bytes := []byte(string(r))
		for _, b := range utf8Bytes {
			result.WriteString(fmt.Sprintf("\\%03o", b))
		}
	}
	return result.String()
}

// utf8DecimalEncoding encodes UTF-8 bytes as decimal
func utf8DecimalEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		utf8Bytes := []byte(string(r))
		for _, b := range utf8Bytes {
			result.WriteString(fmt.Sprintf("&#%d;", b))
		}
	}
	return result.String()
}

// utf8BinaryEncoding encodes UTF-8 bytes as binary
func utf8BinaryEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		utf8Bytes := []byte(string(r))
		for _, b := range utf8Bytes {
			result.WriteString(fmt.Sprintf("\\b%08b", b))
		}
	}
	return result.String()
}

// utf8PercentEncoding encodes UTF-8 bytes with percent encoding
func utf8PercentEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		utf8Bytes := []byte(string(r))
		for _, b := range utf8Bytes {
			result.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return result.String()
}

// utf8OverlongEncoding creates overlong UTF-8 sequences
func utf8OverlongEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 {
			// Create overlong encoding for ASCII characters
			// 2-byte overlong: 110xxxxx 10xxxxxx
			b1 := 0xC0 | (byte(r) >> 6)
			b2 := 0x80 | (byte(r) & 0x3F)
			result.WriteString(fmt.Sprintf("\\x%02x\\x%02x", b1, b2))
		} else {
			// Normal encoding for non-ASCII
			result.WriteRune(r)
		}
	}
	return result.String()
}

// utf8NormalizationC applies NFC normalization variants
func utf8NormalizationC(s string) string {
	var result strings.Builder
	for _, r := range s {
		switch r {
		case 'é':
			result.WriteString("e\u0301") // e + combining acute accent
		case 'ñ':
			result.WriteString("n\u0303") // n + combining tilde
		case 'ü':
			result.WriteString("u\u0308") // u + combining diaeresis
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// utf8NormalizationD applies NFD normalization variants
func utf8NormalizationD(s string) string {
	var result strings.Builder
	for _, r := range s {
		switch r {
		case 'a':
			result.WriteString("a\u0300") // a + combining grave accent
		case 'e':
			result.WriteString("e\u0301") // e + combining acute accent
		case 'i':
			result.WriteString("i\u0302") // i + combining circumflex
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// utf8MixedEncoding mixes different UTF-8 encoding styles
func utf8MixedEncoding(s string) string {
	var result strings.Builder
	for i, r := range s {
		utf8Bytes := []byte(string(r))
		switch i % 4 {
		case 0:
			for _, b := range utf8Bytes {
				result.WriteString(fmt.Sprintf("\\x%02x", b))
			}
		case 1:
			for _, b := range utf8Bytes {
				result.WriteString(fmt.Sprintf("\\%03o", b))
			}
		case 2:
			for _, b := range utf8Bytes {
				result.WriteString(fmt.Sprintf("&#%d;", b))
			}
		case 3:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// utf8NullByteEncoding injects null bytes
func utf8NullByteEncoding(s string) string {
	var result strings.Builder
	for i, r := range s {
		result.WriteRune(r)
		if i%3 == 0 {
			result.WriteString("\\x00") // Inject null byte
		}
	}
	return result.String()
}

// utf8BOMVariants adds Byte Order Mark variants
func utf8BOMVariants(s string) string {
	// UTF-8 BOM: EF BB BF
	return "\\xEF\\xBB\\xBF" + s
}

// utf8MalformedSequences creates malformed UTF-8 sequences
func utf8MalformedSequences(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i%5 == 0 && r < 128 {
			// Create malformed sequence: start byte without continuation
			result.WriteString(fmt.Sprintf("\\x%02x", 0xC0|byte(r)))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// utf8SurrogateEncoding uses surrogate pair encoding
func utf8SurrogateEncoding(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r > 0xFFFF {
			// Convert to surrogate pairs
			r -= 0x10000
			high := 0xD800 + (r >> 10)
			low := 0xDC00 + (r & 0x3FF)
			result.WriteString(fmt.Sprintf("\\u%04X\\u%04X", high, low))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// utf8ReplacementChar injects replacement characters
func utf8ReplacementChar(s string) string {
	var result strings.Builder
	for i, r := range s {
		result.WriteRune(r)
		if i%4 == 0 {
			result.WriteRune('\uFFFD') // Unicode replacement character
		}
	}
	return result.String()
}

// utf8ControlCharEncoding injects control characters
func utf8ControlCharEncoding(s string) string {
	var result strings.Builder
	controlChars := []rune{'\u0000', '\u0001', '\u0002', '\u0003', '\u0004', '\u0005'}
	for i, r := range s {
		result.WriteRune(r)
		if i%6 == 0 && i < len(controlChars) {
			result.WriteRune(controlChars[i%len(controlChars)])
		}
	}
	return result.String()
}

// utf8ZeroWidthEncoding injects zero-width characters
func utf8ZeroWidthEncoding(s string) string {
	var result strings.Builder
	zeroWidthChars := []rune{'\u200B', '\u200C', '\u200D', '\uFEFF'}
	for i, r := range s {
		result.WriteRune(r)
		if i%4 == 0 {
			result.WriteRune(zeroWidthChars[i%len(zeroWidthChars)])
		}
	}
	return result.String()
}

// utf8DirectionalMarks injects bidirectional text marks
func utf8DirectionalMarks(s string) string {
	var result strings.Builder
	dirMarks := []rune{'\u202A', '\u202B', '\u202C', '\u202D', '\u202E'}
	for i, r := range s {
		result.WriteRune(r)
		if i%5 == 0 {
			result.WriteRune(dirMarks[i%len(dirMarks)])
		}
	}
	return result.String()
}

// utf8CompatibilityChars uses Unicode compatibility characters
func utf8CompatibilityChars(s string) string {
	var result strings.Builder
	for _, r := range s {
		switch r {
		case 'A':
			result.WriteRune('\uFF21') // Fullwidth Latin Capital Letter A
		case 'a':
			result.WriteRune('\uFF41') // Fullwidth Latin Small Letter A
		case '0':
			result.WriteRune('\uFF10') // Fullwidth Digit Zero
		case '<':
			result.WriteRune('\uFF1C') // Fullwidth Less-Than Sign
		case '>':
			result.WriteRune('\uFF1E') // Fullwidth Greater-Than Sign
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// isValidUTF8 checks if a byte sequence is valid UTF-8
func isValidUTF8(data []byte) bool {
	return utf8.Valid(data)
}
