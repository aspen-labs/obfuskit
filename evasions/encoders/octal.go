package encoders

import (
	"fmt"
	"math/rand"
	"obfuskit/cmd"
	"obfuskit/evasions"
	"regexp"
	"strings"
)

// OctalVariants generates various octal encoded variants of the input payload
// based on the specified obfuscation level
func OctalVariants(payload string, level cmd.Level) []string {
	var variants []string

	// Basic octal encodings
	standardOctal := toOctal(payload, false)
	leadingZeroOctal := toOctal(payload, true)
	cStyleOctal := addBackslashPrefix(standardOctal)
	cStyleLeadingZeroOctal := addBackslashPrefix(leadingZeroOctal)

	// Add basic variants
	variants = append(variants,
		standardOctal,              // Standard octal (177 145 154 154 157)
		leadingZeroOctal,           // Leading zero octal (0177 0145 0154 0154 0157)
		cStyleOctal,                // C-style octal (\177\145\154\154\157)
		cStyleLeadingZeroOctal,     // C-style with leading zeros (\0177\0145\0154\0154\0157)
		mixSpacedOctal(payload),    // Mixed spaces (177 145  154   154 157)
		tabSeparatedOctal(payload), // Tab separated octal (177	145	154	154	157)
	)

	// Return basic variants if level is Basic
	if level == cmd.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more evasion techniques
	variants = append(variants,
		octBinaryMix(payload),         // Mix of octal and binary
		octHexMix(payload),            // Mix of octal and hex
		octDecimalMix(payload),        // Mix of octal and decimal
		partialOctalEncoding(payload), // Only encode special chars
		jsOctalStringLiteral(payload), // JavaScript octal string literal
		bashOctalEncoding(payload),    // Bash-style octal encoding
		overPaddedOctal(payload),      // Over-padded octal (00177 00145...)
		splitDigitGroups(cStyleOctal), // Split digit groups (\1\7\7\1\4\5...)
	)

	// Return medium variants if level is Medium
	if level == cmd.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds complex evasion techniques
	variants = append(variants,
		multilineSplitOctal(payload),           // Split across multiple lines
		commentedOctal(payload),                // With comments
		nestingOctalEncoding(payload),          // Nested encoding
		mixedRadixEncoding(payload),            // Mixed radix encoding
		octalWithControlChars(payload),         // With control characters
		encodedPathTraversal(payload),          // Path traversal with octal
		doubleEncodedOctal(payload),            // Double-encoded octal
		shuffleDigitOrder(payload),             // Shuffle digit order with markers
		octalWithUnicode(payload),              // Mix octal with unicode escapes
		obfuscatedOctalAssignment(payload),     // Obfuscated assignment pattern
		escapedOctalVariant(payload),           // Escaped octal with special syntax
		octalWithWhitespaceVariations(payload), // Various whitespace formats
	)

	return evasions.UniqueStrings(variants)
}

// toOctal converts a string to octal representation, optionally with leading zeros
func toOctal(s string, leadingZero bool) string {
	var b strings.Builder
	for i, c := range []byte(s) {
		if i > 0 {
			b.WriteString(" ")
		}

		if leadingZero {
			b.WriteString(fmt.Sprintf("0%o", c))
		} else {
			b.WriteString(fmt.Sprintf("%o", c))
		}
	}
	return b.String()
}

// addBackslashPrefix adds backslash prefix to each octal value
func addBackslashPrefix(octal string) string {
	parts := strings.Split(octal, " ")
	for i, part := range parts {
		parts[i] = "\\" + part
	}
	return strings.Join(parts, "")
}

// mixSpacedOctal creates mixed spacing between octal values
func mixSpacedOctal(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			// Add random number of spaces (1-4)
			spaces := rand.Intn(4) + 1
			b.WriteString(strings.Repeat(" ", spaces))
		}
		b.WriteString(fmt.Sprintf("%o", c))
	}
	return b.String()
}

// tabSeparatedOctal creates tab-separated octal values
func tabSeparatedOctal(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			b.WriteString("\t")
		}
		b.WriteString(fmt.Sprintf("%o", c))
	}
	return b.String()
}

// octBinaryMix mixes octal and binary encodings
func octBinaryMix(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			b.WriteString(" ")
		}

		// Alternate between octal and binary
		if i%2 == 0 {
			b.WriteString(fmt.Sprintf("%o", c))
		} else {
			b.WriteString(fmt.Sprintf("0b%08b", c))
		}
	}
	return b.String()
}

// octHexMix mixes octal and hexadecimal encodings
func octHexMix(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			b.WriteString(" ")
		}

		// Alternate between octal and hex
		if i%2 == 0 {
			b.WriteString(fmt.Sprintf("0%o", c))
		} else {
			b.WriteString(fmt.Sprintf("0x%02x", c))
		}
	}
	return b.String()
}

// octDecimalMix mixes octal and decimal encodings
func octDecimalMix(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			b.WriteString(" ")
		}

		// Alternate between octal and decimal
		if i%2 == 0 {
			b.WriteString(fmt.Sprintf("%o", c))
		} else {
			b.WriteString(fmt.Sprintf("%d", c))
		}
	}
	return b.String()
}

// partialOctalEncoding only encodes special characters, leaving alphanumeric as-is
func partialOctalEncoding(payload string) string {
	var b strings.Builder
	for _, c := range []byte(payload) {
		// Encode only special characters
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("\\%o", c))
		}
	}
	return b.String()
}

// jsOctalStringLiteral creates JavaScript-style octal string literals
func jsOctalStringLiteral(payload string) string {
	var parts []string
	for _, c := range []byte(payload) {
		parts = append(parts, fmt.Sprintf("'\\%o'", c))
	}
	return strings.Join(parts, "+")
}

// bashOctalEncoding creates bash-style octal encoding with $'...' syntax
func bashOctalEncoding(payload string) string {
	var b strings.Builder
	b.WriteString("$'")
	for _, c := range []byte(payload) {
		b.WriteString(fmt.Sprintf("\\%o", c))
	}
	b.WriteString("'")
	return b.String()
}

// overPaddedOctal adds excessive leading zeros to octal values
func overPaddedOctal(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			b.WriteString(" ")
		}
		// Add 2-4 leading zeros
		padding := rand.Intn(3) + 2
		b.WriteString(fmt.Sprintf("%0*o", padding, c))
	}
	return b.String()
}

// splitDigitGroups breaks up octal digits with separators
func splitDigitGroups(octal string) string {
	re := regexp.MustCompile(`\\([0-7]+)`)
	return re.ReplaceAllStringFunc(octal, func(match string) string {
		digits := match[1:] // Remove leading backslash
		var result strings.Builder

		for _, digit := range digits {
			result.WriteString(fmt.Sprintf("\\%c", digit))
		}

		return result.String()
	})
}

// multilineSplitOctal splits octal encoding across multiple lines
func multilineSplitOctal(payload string) string {
	var parts []string
	for _, c := range []byte(payload) {
		parts = append(parts, fmt.Sprintf("\\%o", c))
	}

	// Add line continuation characters
	return strings.Join(parts, " \\\n")
}

// commentedOctal intersperses comments in octal encoding
func commentedOctal(payload string) string {
	var b strings.Builder
	comments := []string{
		"/* harmless */",
		"// ignore",
		"/* ok */",
		"/* safe */",
		"// allowed",
	}

	for i, c := range []byte(payload) {
		b.WriteString(fmt.Sprintf("\\%o", c))

		// Add a comment after some octal values
		if i%3 == 0 {
			comment := comments[rand.Intn(len(comments))]
			b.WriteString(comment)
		}
	}

	return b.String()
}

// nestingOctalEncoding creates nested octal encoding patterns
func nestingOctalEncoding(payload string) string {
	// First convert to octal
	octalStr := ""
	for _, c := range []byte(payload) {
		octalStr += fmt.Sprintf("\\%o", c)
	}

	// Then encode that octal string again
	var b strings.Builder
	for _, c := range []byte(octalStr) {
		b.WriteString(fmt.Sprintf("\\%o", c))
	}

	return b.String()
}

// mixedRadixEncoding mixes octal with other radix encodings in complex patterns
func mixedRadixEncoding(payload string) string {
	var b strings.Builder
	for i, c := range []byte(payload) {
		if i > 0 {
			// Use different separators
			separators := []string{" ", ".", "_", "-", "+"}
			b.WriteString(separators[rand.Intn(len(separators))])
		}

		// Cycle through different radix encodings
		switch i % 4 {
		case 0:
			b.WriteString(fmt.Sprintf("0%o", c)) // Octal
		case 1:
			b.WriteString(fmt.Sprintf("0x%x", c)) // Hex
		case 2:
			b.WriteString(fmt.Sprintf("%d", c)) // Decimal
		case 3:
			b.WriteString(fmt.Sprintf("0b%b", c)) // Binary
		}
	}

	return b.String()
}

// octalWithControlChars inserts control characters between octal values
func octalWithControlChars(payload string) string {
	var b strings.Builder
	controlChars := []string{
		"\\x00", "\\x01", "\\x02", "\\x03", "\\x04",
		"\\x05", "\\x06", "\\x07", "\\x08", "\\x09",
	}

	for _, c := range []byte(payload) {
		b.WriteString(fmt.Sprintf("\\%o", c))
		// Insert random control character
		b.WriteString(controlChars[rand.Intn(len(controlChars))])
	}

	return b.String()
}

// encodedPathTraversal creates path traversal with octal encoding
func encodedPathTraversal(payload string) string {
	var b strings.Builder
	b.WriteString("../") // Add path traversal prefix

	for _, c := range []byte(payload) {
		b.WriteString(fmt.Sprintf("\\%o", c))
	}

	return b.String()
}

// doubleEncodedOctal performs double encoding on octal values
func doubleEncodedOctal(payload string) string {
	// First encode to octal
	var firstPass strings.Builder
	for _, c := range []byte(payload) {
		firstPass.WriteString(fmt.Sprintf("\\%o", c))
	}

	// Then URL-encode the backslashes
	encoded := strings.ReplaceAll(firstPass.String(), "\\", "%5C")

	return encoded
}

// shuffleDigitOrder shuffles octal digits with position markers
func shuffleDigitOrder(payload string) string {
	var b strings.Builder

	for _, c := range []byte(payload) {
		// Convert to octal without leading backslash
		octal := fmt.Sprintf("%o", c)

		// Add position markers and shuffle
		if len(octal) == 3 {
			// Format: \[2]X\[0]Y\[1]Z where X,Y,Z are the digits
			b.WriteString(fmt.Sprintf("\\[2]%c\\[0]%c\\[1]%c",
				octal[2], octal[0], octal[1]))
		} else if len(octal) == 2 {
			b.WriteString(fmt.Sprintf("\\[1]%c\\[0]%c",
				octal[1], octal[0]))
		} else {
			b.WriteString(fmt.Sprintf("\\[0]%c", octal[0]))
		}
	}

	return b.String()
}

// octalWithUnicode mixes octal with Unicode escape sequences
func octalWithUnicode(payload string) string {
	var b strings.Builder

	for i, c := range []byte(payload) {
		if i%2 == 0 {
			// Octal encoding
			b.WriteString(fmt.Sprintf("\\%o", c))
		} else {
			// Unicode encoding
			b.WriteString(fmt.Sprintf("\\u%04x", c))
		}
	}

	return b.String()
}

func obfuscatedOctalAssignment(payload string) string {
	var parts []string

	// Create variable assignments x1=\123, x2=\124, etc.
	for i, c := range []byte(payload) {
		parts = append(parts, fmt.Sprintf("x%d=\\%o", i+1, c))
	}

	// Join with semicolons
	return strings.Join(parts, ";")
}

func escapedOctalVariant(payload string) string {
	var b strings.Builder

	b.WriteString("eval(\"")
	for _, c := range []byte(payload) {
		b.WriteString(fmt.Sprintf("\\\\%o", c))
	}
	b.WriteString("\")")

	return b.String()
}

// octalWithWhitespaceVariations creates octal encoding with various whitespace formats
func octalWithWhitespaceVariations(payload string) string {
	var b strings.Builder
	whitespaces := []string{
		" ", "\t", "\n", "\r", "\f", "\v",
		"\u00A0", // Non-breaking space
		"\u2003", // Em space
		"\u2009", // Thin space
	}

	for i, c := range []byte(payload) {
		if i > 0 {
			// Add 1-3 random whitespace characters
			count := rand.Intn(3) + 1
			for j := 0; j < count; j++ {
				b.WriteString(whitespaces[rand.Intn(len(whitespaces))])
			}
		}

		b.WriteString(fmt.Sprintf("\\%o", c))
	}

	return b.String()
}
