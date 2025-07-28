package encoders

import (
	"fmt"
	"math/rand"
	"obfuskit/evasions"
	"obfuskit/types"
	"regexp"
	"strings"
)

// HexVariants generates various hex encoded variants of the input payload
// based on the specified obfuscation level
func HexVariants(payload string, level types.EvasionLevel) []string {
	var variants []string

	// Basic hex encodings
	hexLower := toHex(payload, false)
	hexUpper := toHex(payload, true)

	// Curly brace style variants
	hexCurlyLower := addCurlyPrefix(hexLower)
	hexCurlyUpper := addCurlyPrefix(hexUpper)

	// Basic variants
	variants = append(variants,
		hexCurlyLower,                // \x{hh} style lowercase
		hexCurlyUpper,                // \x{hh} style uppercase
		splitCurlyHex(hexCurlyLower), // Split curly hex lowercase
		splitCurlyHex(hexCurlyUpper), // Split curly hex uppercase
		hexLower,                     // Plain hex lowercase
		hexUpper,                     // Plain hex uppercase
		addPrefix(hexLower),          // \xhh-style (lowercase)
		addPrefix(hexUpper),          // \xhh-style (uppercase)
		percentEncode(hexLower),      // %hh-style lowercase
		percentEncode(hexUpper),      // %hh-style uppercase
		jsConcatStyle(hexLower),      // JavaScript concat style lowercase
		jsConcatStyle(hexUpper),      // JavaScript concat style uppercase
	)

	// Return basic variants if level is Basic
	if level == types.EvasionLevelBasic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds whitespace character bypasses
	// Referenced from: https://github.com/Mehdi0x90/Web_Hacking/blob/main/WAF%20Bypass.md#nodejs
	variants = append(variants,
		appendHexLiteral(payload, "A0"), // Non-breaking space
		appendHexLiteral(payload, "09"), // Tab
		appendHexLiteral(payload, "0C"), // Form feed
	)

	// Return medium variants if level is Medium
	if level == types.EvasionLevelMedium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds null bytes and control characters
	variants = append(variants,
		appendRandomly(payload, "00"), // Null character
		// Control characters for bypassing filters
		appendRandomly(payload, "01"), // Start of Heading
		appendRandomly(payload, "02"), // Start of Text
		appendRandomly(payload, "03"), // End of Text
		appendRandomly(payload, "04"), // End of Transmission
		appendRandomly(payload, "05"), // Enquiry
		appendRandomly(payload, "06"), // Acknowledge
		appendRandomly(payload, "07"), // Bell
		appendRandomly(payload, "08"), // Backspace
		appendRandomly(payload, "0A"), // Line feed
		appendRandomly(payload, "0B"), // Vertical tab
		appendRandomly(payload, "0C"), // Form feed
		appendRandomly(payload, "0D"), // Carriage return
		appendRandomly(payload, "0E"), // Shift Out
		appendRandomly(payload, "0F"), // Shift In

		// Complex insertion between words
		appendRandomlyInBetweenWords(payload, "00"),
	)

	// Advanced WAF evasion techniques - splitting hex values
	variants = append(variants,
		splitHex(addPrefix(hexLower), "\\x"),   // Split hex with null bytes
		splitHex(percentEncode(hexLower), "%"), // Split percent encoding
	)

	return evasions.UniqueStrings(variants)
}

// appendRandomlyInBetweenWords splits the payload into words and non-words,
// then for each word it performs 1–3 random insertions of the escape sequence.
func appendRandomlyInBetweenWords(payload, hexBytes string) string {
	// Prepare the insertion string
	insert := `\x` + hexBytes
	if hexBytes == `\b` {
		// Wrap backspace in NULs
		insert = "\x00" + `\b` + "\x00"
	}

	// Regex to capture words (\w+) and non-word spans (\W+)
	re := regexp.MustCompile(`\w+|\W+`)
	tokens := re.FindAllString(payload, -1)

	// For detecting words
	wordRe := regexp.MustCompile(`^\w+$`)

	for i, tok := range tokens {
		if wordRe.MatchString(tok) {
			// Decide how many times to insert into this word
			times := rand.Intn(3) + 1
			for j := 0; j < times; j++ {
				// Pick a random insertion point within the word
				pos := rand.Intn(len(tok) + 1)
				tok = tok[:pos] + insert + tok[pos:]
			}
			tokens[i] = tok
		}
	}

	return strings.Join(tokens, "")
}

func appendRandomly(payload string, hexBytes string) string {
	// Find a random index and insert the string
	var b strings.Builder
	b.WriteString(payload[:rand.Intn(len(payload))])
	b.WriteString("\\x" + hexBytes)
	b.WriteString(payload[rand.Intn(len(payload)):])
	return b.String()
}

func appendHexLiteral(payload, hexByte string) string {
	return payload + `\x` + hexByte
}

func toHex(s string, upper bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if upper {
			b.WriteString(fmt.Sprintf("%02X", c))
		} else {
			b.WriteString(fmt.Sprintf("%02x", c))
		}
	}
	return b.String()
}

func addPrefix(hex string) string {
	var out strings.Builder
	for i := 0; i < len(hex); i += 2 {
		out.WriteString("\\x" + hex[i:i+2])
	}
	return out.String()
}

func percentEncode(hex string) string {
	var out strings.Builder
	for i := 0; i < len(hex); i += 2 {
		out.WriteString("%" + hex[i:i+2])
	}
	return out.String()
}

func jsConcatStyle(hex string) string {
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, fmt.Sprintf("'\\x%s'", hex[i:i+2]))
	}
	return strings.Join(parts, "+")
}

// splitHex adds dummy separators (like \x61\x00\x6c...) to trick WAFs
func splitHex(encoded, prefix string) string {
	return strings.ReplaceAll(encoded, prefix, prefix+"00"+prefix)
}

func addCurlyPrefix(hex string) string {
	var out strings.Builder
	for i := 0; i < len(hex); i += 2 {
		out.WriteString("\\x{" + hex[i:i+2] + "}")
	}
	return out.String()
}

func splitCurlyHex(hexCurly string) string {
	return strings.ReplaceAll(hexCurly, "}", "00}")
}
