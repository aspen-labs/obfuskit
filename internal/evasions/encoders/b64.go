package encoders

import (
	"encoding/base64"
	"obfuskit/constants"
	"obfuskit/internal/evasions"
	"strings"
)

// Base64Variants generates various base64 encoded variants of the input payload
// based on the specified obfuscation level
func Base64Variants(payload string, level constants.Level) []string {
	raw := []byte(payload)
	var variants []string

	// Standard and URL-safe encodings
	stdEncoded := base64.StdEncoding.EncodeToString(raw)
	urlEncoded := base64.URLEncoding.EncodeToString(raw)

	// Basic variants with different paddings
	variants = append(variants,
		stdEncoded,                         // Standard with padding
		strings.TrimRight(stdEncoded, "="), // No padding
		urlEncoded,                         // URL-safe with padding
		strings.TrimRight(urlEncoded, "="), // URL-safe no padding
		urlEncoded+"=",                     // URL-safe over-padded
		urlEncoded[:len(urlEncoded)-1],     // URL-safe under-padded
	)

	// Return basic variants if level is Basic
	if level == constants.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds padding manipulations
	variants = append(variants,
		stdEncoded+"=",                 // Over-padded
		stdEncoded+"===",               // Malformed extra padding
		stdEncoded[:len(stdEncoded)-1], // Under-padded
		stdEncoded[:len(stdEncoded)-2], // Missing 2 padding chars
	)

	// Return medium variants if level is Medium
	if level == constants.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds double encoding and reversed payload encoding
	doubleStd := base64.StdEncoding.EncodeToString([]byte(stdEncoded))
	variants = append(variants, doubleStd)

	// Reversed payload then base64 encoded
	reversed := reverse(payload)
	reversedEncoded := base64.StdEncoding.EncodeToString([]byte(reversed))
	variants = append(variants, reversedEncoded)

	return evasions.UniqueStrings(variants)
}

// reverse returns the reversed version of input string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
