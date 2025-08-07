package encoders

import (
	"net/url"
	"obfuskit/internal/evasions"
	"obfuskit/types"
)

// DoubleURLVariants generates double URL encoded variants of the input payload
// based on the specified obfuscation level
func DoubleURLVariants(payload string, level types.EvasionLevel) []string {
	var variants []string

	// First get single URL encoded variants
	singleEncoded := URLVariants(payload, types.EvasionLevelBasic)

	// Basic double encoding - apply URL encoding twice
	for _, encoded := range singleEncoded {
		doubleEncoded := url.QueryEscape(encoded)
		variants = append(variants, doubleEncoded)
	}

	// Ensure we have actual double encoding even for safe strings
	if len(variants) == 0 || (len(variants) == 1 && variants[0] == payload) {
		// Force encode the payload first, then double encode
		firstEncode := forceURLEncode(payload, false)
		doubleEncoded := url.QueryEscape(firstEncode)
		variants = append(variants, doubleEncoded)
	}

	// Standard double encoding
	standard := url.QueryEscape(payload)
	doubleStandard := url.QueryEscape(standard)
	variants = append(variants, doubleStandard)

	// Return basic variants if level is Basic
	if level == types.EvasionLevelBasic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds mixed encoding approaches
	manualFirst := manualURLEncode(payload, false)
	standardSecond := url.QueryEscape(manualFirst)
	variants = append(variants, standardSecond)

	// Path encoding first, then query encoding
	pathFirst := url.PathEscape(payload)
	querySecond := url.QueryEscape(pathFirst)
	variants = append(variants, querySecond)

	// Return medium variants if level is Medium
	if level == types.EvasionLevelMedium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds triple encoding and asymmetric encoding
	// Triple encoding
	tripleEncoded := url.QueryEscape(doubleStandard)
	variants = append(variants, tripleEncoded)

	// Asymmetric double encoding (different methods for each pass)
	for _, singleVar := range URLVariants(payload, types.EvasionLevelMedium) {
		// Apply different encoding methods
		variants = append(variants, url.QueryEscape(singleVar))
		variants = append(variants, url.PathEscape(singleVar))
	}

	return evasions.UniqueStrings(variants)
}
