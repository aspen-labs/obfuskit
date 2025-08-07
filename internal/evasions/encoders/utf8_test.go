package encoders

import (
	"obfuskit/types"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUTF8Variants(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		level    types.EvasionLevel
		minCount int
		checks   []func([]string) bool
	}{
		{
			name:     "Basic level UTF-8 encoding",
			payload:  "test",
			level:    types.EvasionLevelBasic,
			minCount: 4,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain hex encoding
					for _, v := range variants {
						if strings.Contains(v, "\\x") {
							return true
						}
					}
					return false
				},
				func(variants []string) bool {
					// Should contain octal encoding
					for _, v := range variants {
						if strings.Contains(v, "\\0") || strings.Contains(v, "\\1") {
							return true
						}
					}
					return false
				},
			},
		},
		{
			name:     "Basic level with special characters",
			payload:  "<script>",
			level:    types.EvasionLevelBasic,
			minCount: 4,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain percent encoding
					for _, v := range variants {
						if strings.Contains(v, "%") {
							return true
						}
					}
					return false
				},
			},
		},
		{
			name:     "Medium level with normalization",
			payload:  "café",
			level:    types.EvasionLevelMedium,
			minCount: 6,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain BOM
					for _, v := range variants {
						if strings.Contains(v, "\\xEF\\xBB\\xBF") {
							return true
						}
					}
					return false
				},
			},
		},
		{
			name:     "Advanced level with malformed sequences",
			payload:  "test",
			level:    types.EvasionLevelAdvanced,
			minCount: 10,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain replacement characters
					for _, v := range variants {
						if strings.Contains(v, "\uFFFD") {
							return true
						}
					}
					return false
				},
				func(variants []string) bool {
					// Should contain zero-width characters
					for _, v := range variants {
						if strings.Contains(v, "\u200B") || strings.Contains(v, "\u200C") {
							return true
						}
					}
					return false
				},
			},
		},
		{
			name:     "Empty payload",
			payload:  "",
			level:    types.EvasionLevelBasic,
			minCount: 1,
			checks: []func([]string) bool{
				func(variants []string) bool {
					return len(variants) >= 1
				},
			},
		},
		{
			name:     "Unicode characters",
			payload:  "🚀test",
			level:    types.EvasionLevelMedium,
			minCount: 5,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should handle multi-byte UTF-8
					return len(variants) > 0
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := UTF8Variants(tt.payload, tt.level)

			if len(variants) < tt.minCount {
				t.Errorf("UTF8Variants() returned %d variants, expected at least %d", len(variants), tt.minCount)
			}

			// Check for duplicates
			seen := make(map[string]bool)
			for _, variant := range variants {
				if seen[variant] {
					t.Errorf("UTF8Variants() returned duplicate variant: %s", variant)
				}
				seen[variant] = true
			}

			// Run additional checks
			for i, check := range tt.checks {
				if !check(variants) {
					t.Errorf("UTF8Variants() failed check %d for test %s", i+1, tt.name)
				}
			}
		})
	}
}

func TestUTF8HexEncoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple ASCII",
			input:    "A",
			expected: "\\x41",
		},
		{
			name:     "Multiple characters",
			input:    "AB",
			expected: "\\x41\\x42",
		},
		{
			name:     "Special character",
			input:    "<",
			expected: "\\x3c",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8HexEncoding(tt.input)
			if result != tt.expected {
				t.Errorf("utf8HexEncoding() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUTF8OctalEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Simple ASCII",
			input: "A",
		},
		{
			name:  "Special character",
			input: "<",
		},
		{
			name:  "Multiple characters",
			input: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8OctalEncoding(tt.input)

			// Should contain octal escapes
			if len(tt.input) > 0 && !strings.Contains(result, "\\") {
				t.Errorf("utf8OctalEncoding() should contain octal escapes for non-empty input")
			}

			// Should have correct format (3 digits after backslash)
			if len(tt.input) > 0 {
				parts := strings.Split(result, "\\")
				if len(parts) < 2 {
					t.Errorf("utf8OctalEncoding() should produce octal escape sequences")
				}
			}
		})
	}
}

func TestUTF8DecimalEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Simple ASCII",
			input: "A",
		},
		{
			name:  "Special character",
			input: "<",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8DecimalEncoding(tt.input)

			// Should contain HTML numeric entities
			if len(tt.input) > 0 && !strings.Contains(result, "&#") {
				t.Errorf("utf8DecimalEncoding() should contain HTML numeric entities")
			}

			if len(tt.input) > 0 && !strings.Contains(result, ";") {
				t.Errorf("utf8DecimalEncoding() should contain semicolons")
			}
		})
	}
}

func TestUTF8BinaryEncoding(t *testing.T) {
	input := "A"
	result := utf8BinaryEncoding(input)

	// Should contain binary representation
	if !strings.Contains(result, "\\b") {
		t.Errorf("utf8BinaryEncoding() should contain binary escape sequences")
	}

	// Should contain 8-bit binary
	if !strings.Contains(result, "01000001") { // Binary for 'A'
		t.Errorf("utf8BinaryEncoding() should contain correct binary representation")
	}
}

func TestUTF8PercentEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Simple ASCII",
			input: "A",
		},
		{
			name:  "Special character",
			input: "<",
		},
		{
			name:  "Space",
			input: " ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8PercentEncoding(tt.input)

			// Should contain percent encoding
			if len(tt.input) > 0 && !strings.Contains(result, "%") {
				t.Errorf("utf8PercentEncoding() should contain percent signs")
			}
		})
	}
}

func TestUTF8OverlongEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "ASCII character",
			input: "A",
		},
		{
			name:  "Special character",
			input: "<",
		},
		{
			name:  "Non-ASCII character",
			input: "é",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8OverlongEncoding(tt.input)

			// Should not be empty for non-empty input
			if len(tt.input) > 0 && len(result) == 0 {
				t.Errorf("utf8OverlongEncoding() returned empty string for non-empty input")
			}

			// For ASCII characters, should create overlong encoding
			if len(tt.input) == 1 && tt.input[0] < 128 {
				if !strings.Contains(result, "\\x") {
					t.Errorf("utf8OverlongEncoding() should create overlong sequences for ASCII")
				}
			}
		})
	}
}

func TestUTF8NormalizationVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		testFunc func(string) string
		funcName string
	}{
		{
			name:     "NFC normalization with é",
			input:    "café",
			testFunc: utf8NormalizationC,
			funcName: "utf8NormalizationC",
		},
		{
			name:     "NFD normalization with vowels",
			input:    "test",
			testFunc: utf8NormalizationD,
			funcName: "utf8NormalizationD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.input)

			// Should not be empty for non-empty input
			if len(tt.input) > 0 && len(result) == 0 {
				t.Errorf("%s() returned empty string for non-empty input", tt.funcName)
			}

			// Length should be preserved or increased (due to combining characters)
			if len(result) < len(tt.input) {
				t.Errorf("%s() should not decrease string length", tt.funcName)
			}
		})
	}
}

func TestUTF8MixedEncoding(t *testing.T) {
	input := "test"
	result := utf8MixedEncoding(input)

	// Should contain different encoding styles
	hasHex := strings.Contains(result, "\\x")
	hasOctal := strings.Contains(result, "\\0") || strings.Contains(result, "\\1")
	hasDecimal := strings.Contains(result, "&#")
	hasPlain := false

	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasPlain = true
			break
		}
	}

	encodingTypes := 0
	if hasHex {
		encodingTypes++
	}
	if hasOctal {
		encodingTypes++
	}
	if hasDecimal {
		encodingTypes++
	}
	if hasPlain {
		encodingTypes++
	}

	if encodingTypes < 2 {
		t.Errorf("utf8MixedEncoding() should use multiple encoding types, found %d", encodingTypes)
	}
}

func TestUTF8NullByteEncoding(t *testing.T) {
	input := "test"
	result := utf8NullByteEncoding(input)

	// Should contain null byte encoding
	if !strings.Contains(result, "\\x00") {
		t.Errorf("utf8NullByteEncoding() should contain null byte encoding")
	}

	// Should contain original content or null bytes
	if !strings.Contains(result, "test") && !strings.Contains(result, "\\x00") {
		t.Errorf("utf8NullByteEncoding() should preserve original content or contain null bytes")
	}
}

func TestUTF8BOMVariants(t *testing.T) {
	input := "test"
	result := utf8BOMVariants(input)

	// Should start with BOM
	if !strings.HasPrefix(result, "\\xEF\\xBB\\xBF") {
		t.Errorf("utf8BOMVariants() should start with UTF-8 BOM")
	}

	// Should contain original content
	if !strings.Contains(result, input) {
		t.Errorf("utf8BOMVariants() should contain original content")
	}
}

func TestUTF8MalformedSequences(t *testing.T) {
	input := "test"
	result := utf8MalformedSequences(input)

	// Should not be empty
	if len(result) == 0 {
		t.Errorf("utf8MalformedSequences() returned empty string")
	}

	// Should contain some of the original content
	if !strings.Contains(result, "est") { // At least part of "test"
		t.Errorf("utf8MalformedSequences() should preserve some original content")
	}
}

func TestUTF8SurrogateEncoding(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Basic ASCII",
			input: "test",
		},
		{
			name:  "High Unicode",
			input: "🚀", // This should trigger surrogate encoding logic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8SurrogateEncoding(tt.input)

			// Should not be empty for non-empty input
			if len(tt.input) > 0 && len(result) == 0 {
				t.Errorf("utf8SurrogateEncoding() returned empty string for non-empty input")
			}
		})
	}
}

func TestUTF8SpecialCharacterEncoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		testFunc func(string) string
		funcName string
	}{
		{
			name:     "Replacement character",
			input:    "test",
			testFunc: utf8ReplacementChar,
			funcName: "utf8ReplacementChar",
		},
		{
			name:     "Control character",
			input:    "test",
			testFunc: utf8ControlCharEncoding,
			funcName: "utf8ControlCharEncoding",
		},
		{
			name:     "Zero-width encoding",
			input:    "test",
			testFunc: utf8ZeroWidthEncoding,
			funcName: "utf8ZeroWidthEncoding",
		},
		{
			name:     "Directional marks",
			input:    "test",
			testFunc: utf8DirectionalMarks,
			funcName: "utf8DirectionalMarks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.input)

			// Should not be empty for non-empty input
			if len(tt.input) > 0 && len(result) == 0 {
				t.Errorf("%s() returned empty string for non-empty input", tt.funcName)
			}

			// Should contain original content or be longer (indicating transformation)
			if !strings.Contains(result, tt.input) && len(result) <= len(tt.input) {
				t.Errorf("%s() should transform input meaningfully", tt.funcName)
			}
		})
	}
}

func TestUTF8CompatibilityChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected rune
	}{
		{
			name:     "Capital A",
			input:    "A",
			expected: '\uFF21',
		},
		{
			name:     "Lowercase a",
			input:    "a",
			expected: '\uFF41',
		},
		{
			name:     "Digit 0",
			input:    "0",
			expected: '\uFF10',
		},
		{
			name:     "Less than",
			input:    "<",
			expected: '\uFF1C',
		},
		{
			name:     "Greater than",
			input:    ">",
			expected: '\uFF1E',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf8CompatibilityChars(tt.input)

			// Should contain the expected fullwidth character
			if !strings.ContainsRune(result, tt.expected) {
				t.Errorf("utf8CompatibilityChars() should contain fullwidth character %U", tt.expected)
			}
		})
	}
}

func TestIsValidUTF8(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "Valid ASCII",
			input:    []byte("hello"),
			expected: true,
		},
		{
			name:     "Valid UTF-8",
			input:    []byte("café"),
			expected: true,
		},
		{
			name:     "Invalid UTF-8",
			input:    []byte{0xFF, 0xFE},
			expected: false,
		},
		{
			name:     "Empty",
			input:    []byte{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidUTF8(tt.input)
			if result != tt.expected {
				t.Errorf("isValidUTF8() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUTF8EvasionLevels(t *testing.T) {
	payload := "test"

	basicVariants := UTF8Variants(payload, types.EvasionLevelBasic)
	mediumVariants := UTF8Variants(payload, types.EvasionLevelMedium)
	advancedVariants := UTF8Variants(payload, types.EvasionLevelAdvanced)

	// Higher levels should produce more variants
	if len(mediumVariants) <= len(basicVariants) {
		t.Error("Medium level should produce more variants than basic level")
	}

	if len(advancedVariants) <= len(mediumVariants) {
		t.Error("Advanced level should produce more variants than medium level")
	}
}

func TestUTF8WithValidUnicodeInput(t *testing.T) {
	unicodeInputs := []string{
		"café",    // Latin with accent
		"München", // German with umlaut
		"🚀test",   // Emoji
		"中文",      // Chinese characters
		"עברית",   // Hebrew
		"العربية", // Arabic
	}

	for _, input := range unicodeInputs {
		t.Run("Unicode_"+input, func(t *testing.T) {
			if !utf8.ValidString(input) {
				t.Skip("Input is not valid UTF-8")
			}

			variants := UTF8Variants(input, types.EvasionLevelBasic)

			if len(variants) == 0 {
				t.Errorf("UTF8Variants() should handle Unicode input: %s", input)
			}

			// Should not panic and should produce some output
			for _, variant := range variants {
				if len(variant) == 0 {
					t.Errorf("UTF8Variants() produced empty variant for input: %s", input)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkUTF8VariantsBasic(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		UTF8Variants(payload, types.EvasionLevelBasic)
	}
}

func BenchmarkUTF8VariantsMedium(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		UTF8Variants(payload, types.EvasionLevelMedium)
	}
}

func BenchmarkUTF8VariantsAdvanced(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		UTF8Variants(payload, types.EvasionLevelAdvanced)
	}
}
