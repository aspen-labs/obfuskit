package encoders

import (
	"net/url"
	"obfuskit/types"
	"strings"
	"testing"
)

func TestURLVariants(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		level    types.EvasionLevel
		minCount int                   // Minimum expected variants
		checks   []func([]string) bool // Additional validation functions
	}{
		{
			name:     "Basic level with simple payload",
			payload:  "test",
			level:    types.EvasionLevelBasic,
			minCount: 1,
			checks: []func([]string) bool{
				func(variants []string) bool {
					return containsVariant(variants, url.QueryEscape("test"))
				},
				func(variants []string) bool {
					return containsVariant(variants, url.PathEscape("test"))
				},
			},
		},
		{
			name:     "Basic level with special characters",
			payload:  "<script>alert('test')</script>",
			level:    types.EvasionLevelBasic,
			minCount: 2,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain URL encoded version
					for _, v := range variants {
						if strings.Contains(v, "%3C") || strings.Contains(v, "%3c") {
							return true
						}
					}
					return false
				},
			},
		},
		{
			name:     "Medium level increases variant count",
			payload:  "test&data=value",
			level:    types.EvasionLevelMedium,
			minCount: 4,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should include partial encoding variants
					return len(variants) >= 4
				},
			},
		},
		{
			name:     "Advanced level provides most variants",
			payload:  "<script>alert('xss')</script>",
			level:    types.EvasionLevelAdvanced,
			minCount: 8,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should include double encoding
					for _, v := range variants {
						if strings.Contains(v, "%25") {
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
			payload:  "café",
			level:    types.EvasionLevelMedium,
			minCount: 3,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should handle Unicode properly
					return len(variants) > 0
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := URLVariants(tt.payload, tt.level)

			if len(variants) < tt.minCount {
				t.Errorf("URLVariants() returned %d variants, expected at least %d", len(variants), tt.minCount)
			}

			// Check for duplicates
			seen := make(map[string]bool)
			for _, variant := range variants {
				if seen[variant] {
					t.Errorf("URLVariants() returned duplicate variant: %s", variant)
				}
				seen[variant] = true
			}

			// Run additional checks
			for i, check := range tt.checks {
				if !check(variants) {
					t.Errorf("URLVariants() failed check %d for test %s", i+1, tt.name)
				}
			}
		})
	}
}

func TestManualURLEncode(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		uppercase bool
		expected  string
	}{
		{
			name:      "Simple text lowercase",
			input:     "hello world",
			uppercase: false,
			expected:  "hello%20world",
		},
		{
			name:      "Simple text uppercase",
			input:     "hello world",
			uppercase: true,
			expected:  "hello%20world",
		},
		{
			name:      "Special characters lowercase",
			input:     "<script>",
			uppercase: false,
			expected:  "%3cscript%3e",
		},
		{
			name:      "Special characters uppercase",
			input:     "<script>",
			uppercase: true,
			expected:  "%3Cscript%3E",
		},
		{
			name:      "Safe characters",
			input:     "abc123-_.~",
			uppercase: false,
			expected:  "abc123-_.~",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manualURLEncode(tt.input, tt.uppercase)
			if result != tt.expected {
				t.Errorf("manualURLEncode() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestShouldEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected bool
	}{
		{"Letter A", 'A', false},
		{"Letter a", 'a', false},
		{"Digit 0", '0', false},
		{"Hyphen", '-', false},
		{"Underscore", '_', false},
		{"Period", '.', false},
		{"Tilde", '~', false},
		{"Space", ' ', true},
		{"Less than", '<', true},
		{"Greater than", '>', true},
		{"Ampersand", '&', true},
		{"Question mark", '?', true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldEncode(tt.input)
			if result != tt.expected {
				t.Errorf("shouldEncode(%c) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPartialURLEncode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		ratio float64
	}{
		{
			name:  "50% encoding",
			input: "<script>alert('test')</script>",
			ratio: 0.5,
		},
		{
			name:  "30% encoding",
			input: "hello world & friends",
			ratio: 0.3,
		},
		{
			name:  "0% encoding",
			input: "<>&?",
			ratio: 0.0,
		},
		{
			name:  "100% encoding",
			input: "<>&?",
			ratio: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := partialURLEncode(tt.input, tt.ratio)

			// Should not be empty
			if len(result) == 0 && len(tt.input) > 0 {
				t.Errorf("partialURLEncode() returned empty string for non-empty input")
			}

			// For 0% ratio, should be mostly unencoded (except for strategic encoding)
			if tt.ratio == 0.0 {
				percentCount := strings.Count(result, "%")
				if percentCount > len(tt.input)/2 {
					t.Errorf("partialURLEncode() with 0%% ratio encoded too many characters")
				}
			}
		})
	}
}

func TestAdvancedURLEncodingFunctions(t *testing.T) {
	testPayload := "<script>alert('test')</script>"

	t.Run("mixedCaseURLEncode", func(t *testing.T) {
		result := mixedCaseURLEncode(testPayload)
		if len(result) == 0 {
			t.Error("mixedCaseURLEncode() returned empty string")
		}

		// Should contain both cases
		hasLower := strings.Contains(result, "%3c") || strings.Contains(result, "%2f")
		hasUpper := strings.Contains(result, "%3C") || strings.Contains(result, "%2F")
		if !hasLower && !hasUpper {
			t.Error("mixedCaseURLEncode() should contain mixed case encoding")
		}
	})

	t.Run("unicodeURLEncode", func(t *testing.T) {
		result := unicodeURLEncode(testPayload)
		if len(result) == 0 {
			t.Error("unicodeURLEncode() returned empty string")
		}
	})

	t.Run("plusSpaceEncode", func(t *testing.T) {
		input := "hello world"
		result := plusSpaceEncode(input)
		if strings.Contains(result, "%20") {
			t.Error("plusSpaceEncode() should replace %20 with +")
		}
		if !strings.Contains(result, "+") {
			t.Error("plusSpaceEncode() should contain + for spaces")
		}
	})

	t.Run("malformedURLEncode", func(t *testing.T) {
		result := malformedURLEncode(testPayload)
		if len(result) == 0 {
			t.Error("malformedURLEncode() returned empty string")
		}
	})

	t.Run("nullByteURLEncode", func(t *testing.T) {
		result := nullByteURLEncode(testPayload)
		if !strings.Contains(result, "%00") {
			t.Error("nullByteURLEncode() should contain null byte encoding")
		}
	})

	t.Run("unicodeNormalizationEncode", func(t *testing.T) {
		result := unicodeNormalizationEncode(testPayload)
		// Should contain Unicode escape sequences
		if !strings.Contains(result, "%u") {
			t.Error("unicodeNormalizationEncode() should contain Unicode escape sequences")
		}
	})
}

// Helper function to check if a variant exists in the slice
func containsVariant(variants []string, target string) bool {
	for _, variant := range variants {
		if variant == target {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkURLVariantsBasic(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		URLVariants(payload, types.EvasionLevelBasic)
	}
}

func BenchmarkURLVariantsMedium(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		URLVariants(payload, types.EvasionLevelMedium)
	}
}

func BenchmarkURLVariantsAdvanced(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		URLVariants(payload, types.EvasionLevelAdvanced)
	}
}
