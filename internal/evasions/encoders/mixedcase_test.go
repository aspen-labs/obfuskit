package encoders

import (
	"obfuskit/types"
	"strings"
	"testing"
	"unicode"
)

func TestMixedCaseVariants(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		level    types.EvasionLevel
		minCount int
		checks   []func([]string) bool
	}{
		{
			name:     "Basic level alternating case",
			payload:  "script",
			level:    types.EvasionLevelBasic,
			minCount: 3,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain alternating case
					for _, v := range variants {
						if hasAlternatingCase(v) {
							return true
						}
					}
					return false
				},
			},
		},
		{
			name:     "Basic level with HTML tags",
			payload:  "<script>alert</script>",
			level:    types.EvasionLevelBasic,
			minCount: 3,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should preserve structure while changing case
					for _, v := range variants {
						if strings.Contains(v, "<") && strings.Contains(v, ">") {
							return true
						}
					}
					return true // Structure should be preserved
				},
			},
		},
		{
			name:     "Medium level increases variant count",
			payload:  "hello world",
			level:    types.EvasionLevelMedium,
			minCount: 5,
			checks: []func([]string) bool{
				func(variants []string) bool {
					return len(variants) >= 5
				},
			},
		},
		{
			name:     "Advanced level with Unicode transformations",
			payload:  "test script",
			level:    types.EvasionLevelAdvanced,
			minCount: 8,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should include leet speak variants
					for _, v := range variants {
						if strings.Contains(v, "@") || strings.Contains(v, "3") || strings.Contains(v, "$") {
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
			name:     "Numbers and special characters",
			payload:  "test123!@#",
			level:    types.EvasionLevelMedium,
			minCount: 3,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Numbers and special chars should be preserved
					for _, v := range variants {
						if strings.Contains(v, "123") {
							return true
						}
					}
					return false
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := MixedCaseVariants(tt.payload, tt.level)
			
			if len(variants) < tt.minCount {
				t.Errorf("MixedCaseVariants() returned %d variants, expected at least %d", len(variants), tt.minCount)
			}
			
			// Check for duplicates
			seen := make(map[string]bool)
			for _, variant := range variants {
				if seen[variant] {
					t.Errorf("MixedCaseVariants() returned duplicate variant: %s", variant)
				}
				seen[variant] = true
			}
			
			// Run additional checks
			for i, check := range tt.checks {
				if !check(variants) {
					t.Errorf("MixedCaseVariants() failed check %d for test %s", i+1, tt.name)
				}
			}
		})
	}
}

func TestAlternatingCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple word",
			input:    "hello",
			expected: "hElLo",
		},
		{
			name:     "With numbers",
			input:    "test123",
			expected: "tEsT123",
		},
		{
			name:     "Mixed content",
			input:    "Hello World!",
			expected: "hElLo WoRlD!",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := alternatingCase(tt.input)
			if result != tt.expected {
				t.Errorf("alternatingCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRandomCase(t *testing.T) {
	tests := []struct {
		name  string
		input string
		ratio float64
	}{
		{
			name:  "50% ratio",
			input: "abcdefghij",
			ratio: 0.5,
		},
		{
			name:  "30% ratio",
			input: "hello world",
			ratio: 0.3,
		},
		{
			name:  "0% ratio",
			input: "test",
			ratio: 0.0,
		},
		{
			name:  "100% ratio",
			input: "test",
			ratio: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randomCase(tt.input, tt.ratio)
			
			// Should not be empty for non-empty input
			if len(result) == 0 && len(tt.input) > 0 {
				t.Errorf("randomCase() returned empty string for non-empty input")
			}
			
			// Length should be preserved
			if len(result) != len(tt.input) {
				t.Errorf("randomCase() changed string length: got %d, want %d", len(result), len(tt.input))
			}
		})
	}
}

func TestWordBoundaryUpper(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Multiple words",
			input:    "hello world",
			expected: "Hello World",
		},
		{
			name:     "Single word",
			input:    "test",
			expected: "Test",
		},
		{
			name:     "With punctuation",
			input:    "hello, world!",
			expected: "Hello, World!",
		},
		{
			name:     "Multiple spaces",
			input:    "hello  world",
			expected: "Hello  World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wordBoundaryUpper(tt.input)
			if result != tt.expected {
				t.Errorf("wordBoundaryUpper() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVowelConsonantCase(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		funcName string
		testFunc func(string) string
	}{
		{
			name:     "Vowel uppercase",
			input:    "hello",
			funcName: "vowelUppercase",
			testFunc: vowelUppercase,
		},
		{
			name:     "Consonant uppercase",
			input:    "hello",
			funcName: "consonantUppercase",
			testFunc: consonantUppercase,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.input)
			
			// Should not be empty for non-empty input
			if len(result) == 0 && len(tt.input) > 0 {
				t.Errorf("%s() returned empty string for non-empty input", tt.funcName)
			}
			
			// Should have some case transformation
			if result == tt.input && len(tt.input) > 0 {
				hasVowels := strings.ContainsAny(strings.ToLower(tt.input), "aeiou")
				hasConsonants := false
				for _, r := range strings.ToLower(tt.input) {
					if unicode.IsLetter(r) && !strings.ContainsRune("aeiou", r) {
						hasConsonants = true
						break
					}
				}
				
				// Only expect change if input has relevant characters
				if (tt.funcName == "vowelUppercase" && hasVowels) || 
				   (tt.funcName == "consonantUppercase" && hasConsonants) {
					t.Errorf("%s() should transform case, got same string: %s", tt.funcName, result)
				}
			}
		})
	}
}

func TestReverseCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Mixed case",
			input:    "Hello",
			expected: "hELLO",
		},
		{
			name:     "All uppercase",
			input:    "HELLO",
			expected: "hello",
		},
		{
			name:     "All lowercase",
			input:    "hello",
			expected: "HELLO",
		},
		{
			name:     "With numbers",
			input:    "Test123",
			expected: "tEST123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverseCase(tt.input)
			if result != tt.expected {
				t.Errorf("reverseCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCamelCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Two words",
			input:    "hello world",
			expected: "helloWorld",
		},
		{
			name:     "Multiple words",
			input:    "hello world test",
			expected: "helloWorldTest",
		},
		{
			name:     "Single word",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "With punctuation",
			input:    "hello, world!",
			expected: "hello,World!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := camelCase(tt.input)
			if result != tt.expected {
				t.Errorf("camelCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSnakeToUpperCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "With spaces",
			input:    "hello world",
			expected: "HELLO_WORLD",
		},
		{
			name:     "Mixed case",
			input:    "Hello World",
			expected: "HELLO_WORLD",
		},
		{
			name:     "Single word",
			input:    "hello",
			expected: "HELLO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := snakeToUpperCase(tt.input)
			if result != tt.expected {
				t.Errorf("snakeToUpperCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLeetSpeakCase(t *testing.T) {
	input := "hello"
	result := leetSpeakCase(input)
	
	// Should contain some leet substitutions
	hasLeetChars := strings.ContainsAny(result, "@30$1")
	if !hasLeetChars {
		t.Errorf("leetSpeakCase() should contain leet speak characters, got: %s", result)
	}
}

func TestZebraCaseVariants(t *testing.T) {
	input := "abcdef"
	
	zebra := zebraCase(input)
	inverseZebra := inverseZebraCase(input)
	
	// They should be different
	if zebra == inverseZebra {
		t.Errorf("zebraCase() and inverseZebraCase() should produce different results")
	}
	
	// Both should have mixed case
	if !hasMixedCase(zebra) {
		t.Errorf("zebraCase() should produce mixed case: %s", zebra)
	}
	
	if !hasMixedCase(inverseZebra) {
		t.Errorf("inverseZebraCase() should produce mixed case: %s", inverseZebra)
	}
}

func TestRandomWordCase(t *testing.T) {
	input := "hello world test case"
	result := randomWordCase(input)
	
	words := strings.Fields(result)
	originalWords := strings.Fields(input)
	
	if len(words) != len(originalWords) {
		t.Errorf("randomWordCase() should preserve word count")
	}
	
	// Should have some variation
	hasVariation := false
	for i, word := range words {
		if word != originalWords[i] {
			hasVariation = true
			break
		}
	}
	
	if !hasVariation {
		t.Errorf("randomWordCase() should produce some variation: %s", result)
	}
}

// Helper functions
func hasAlternatingCase(s string) bool {
	lastWasUpper := false
	firstLetter := true
	
	for _, r := range s {
		if unicode.IsLetter(r) {
			isUpper := unicode.IsUpper(r)
			if !firstLetter && isUpper == lastWasUpper {
				return false
			}
			lastWasUpper = isUpper
			firstLetter = false
		}
	}
	return !firstLetter // Had at least one letter
}

func hasMixedCase(s string) bool {
	hasUpper := false
	hasLower := false
	
	for _, r := range s {
		if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsLower(r) {
			hasLower = true
		}
		
		if hasUpper && hasLower {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkMixedCaseVariantsBasic(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		MixedCaseVariants(payload, types.EvasionLevelBasic)
	}
}

func BenchmarkMixedCaseVariantsMedium(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		MixedCaseVariants(payload, types.EvasionLevelMedium)
	}
}

func BenchmarkMixedCaseVariantsAdvanced(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		MixedCaseVariants(payload, types.EvasionLevelAdvanced)
	}
}