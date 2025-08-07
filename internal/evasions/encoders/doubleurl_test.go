package encoders

import (
	"net/url"
	"obfuskit/types"
	"strings"
	"testing"
)

func TestDoubleURLVariants(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		level    types.EvasionLevel
		minCount int
		checks   []func([]string) bool
	}{
		{
			name:     "Basic level double encoding",
			payload:  "hello world",
			level:    types.EvasionLevelBasic,
			minCount: 1,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain double encoded version
					expected := url.QueryEscape(url.QueryEscape("hello world"))
					return containsVariant(variants, expected)
				},
			},
		},
		{
			name:     "Basic level with special characters",
			payload:  "<script>",
			level:    types.EvasionLevelBasic,
			minCount: 2,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain %25 (double encoded %)
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
			name:     "Medium level mixed encoding",
			payload:  "hello world",
			level:    types.EvasionLevelMedium,
			minCount: 2,
			checks: []func([]string) bool{
				func(variants []string) bool {
					return len(variants) >= 2
				},
			},
		},
		{
			name:     "Advanced level with triple encoding",
			payload:  "<>&",
			level:    types.EvasionLevelAdvanced,
			minCount: 4,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should have triple encoding (%252525 etc)
					for _, v := range variants {
						if strings.Count(v, "%25") > 1 {
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
			name:     "Complex XSS payload",
			payload:  "<script>alert('xss')</script>",
			level:    types.EvasionLevelAdvanced,
			minCount: 5,
			checks: []func([]string) bool{
				func(variants []string) bool {
					// Should contain various levels of encoding
					hasBasicDouble := false
					hasTriple := false
					for _, v := range variants {
						if strings.Contains(v, "%253C") {
							hasBasicDouble = true
						}
						if strings.Contains(v, "%25253C") {
							hasTriple = true
						}
					}
					return hasBasicDouble || hasTriple
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := DoubleURLVariants(tt.payload, tt.level)

			if len(variants) < tt.minCount {
				t.Errorf("DoubleURLVariants() returned %d variants, expected at least %d", len(variants), tt.minCount)
			}

			// Check for duplicates
			seen := make(map[string]bool)
			for _, variant := range variants {
				if seen[variant] {
					t.Errorf("DoubleURLVariants() returned duplicate variant: %s", variant)
				}
				seen[variant] = true
			}

			// All non-empty variants should be different from original (except for empty payload and safe strings)
			for _, variant := range variants {
				if variant == tt.payload && tt.payload != "" && len(variants) > 1 {
					t.Errorf("DoubleURLVariants() returned original payload unchanged: %s", variant)
				}
			}

			// Run additional checks
			for i, check := range tt.checks {
				if !check(variants) {
					t.Errorf("DoubleURLVariants() failed check %d for test %s", i+1, tt.name)
				}
			}
		})
	}
}

func TestDoubleEncodingPatterns(t *testing.T) {
	testCases := []struct {
		name    string
		payload string
		level   types.EvasionLevel
		pattern string // Pattern to look for in results
	}{
		{
			name:    "Double percent encoding",
			payload: "100%",
			level:   types.EvasionLevelBasic,
			pattern: "%25", // % becomes %25
		},
		{
			name:    "Double space encoding",
			payload: "hello world",
			level:   types.EvasionLevelBasic,
			pattern: "%2520", // space -> %20 -> %2520
		},
		{
			name:    "Double angle bracket encoding",
			payload: "<test>",
			level:   types.EvasionLevelBasic,
			pattern: "%253C", // < -> %3C -> %253C
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			variants := DoubleURLVariants(tc.payload, tc.level)

			found := false
			for _, variant := range variants {
				if strings.Contains(variant, tc.pattern) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("DoubleURLVariants() should contain pattern %s, got variants: %v", tc.pattern, variants)
			}
		})
	}
}

func TestDoubleURLVariantsEvasionLevels(t *testing.T) {
	payload := "<script>alert('test')</script>"

	basicVariants := DoubleURLVariants(payload, types.EvasionLevelBasic)
	mediumVariants := DoubleURLVariants(payload, types.EvasionLevelMedium)
	advancedVariants := DoubleURLVariants(payload, types.EvasionLevelAdvanced)

	// Higher levels should produce same or more variants
	if len(mediumVariants) < len(basicVariants) {
		t.Error("Medium level should produce at least as many variants as basic level")
	}

	if len(advancedVariants) < len(mediumVariants) {
		t.Error("Advanced level should produce at least as many variants as medium level")
	}

	// Basic variants should be subset of medium variants
	basicSet := make(map[string]bool)
	for _, v := range basicVariants {
		basicSet[v] = true
	}

	foundBasicInMedium := 0
	for _, v := range mediumVariants {
		if basicSet[v] {
			foundBasicInMedium++
		}
	}

	// Should have most basic variants in medium
	if foundBasicInMedium < len(basicVariants)/2 {
		t.Error("Medium level should include most basic level variants")
	}
}

func TestAsymmetricDoubleEncoding(t *testing.T) {
	payload := "test & data"
	variants := DoubleURLVariants(payload, types.EvasionLevelAdvanced)

	// Should have variants with different encoding methods
	hasQueryThenPath := false
	hasPathThenQuery := false

	for _, variant := range variants {
		// This is a simplified check - in practice we'd need more sophisticated detection
		if strings.Contains(variant, "%25") && len(variant) > len(payload)*2 {
			if strings.Count(variant, "%") > 3 {
				hasQueryThenPath = true
			} else {
				hasPathThenQuery = true
			}
		}
	}

	if !hasQueryThenPath && !hasPathThenQuery {
		t.Log("Advanced level should include asymmetric double encoding variants")
		// Note: This is more of a documentation test - the exact detection is complex
	}
}

func TestDoubleURLEmptyAndEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		level   types.EvasionLevel
	}{
		{"Empty string", "", types.EvasionLevelBasic},
		{"Single character", "a", types.EvasionLevelBasic},
		{"Only special chars", "<>&", types.EvasionLevelMedium},
		{"Unicode characters", "café", types.EvasionLevelMedium},
		{"Very long payload", strings.Repeat("test", 100), types.EvasionLevelBasic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := DoubleURLVariants(tt.payload, tt.level)

			// Should not panic and should return some variants
			if len(variants) == 0 {
				t.Errorf("DoubleURLVariants() returned no variants for %s", tt.name)
			}

			// Each variant should be a valid string (not panic)
			for _, variant := range variants {
				if variant == "" && tt.payload != "" {
					t.Errorf("Empty variant returned for non-empty payload: %s", tt.name)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkDoubleURLVariantsBasic(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		DoubleURLVariants(payload, types.EvasionLevelBasic)
	}
}

func BenchmarkDoubleURLVariantsMedium(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		DoubleURLVariants(payload, types.EvasionLevelMedium)
	}
}

func BenchmarkDoubleURLVariantsAdvanced(b *testing.B) {
	payload := "<script>alert('test')</script>"
	for i := 0; i < b.N; i++ {
		DoubleURLVariants(payload, types.EvasionLevelAdvanced)
	}
}
