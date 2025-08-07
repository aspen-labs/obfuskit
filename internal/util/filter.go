package util

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"obfuskit/internal/model"
	"obfuskit/request"
)

// FilterOptions represents advanced filtering configuration
type FilterOptions struct {
	Limit             int           // Maximum number of payloads to process
	MinSuccessRate    float64       // Minimum success rate (0.0-1.0)
	Complexity        string        // Complexity filter: simple, medium, complex
	MaxResponseTime   time.Duration // Maximum allowed response time
	FilterStatusCodes []int         // Only include specific status codes
	ExcludeEncodings  []string      // Exclude specific encoding types
	OnlySuccessful    bool          // Only include successful bypasses
}

// PayloadComplexity estimates the complexity of a payload
type PayloadComplexity int

const (
	ComplexitySimple PayloadComplexity = iota
	ComplexityMedium
	ComplexityComplex
)

// CreateFilterOptions creates FilterOptions from CLI flags
func CreateFilterOptions(limit int, minSuccessRate float64, complexity string,
	maxResponseTime time.Duration, statusCodes, excludeEncodings string, onlySuccessful bool) *FilterOptions {

	filter := &FilterOptions{
		Limit:           limit,
		MinSuccessRate:  minSuccessRate,
		Complexity:      strings.ToLower(complexity),
		MaxResponseTime: maxResponseTime,
		OnlySuccessful:  onlySuccessful,
	}

	// Parse status codes
	if statusCodes != "" {
		codes := strings.Split(statusCodes, ",")
		for _, code := range codes {
			if c, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
				filter.FilterStatusCodes = append(filter.FilterStatusCodes, c)
			}
		}
	}

	// Parse exclude encodings
	if excludeEncodings != "" {
		encodings := strings.Split(excludeEncodings, ",")
		for _, encoding := range encodings {
			filter.ExcludeEncodings = append(filter.ExcludeEncodings, strings.TrimSpace(encoding))
		}
	}

	return filter
}

// FilterPayloadResults filters payload results based on criteria
func FilterPayloadResults(results []model.PayloadResults, filter *FilterOptions) []model.PayloadResults {
	if filter == nil {
		return results
	}

	var filtered []model.PayloadResults
	count := 0

	for _, result := range results {
		// Check limit
		if filter.Limit > 0 && count >= filter.Limit {
			break
		}

		// Check excluded encodings
		if filter.shouldExcludeEncoding(result.EvasionType) {
			continue
		}

		// Check complexity
		if filter.Complexity != "" && !filter.matchesComplexity(result.OriginalPayload) {
			continue
		}

		// Apply filters and add to results
		filteredVariants := filter.filterVariants(result.Variants, result.OriginalPayload)
		if len(filteredVariants) > 0 {
			filteredResult := result
			filteredResult.Variants = filteredVariants
			filtered = append(filtered, filteredResult)
			count++
		}
	}

	return filtered
}

// FilterRequestResults filters request results based on response criteria
func FilterRequestResults(results []request.TestResult, filter *FilterOptions) []request.TestResult {
	if filter == nil {
		return results
	}

	var filtered []request.TestResult

	for _, result := range results {
		// Check only successful
		if filter.OnlySuccessful && result.Blocked {
			continue
		}

		// Check response time
		if filter.MaxResponseTime > 0 && result.ResponseTime > filter.MaxResponseTime {
			continue
		}

		// Check status codes
		if len(filter.FilterStatusCodes) > 0 && !filter.containsStatusCode(result.StatusCode) {
			continue
		}

		filtered = append(filtered, result)
	}

	// Apply success rate filter if specified
	if filter.MinSuccessRate > 0.0 {
		successRate := CalculateSuccessRate(filtered)
		if successRate < filter.MinSuccessRate {
			// If success rate is too low, return empty results
			return []request.TestResult{}
		}
	}

	return filtered
}

// shouldExcludeEncoding checks if an encoding should be excluded
func (f *FilterOptions) shouldExcludeEncoding(encodingType string) bool {
	for _, excluded := range f.ExcludeEncodings {
		if strings.Contains(strings.ToLower(encodingType), strings.ToLower(excluded)) {
			return true
		}
	}
	return false
}

// matchesComplexity checks if payload matches complexity criteria
func (f *FilterOptions) matchesComplexity(payload string) bool {
	complexity := EstimatePayloadComplexity(payload)

	switch f.Complexity {
	case "simple":
		return complexity == ComplexitySimple
	case "medium":
		return complexity == ComplexityMedium
	case "complex":
		return complexity == ComplexityComplex
	default:
		return true
	}
}

// filterVariants filters payload variants based on criteria
func (f *FilterOptions) filterVariants(variants []string, originalPayload string) []string {
	var filtered []string

	for _, variant := range variants {
		// Apply complexity filter to variants as well
		if f.Complexity != "" {
			variantComplexity := EstimatePayloadComplexity(variant)
			expectedComplexity := f.getExpectedComplexity()
			if variantComplexity != expectedComplexity {
				continue
			}
		}

		filtered = append(filtered, variant)

		// Apply limit to variants if needed
		if f.Limit > 0 && len(filtered) >= f.Limit {
			break
		}
	}

	return filtered
}

// containsStatusCode checks if status code is in filter list
func (f *FilterOptions) containsStatusCode(statusCode int) bool {
	for _, code := range f.FilterStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

// getExpectedComplexity converts string complexity to enum
func (f *FilterOptions) getExpectedComplexity() PayloadComplexity {
	switch f.Complexity {
	case "simple":
		return ComplexitySimple
	case "medium":
		return ComplexityMedium
	case "complex":
		return ComplexityComplex
	default:
		return ComplexityMedium
	}
}

// EstimatePayloadComplexity estimates the complexity of a payload
func EstimatePayloadComplexity(payload string) PayloadComplexity {
	// Simple heuristics for complexity estimation
	complexityScore := 0

	// Length factor
	if len(payload) > 100 {
		complexityScore += 2
	} else if len(payload) > 50 {
		complexityScore += 1
	}

	// Special characters
	specialChars := []string{"<", ">", "(", ")", "{", "}", "[", "]", "&", "%", "\\", "'", "\""}
	for _, char := range specialChars {
		if strings.Contains(payload, char) {
			complexityScore++
		}
	}

	// Encoding patterns
	encodingPatterns := []string{"%", "&#", "\\u", "\\x", "+", "="}
	for _, pattern := range encodingPatterns {
		if strings.Contains(payload, pattern) {
			complexityScore++
		}
	}

	// SQL/XSS specific patterns
	advancedPatterns := []string{"UNION", "SELECT", "javascript:", "eval(", "setTimeout", "String.fromCharCode"}
	for _, pattern := range advancedPatterns {
		if strings.Contains(strings.ToUpper(payload), strings.ToUpper(pattern)) {
			complexityScore += 2
		}
	}

	// Determine complexity level
	if complexityScore <= 3 {
		return ComplexitySimple
	} else if complexityScore <= 7 {
		return ComplexityMedium
	} else {
		return ComplexityComplex
	}
}

// CalculateSuccessRate calculates the success rate from test results
func CalculateSuccessRate(results []request.TestResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	successful := 0
	for _, result := range results {
		if !result.Blocked {
			successful++
		}
	}

	return float64(successful) / float64(len(results))
}

// PrintFilterSummary prints a summary of applied filters
func PrintFilterSummary(filter *FilterOptions, originalCount, filteredCount int) {
	if filter == nil {
		return
	}

	fmt.Printf("\n🔍 Filter Summary:\n")
	fmt.Printf("  Original payloads: %d\n", originalCount)
	fmt.Printf("  Filtered payloads: %d\n", filteredCount)

	if filter.Limit > 0 {
		fmt.Printf("  Limit applied: %d\n", filter.Limit)
	}

	if filter.Complexity != "" {
		fmt.Printf("  Complexity filter: %s\n", filter.Complexity)
	}

	if len(filter.ExcludeEncodings) > 0 {
		fmt.Printf("  Excluded encodings: %s\n", strings.Join(filter.ExcludeEncodings, ", "))
	}

	if filter.OnlySuccessful {
		fmt.Printf("  Only successful bypasses: enabled\n")
	}

	if filter.MaxResponseTime > 0 {
		fmt.Printf("  Max response time: %s\n", filter.MaxResponseTime)
	}

	if len(filter.FilterStatusCodes) > 0 {
		codes := make([]string, len(filter.FilterStatusCodes))
		for i, code := range filter.FilterStatusCodes {
			codes[i] = strconv.Itoa(code)
		}
		fmt.Printf("  Status code filter: %s\n", strings.Join(codes, ", "))
	}

	fmt.Printf("  Reduction: %.1f%%\n", float64(originalCount-filteredCount)/float64(originalCount)*100)
}
