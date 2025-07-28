package main

import (
	"fmt"
	"sort"

	"obfuskit/internal/constants"
	"obfuskit/internal/evasions/command"
	"obfuskit/internal/evasions/encoders"
	"obfuskit/internal/evasions/path"
)

var EvasionFunctions = map[string]func(string, constants.Level) []string{
	"Base64Variants":  encoders.Base64Variants,
	"BestFitVariants": encoders.BestFitVariants,
	"HexVariants":     encoders.HexVariants,
	"HTMLVariants":    encoders.HTMLVariants,
	"OctalVariants":   encoders.OctalVariants,
	"UnicodeVariants": encoders.UnicodeVariants,

	"UnixCmdVariants":    command.UnixCmdVariants,
	"WindowsCmdVariants": command.WindowsCmdVariants,

	"PathTraversalVariants": path.PathTraversalVariants,
}

var PayloadEvasionMap = map[string][]string{
	"xss": {
		"HTMLVariants",
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
		// "XSSVariants",
	},
	"sqli": {
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
	},
	"unixcmdi": {
		"UnixCmdVariants",
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
		"PathTraversalVariants",
	},
	"wincmdi": {
		"WindowsCmdVariants",
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
		"PathTraversalVariants",
	},
	"path": {
		"PathTraversalVariants",
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
	},
	"fileaccess": {
		"PathTraversalVariants",
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
	},
	"ldapi": {
		"UnicodeVariants",
		"HexVariants",
		"OctalVariants",
		"Base64Variants",
		// "EscapingVariants",
		"BestFitVariants",
	},
}

var EvasionCategories = map[string]string{
	"HTMLVariants":    "encoder",
	"UnicodeVariants": "encoder",
	"HexVariants":     "encoder",
	"OctalVariants":   "encoder",
	"Base64Variants":  "encoder",
	// "EscapingVariants":      "encoder",
	"BestFitVariants":       "encoder",
	"UnixCmdVariants":       "command",
	"WindowsCmdVariants":    "command",
	"PathTraversalVariants": "path",
	// "XSSVariants":           "xss",
}

func GetEvasionsForPayload(payloadType string) ([]string, bool) {
	evasions, exists := PayloadEvasionMap[payloadType]
	return evasions, exists
}

func GetEvasionsByCategory(payloadType string) map[string][]string {
	evasions, exists := PayloadEvasionMap[payloadType]
	if !exists {
		return nil
	}

	categorized := make(map[string][]string)
	for _, evasion := range evasions {
		category := EvasionCategories[evasion]
		categorized[category] = append(categorized[category], evasion)
	}

	return categorized
}

func IsEvasionApplicable(payloadType, evasionType string) bool {
	evasions, exists := PayloadEvasionMap[payloadType]
	if !exists {
		return false
	}

	for _, evasion := range evasions {
		if evasion == evasionType {
			return true
		}
	}
	return false
}

func ApplyEvasion(payload, evasionType string, level constants.Level) ([]string, error) {
	if payload == "" {
		return nil, nil
	}

	evasionFunc, exists := EvasionFunctions[evasionType]
	if !exists {
		return nil, fmt.Errorf("evasion function %q not found", evasionType)
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in %s: %v\n", evasionType, r)
		}
	}()

	return evasionFunc(payload, level), nil
}

func ApplyEvasionsToPayload(payload, payloadType string, level constants.Level) map[string][]string {
	if payload == "" || payloadType == "" {
		return nil
	}

	evasions, exists := GetEvasionsForPayload(payloadType)
	if !exists {
		return nil
	}

	results := make(map[string][]string, len(evasions))
	for _, evasionType := range evasions {
		variants, err := ApplyEvasion(payload, evasionType, level)
		if err != nil {
			results[evasionType] = []string{fmt.Sprintf("Error: %v", err)}
			continue
		}
		if len(variants) > 0 {
			results[evasionType] = variants
		}
	}

	return results
}

func GetAllPayloadTypes() []string {
	types := make([]string, 0, len(PayloadEvasionMap))
	for payloadType := range PayloadEvasionMap {
		types = append(types, payloadType)
	}
	sort.Strings(types)
	return types
}

func PrintPayloadEvasionMap() {
	payloadTypes := GetAllPayloadTypes()

	fmt.Println("Payload to Evasions Mapping:")
	fmt.Println("============================")

	for _, payloadType := range payloadTypes {
		fmt.Printf("\n%s:\n", payloadType)
		categorized := GetEvasionsByCategory(payloadType)

		categories := make([]string, 0, len(categorized))
		for category := range categorized {
			categories = append(categories, category)
		}
		sort.Strings(categories)

		for _, category := range categories {
			evasions := categorized[category]
			sort.Strings(evasions)
			fmt.Printf("  %s:\n", category)
			for _, evasion := range evasions {
				fmt.Printf("    - %s\n", evasion)
			}
		}
	}
}

// Example function showing how to use the evasion mapping
func ExampleUsage() {
	fmt.Println("\nExample: Evasions for XSS payloads:")
	if evasions, exists := GetEvasionsForPayload("xss"); exists {
		for _, evasion := range evasions {
			fmt.Printf("- %s\n", evasion)
		}
	}

	fmt.Printf("\nIs Base64 encoding applicable to SQL injection? %t\n",
		IsEvasionApplicable("sqli", "Base64Variants"))

	exampleSqliPayload := "; 1 == 1"
	level := constants.Medium

	fmt.Printf("\nOriginal payload: %s\n", exampleSqliPayload)
	fmt.Printf("Applying evasions at level %s:\n", level)

	results := ApplyEvasionsToPayload(exampleSqliPayload, "sqli", level)
	for evasionType, variants := range results {
		fmt.Printf("- %s:\n", evasionType)
		for i, variant := range variants {
			fmt.Printf("  %d: %s\n", i+1, variant)
		}
	}

	testPayload := "<script>alert('xss')</script>"
	variants, err := ApplyEvasion(testPayload, "HTMLVariants", constants.Advanced)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("\nOriginal: %s\n", testPayload)
	fmt.Printf("HTML variants (level %s):\n", constants.Advanced)
	for i, variant := range variants {
		fmt.Printf("%d: %s\n", i+1, variant)
	}
}
