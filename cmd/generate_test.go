package cmd

import (
	"strings"
	"testing"
)

func TestGetInteractiveCmd(t *testing.T) {
	cmd := GetInteractiveCmd()

	if cmd == nil {
		t.Fatal("GetInteractiveCmd() returned nil")
	}

	if cmd.Use != "interactive" {
		t.Errorf("GetInteractiveCmd().Use = %v, want interactive", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("GetInteractiveCmd().Short should not be empty")
	}

	if cmd.Long == "" {
		t.Error("GetInteractiveCmd().Long should not be empty")
	}

	if cmd.Run == nil {
		t.Error("GetInteractiveCmd().Run should not be nil")
	}
}

func TestInteractiveCmdProperties(t *testing.T) {
	cmd := GetInteractiveCmd()

	// Test command properties
	expectedUse := "interactive"
	if cmd.Use != expectedUse {
		t.Errorf("Command Use = %v, want %v", cmd.Use, expectedUse)
	}

	// Test that description contains expected keywords
	expectedKeywords := []string{
		"interactive",
		"terminal",
		"UI",
		"menu",
		"payload",
		"generation",
	}

	for _, keyword := range expectedKeywords {
		if !containsIgnoreCase(cmd.Short, keyword) && !containsIgnoreCase(cmd.Long, keyword) {
			t.Errorf("Command description should contain keyword: %s", keyword)
		}
	}
}

func TestInteractiveCmdValidation(t *testing.T) {
	cmd := GetInteractiveCmd()

	// Verify the command has proper structure
	tests := []struct {
		name    string
		field   string
		value   interface{}
		checkFn func(interface{}) bool
	}{
		{
			name:  "Use field not empty",
			field: "Use",
			value: cmd.Use,
			checkFn: func(v interface{}) bool {
				return v.(string) != ""
			},
		},
		{
			name:  "Short description not empty",
			field: "Short",
			value: cmd.Short,
			checkFn: func(v interface{}) bool {
				return v.(string) != ""
			},
		},
		{
			name:  "Long description not empty",
			field: "Long",
			value: cmd.Long,
			checkFn: func(v interface{}) bool {
				return v.(string) != ""
			},
		},
		{
			name:  "Run function not nil",
			field: "Run",
			value: cmd.Run,
			checkFn: func(v interface{}) bool {
				return v != nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.checkFn(tt.value) {
				t.Errorf("Interactive command %s validation failed", tt.field)
			}
		})
	}
}

func TestInteractiveCmdDocumentation(t *testing.T) {
	cmd := GetInteractiveCmd()

	// Test that documentation is comprehensive
	shortDesc := cmd.Short
	longDesc := cmd.Long

	// Short description should be concise but descriptive
	if len(shortDesc) < 20 {
		t.Error("Short description should be at least 20 characters")
	}

	if len(shortDesc) > 100 {
		t.Error("Short description should be under 100 characters")
	}

	// Long description should be more detailed
	if len(longDesc) < 50 {
		t.Error("Long description should be at least 50 characters")
	}

	// Check for specific documentation elements
	requiredElements := []string{
		"interactive",
		"terminal",
		"payload",
		"attack",
		"evasion",
		"report",
	}

	combinedDesc := shortDesc + " " + longDesc
	for _, element := range requiredElements {
		if !containsIgnoreCase(combinedDesc, element) {
			t.Errorf("Command documentation should mention: %s", element)
		}
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func TestInteractiveCmdIntegration(t *testing.T) {
	// Test that the command integrates properly with the cobra framework
	cmd := GetInteractiveCmd()

	// Verify command can be executed (structure-wise)
	if cmd.Use == "" {
		t.Error("Command Use should not be empty")
	}

	// Verify command has appropriate help
	if cmd.Short == "" {
		t.Error("Command should have short help text")
	}

	if cmd.Long == "" {
		t.Error("Command should have long help text")
	}

	// Verify command has a run function
	if cmd.Run == nil {
		t.Error("Command should have a run function")
	}
}

func TestInteractiveCmdUsage(t *testing.T) {
	cmd := GetInteractiveCmd()

	// Test that the usage string is properly formatted
	if cmd.Use != "interactive" {
		t.Errorf("Expected use to be 'interactive', got: %s", cmd.Use)
	}

	// Verify the command doesn't have conflicting settings
	if cmd.Args != nil {
		// If Args is set, make sure it makes sense for an interactive command
		t.Log("Command has Args validation set")
	}

	// Interactive commands typically don't require additional arguments
	// This is just a structural test
}

// Mock test for the command execution (since we can't easily test the actual interactive flow)
func TestInteractiveCmdStructure(t *testing.T) {
	cmd := GetInteractiveCmd()

	// Basic structural validation
	if cmd == nil {
		t.Fatal("GetInteractiveCmd() should not return nil")
	}

	// Verify command metadata
	metadata := map[string]interface{}{
		"Use":   cmd.Use,
		"Short": cmd.Short,
		"Long":  cmd.Long,
		"Run":   cmd.Run,
	}

	for field, value := range metadata {
		if field == "Run" {
			if value == nil {
				t.Errorf("Command field %s should not be nil", field)
			}
		} else {
			if strVal, ok := value.(string); ok && strVal == "" {
				t.Errorf("Command field %s should not be empty", field)
			}
		}
	}
}

func TestInteractiveCmdErrorHandling(t *testing.T) {
	// Test that the interactive command function doesn't panic when called
	cmd := GetInteractiveCmd()

	if cmd.Run == nil {
		t.Fatal("Command Run function is nil")
	}

	// We can't easily test the actual execution without mocking the entire interactive system
	// But we can verify the function exists and is callable
	t.Log("Interactive command structure is valid")
}
