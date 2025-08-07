package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"obfuskit/types"

	"gopkg.in/yaml.v3"
)

func TestGenerateExampleConfig(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		wantErr    bool
		validateFn func([]byte) error
	}{
		{
			name:    "Generate YAML config",
			format:  "yaml",
			wantErr: false,
			validateFn: func(data []byte) error {
				var config types.Config
				return yaml.Unmarshal(data, &config)
			},
		},
		{
			name:    "Generate JSON config",
			format:  "json",
			wantErr: false,
			validateFn: func(data []byte) error {
				var config types.Config
				return json.Unmarshal(data, &config)
			},
		},
		{
			name:       "Invalid format",
			format:     "xml",
			wantErr:    true,
			validateFn: nil,
		},
		{
			name:       "Empty format",
			format:     "",
			wantErr:    true,
			validateFn: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := GenerateExampleConfig(tt.format)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateExampleConfig() should have returned an error")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateExampleConfig() unexpected error: %v", err)
				return
			}

			if len(data) == 0 {
				t.Error("GenerateExampleConfig() returned empty data")
				return
			}

			// Validate the generated config format
			if tt.validateFn != nil {
				if err := tt.validateFn(data); err != nil {
					t.Errorf("Generated config is invalid: %v", err)
				}
			}
		})
	}
}

func TestGenerateExampleConfigContent(t *testing.T) {
	// Test YAML config content
	yamlData, err := GenerateExampleConfig("yaml")
	if err != nil {
		t.Fatalf("Failed to generate YAML config: %v", err)
	}

	yamlContent := string(yamlData)
	expectedYAMLFields := []string{
		"action:",
		"attack_type:",
		"payload:",
		"evasion_level:",
		"target:",
		"report_type:",
	}

	for _, field := range expectedYAMLFields {
		if !strings.Contains(yamlContent, field) {
			t.Errorf("YAML config missing field: %s", field)
		}
	}

	// Test JSON config content
	jsonData, err := GenerateExampleConfig("json")
	if err != nil {
		t.Fatalf("Failed to generate JSON config: %v", err)
	}

	var config types.Config
	if err := json.Unmarshal(jsonData, &config); err != nil {
		t.Errorf("Generated JSON config is invalid: %v", err)
	}

	// Verify required fields are populated
	if config.Action == "" {
		t.Error("Generated config missing action")
	}
	if config.AttackType == "" {
		t.Error("Generated config missing attack_type")
	}
	if config.EvasionLevel == "" {
		t.Error("Generated config missing evasion_level")
	}
	if config.ReportType == "" {
		t.Error("Generated config missing report_type")
	}
}

func TestLoadConfig(t *testing.T) {
	// Test YAML config loading
	yamlConfig := `
action: "Generate Payloads"
attack_type: "xss"
payload:
  method: "Encodings"
  encoding: "Base64Variants"
  source: "Generated"
evasion_level: "Medium"
target:
  method: "URL"
  url: "https://example.com"
report_type: "HTML"
`

	yamlFile := createTempFile(t, "config-*.yaml", yamlConfig)
	defer os.Remove(yamlFile)

	config, err := LoadConfig(yamlFile)
	if err != nil {
		t.Errorf("LoadConfig() YAML error: %v", err)
	}

	if config.Action != "Generate Payloads" {
		t.Errorf("LoadConfig() action = %v, want Generate Payloads", config.Action)
	}
	if config.AttackType != "xss" {
		t.Errorf("LoadConfig() attack_type = %v, want xss", config.AttackType)
	}

	// Test JSON config loading
	jsonConfig := `{
		"action": "Send to URL",
		"attack_type": "sqli",
		"payload": {
			"method": "Auto",
			"source": "Generated"
		},
		"evasion_level": "Advanced",
		"target": {
			"method": "URL",
			"url": "https://test.com"
		},
		"report_type": "JSON"
	}`

	jsonFile := createTempFile(t, "config-*.json", jsonConfig)
	defer os.Remove(jsonFile)

	config2, err := LoadConfig(jsonFile)
	if err != nil {
		t.Errorf("LoadConfig() JSON error: %v", err)
	}

	if config2.Action != "Send to URL" {
		t.Errorf("LoadConfig() action = %v, want Send to URL", config2.Action)
	}
	if config2.AttackType != "sqli" {
		t.Errorf("LoadConfig() attack_type = %v, want sqli", config2.AttackType)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		wantErr  bool
	}{
		{
			name:     "Non-existent file",
			filename: "non-existent.yaml",
			wantErr:  true,
		},
		{
			name:     "Invalid YAML",
			filename: "invalid.yaml",
			content:  "invalid: yaml: content: [",
			wantErr:  true,
		},
		{
			name:     "Invalid JSON",
			filename: "invalid.json",
			content:  `{"invalid": json syntax}`,
			wantErr:  true,
		},
		{
			name:     "Unsupported extension",
			filename: "config.txt",
			content:  "some content",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filename string
			if tt.content != "" {
				filename = createTempFile(t, tt.filename, tt.content)
				defer os.Remove(filename)
			} else {
				filename = tt.filename
			}

			_, err := LoadConfig(filename)
			if tt.wantErr {
				if err == nil {
					t.Error("LoadConfig() should have returned an error")
				}
			} else {
				if err != nil {
					t.Errorf("LoadConfig() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.Config
		wantErr bool
	}{
		{
			name: "Valid config",
			config: &types.Config{
				Action:     "Generate Payloads",
				AttackType: "xss",
				Payload: types.Payload{
					Method:   "Encodings",
					Encoding: "Base64Variants",
					Source:   "Generated",
				},
				EvasionLevel: "Medium",
				Target: types.Target{
					Method: "URL",
					URL:    "https://example.com",
				},
				ReportType: "HTML",
			},
			wantErr: false,
		},
		{
			name: "Missing action",
			config: &types.Config{
				AttackType: "xss",
				Payload: types.Payload{
					Method: "Encodings",
					Source: "Generated",
				},
				EvasionLevel: "Medium",
				Target: types.Target{
					Method: "URL",
					URL:    "https://example.com",
				},
				ReportType: "HTML",
			},
			wantErr: true,
		},
		{
			name: "Invalid attack type",
			config: &types.Config{
				Action:     "Generate Payloads",
				AttackType: "invalid",
				Payload: types.Payload{
					Method: "Encodings",
					Source: "Generated",
				},
				EvasionLevel: "Medium",
				Target: types.Target{
					Method: "URL",
					URL:    "https://example.com",
				},
				ReportType: "HTML",
			},
			wantErr: true,
		},
		{
			name: "Invalid evasion level",
			config: &types.Config{
				Action:     "Generate Payloads",
				AttackType: "xss",
				Payload: types.Payload{
					Method: "Encodings",
					Source: "Generated",
				},
				EvasionLevel: "Invalid",
				Target: types.Target{
					Method: "URL",
					URL:    "https://example.com",
				},
				ReportType: "HTML",
			},
			wantErr: true,
		},
		{
			name: "Missing URL for URL target",
			config: &types.Config{
				Action:     "Send to URL",
				AttackType: "xss",
				Payload: types.Payload{
					Method: "Encodings",
					Source: "Generated",
				},
				EvasionLevel: "Medium",
				Target: types.Target{
					Method: "URL",
					URL:    "",
				},
				ReportType: "HTML",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("ValidateConfig() should have returned an error")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateConfig() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateConfigAttackTypes(t *testing.T) {
	validAttackTypes := []string{
		"xss", "sqli", "unixcmdi", "wincmdi", "oscmdi",
		"path", "fileaccess", "ldapi", "ssrf", "xxe", "generic", "all",
	}

	for _, attackType := range validAttackTypes {
		t.Run("Valid_"+attackType, func(t *testing.T) {
			config := &types.Config{
				Action:     "Generate Payloads",
				AttackType: types.AttackType(attackType),
				Payload: types.Payload{
					Method:   "Encodings",
					Encoding: "Base64Variants",
					Source:   "Generated",
				},
				EvasionLevel: "Medium",
				Target: types.Target{
					Method: "URL",
					URL:    "https://example.com",
				},
				ReportType: "HTML",
			}

			err := ValidateConfig(config)
			if err != nil {
				t.Errorf("ValidateConfig() should accept valid attack type %s, got error: %v", attackType, err)
			}
		})
	}
}

func TestValidateConfigEvasionLevels(t *testing.T) {
	validEvasionLevels := []string{"Basic", "Medium", "Advanced"}

	for _, level := range validEvasionLevels {
		t.Run("Valid_"+level, func(t *testing.T) {
			config := &types.Config{
				Action:     "Generate Payloads",
				AttackType: "xss",
				Payload: types.Payload{
					Method:   "Encodings",
					Encoding: "Base64Variants",
					Source:   "Generated",
				},
				EvasionLevel: types.EvasionLevel(level),
				Target: types.Target{
					Method: "URL",
					URL:    "https://example.com",
				},
				ReportType: "HTML",
			}

			err := ValidateConfig(config)
			if err != nil {
				t.Errorf("ValidateConfig() should accept valid evasion level %s, got error: %v", level, err)
			}
		})
	}
}

// Helper function to create temporary files for testing
func createTempFile(t *testing.T, pattern, content string) string {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}
