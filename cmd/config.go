package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the configuration structure for WAF testing
type Config struct {
	// Action specifies what to do: "Generate Payloads", "Send to URL", or "Use Existing Payloads"
	Action string `yaml:"action" json:"action"`

	// Attack configuration
	Attack struct {
		Type string `yaml:"type" json:"type"` // e.g., "xss", "sqli", "unixcmdi", etc.
	} `yaml:"attack" json:"attack"`

	// Payload configuration
	Payload struct {
		Method   string   `yaml:"method" json:"method"`     // "Auto", "Encodings", "From File", "Enter Manually"
		Encoding string   `yaml:"encoding" json:"encoding"` // specific encoding when method is "Encodings"
		Source   string   `yaml:"source" json:"source"`     // "Auto", "From File", "Enter Manually"
		FilePath string   `yaml:"file_path" json:"file_path"`
		Custom   []string `yaml:"custom" json:"custom"` // custom payloads when source is "Enter Manually"
	} `yaml:"payload" json:"payload"`

	// Evasion configuration
	Evasion struct {
		Level string `yaml:"level" json:"level"` // "Basic", "Medium", "Advanced"
	} `yaml:"evasion" json:"evasion"`

	// Target configuration
	Target struct {
		Method string `yaml:"method" json:"method"` // "URL" or "File"
		URL    string `yaml:"url" json:"url"`
	} `yaml:"target" json:"target"`

	// Report configuration
	Report struct {
		Type string `yaml:"type" json:"type"` // "HTML", "Pretty Terminal", "PDF", "CSV", "Nuclei Templates"
		Auto bool   `yaml:"auto" json:"auto"` // whether to auto-generate reports
	} `yaml:"report" json:"report"`
}

// LoadConfig loads configuration from a file (supports YAML and JSON)
func LoadConfig(configPath string) (*Config, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := &Config{}
	ext := strings.ToLower(filepath.Ext(configPath))

	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, config)
	case ".json":
		err = json.Unmarshal(data, config)
	default:
		return nil, fmt.Errorf("unsupported config file format: %s (supported: .yaml, .yml, .json)", ext)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// ValidateConfig validates the configuration
func ValidateConfig(config *Config) error {
	if config.Action == "" {
		return fmt.Errorf("action is required")
	}

	validActions := []string{"Generate Payloads", "Send to URL", "Use Existing Payloads"}
	if !contains(validActions, config.Action) {
		return fmt.Errorf("invalid action: %s (valid: %s)", config.Action, strings.Join(validActions, ", "))
	}

	if config.Action != "Use Existing Payloads" {
		if config.Attack.Type == "" {
			return fmt.Errorf("attack.type is required")
		}

		validAttacks := []string{"xss", "sqli", "unixcmdi", "wincmdi", "path", "fileaccess", "ldapi", "generic"}
		if !contains(validAttacks, config.Attack.Type) {
			return fmt.Errorf("invalid attack.type: %s (valid: %s)", config.Attack.Type, strings.Join(validAttacks, ", "))
		}

		if config.Payload.Method == "" {
			config.Payload.Method = "Auto" // default
		}

		validPayloadMethods := []string{"Auto", "Encodings", "From File", "Enter Manually"}
		if !contains(validPayloadMethods, config.Payload.Method) {
			return fmt.Errorf("invalid payload.method: %s (valid: %s)", config.Payload.Method, strings.Join(validPayloadMethods, ", "))
		}

		if config.Payload.Method == "Encodings" && config.Payload.Encoding == "" {
			return fmt.Errorf("payload.encoding is required when payload.method is 'Encodings'")
		}

		if config.Payload.Method == "From File" && config.Payload.FilePath == "" {
			return fmt.Errorf("payload.file_path is required when payload.method is 'From File'")
		}

		if config.Payload.Method == "Enter Manually" && len(config.Payload.Custom) == 0 {
			return fmt.Errorf("payload.custom is required when payload.method is 'Enter Manually'")
		}
	} else {
		// For "Use Existing Payloads"
		if config.Payload.Source == "" {
			return fmt.Errorf("payload.source is required for 'Use Existing Payloads'")
		}

		validSources := []string{"From File", "Enter Manually"}
		if !contains(validSources, config.Payload.Source) {
			return fmt.Errorf("invalid payload.source: %s (valid: %s)", config.Payload.Source, strings.Join(validSources, ", "))
		}

		if config.Payload.Source == "From File" && config.Payload.FilePath == "" {
			return fmt.Errorf("payload.file_path is required when payload.source is 'From File'")
		}

		if config.Payload.Source == "Enter Manually" && len(config.Payload.Custom) == 0 {
			return fmt.Errorf("payload.custom is required when payload.source is 'Enter Manually'")
		}
	}

	if config.Evasion.Level == "" {
		config.Evasion.Level = "Medium" // default
	}

	validLevels := []string{"Basic", "Medium", "Advanced"}
	if !contains(validLevels, config.Evasion.Level) {
		return fmt.Errorf("invalid evasion.level: %s (valid: %s)", config.Evasion.Level, strings.Join(validLevels, ", "))
	}

	if config.Target.Method == "" {
		if config.Action == "Send to URL" {
			config.Target.Method = "URL"
		} else {
			config.Target.Method = "File"
		}
	}

	validTargetMethods := []string{"URL", "File", "Response"}
	if !contains(validTargetMethods, config.Target.Method) {
		return fmt.Errorf("invalid target.method: %s (valid: %s)", config.Target.Method, strings.Join(validTargetMethods, ", "))
	}

	if config.Target.Method == "URL" && config.Target.URL == "" {
		return fmt.Errorf("target.url is required when target.method is 'URL'")
	}

	if config.Report.Type == "" {
		config.Report.Type = "HTML" // default
	}

	validReportTypes := []string{"HTML", "Pretty Terminal", "PDF", "CSV", "Nuclei Templates"}
	if !contains(validReportTypes, config.Report.Type) {
		return fmt.Errorf("invalid report.type: %s (valid: %s)", config.Report.Type, strings.Join(validReportTypes, ", "))
	}

	return nil
}

// ConvertConfigToModel converts a Config to a Model (for compatibility with existing code)
func ConvertConfigToModel(config *Config) Model {
	model := Model{
		Selection:             config.Action,
		SelectedAttack:        config.Attack.Type,
		SelectedPayload:       config.Payload.Method,
		SelectedEncoding:      config.Payload.Encoding,
		SelectedEvasionLevel:  config.Evasion.Level,
		SelectedPayloadSource: config.Payload.Source,
		PayloadFilePath:       config.Payload.FilePath,
		CustomPayloads:        config.Payload.Custom,
		SelectedTarget:        config.Target.Method,
		URL:                   config.Target.URL,
		SelectedReportType:    config.Report.Type,
		autoReport:            config.Report.Auto,
		current:               stateDone, // Mark as completed
	}

	// Set defaults for backward compatibility
	if model.SelectedPayload == "" {
		model.SelectedPayload = "Auto"
	}
	if model.SelectedPayloadSource == "" && model.SelectedPayload != "Auto" {
		model.SelectedPayloadSource = "Auto"
	}

	// Handle auto flags based on selections
	model.autoAttack = (model.SelectedAttack != "")
	model.autoPayload = (model.SelectedPayload == "Auto")
	// Note: autoEvasionLevel and autoTarget are not fields in the Model struct

	return model
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig(format string) ([]byte, error) {
	exampleConfig := Config{
		Action: "Send to URL",
		Attack: struct {
			Type string `yaml:"type" json:"type"`
		}{
			Type: "xss",
		},
		Payload: struct {
			Method   string   `yaml:"method" json:"method"`
			Encoding string   `yaml:"encoding" json:"encoding"`
			Source   string   `yaml:"source" json:"source"`
			FilePath string   `yaml:"file_path" json:"file_path"`
			Custom   []string `yaml:"custom" json:"custom"`
		}{
			Method: "Auto",
			Source: "Auto",
		},
		Evasion: struct {
			Level string `yaml:"level" json:"level"`
		}{
			Level: "Medium",
		},
		Target: struct {
			Method string `yaml:"method" json:"method"`
			URL    string `yaml:"url" json:"url"`
		}{
			Method: "URL",
			URL:    "http://example.com/vulnerable-page",
		},
		Report: struct {
			Type string `yaml:"type" json:"type"`
			Auto bool   `yaml:"auto" json:"auto"`
		}{
			Type: "HTML",
			Auto: true,
		},
	}

	switch strings.ToLower(format) {
	case "yaml", "yml":
		return yaml.Marshal(&exampleConfig)
	case "json":
		return json.MarshalIndent(&exampleConfig, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format: %s (supported: yaml, json)", format)
	}
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
