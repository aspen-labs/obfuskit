package cmd

import (
	"encoding/json"
	"fmt"
	"obfuskit/types"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from a file (supports YAML and JSON)
func LoadConfig(configPath string) (*types.Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := &types.Config{}
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
func ValidateConfig(config *types.Config) error {
	if config.Action == "" {
		return fmt.Errorf("action is required")
	}

	if config.Action != types.ActionUseExistingPayloads {
		if config.AttackType == "" {
			return fmt.Errorf("attack_type is required")
		}

		if config.Payload.Method == "" {
			config.Payload.Method = types.PayloadMethodAuto // default
		}

		if config.Payload.Method == types.PayloadMethodEncodings && config.Payload.Encoding == "" {
			return fmt.Errorf("payload.encoding is required when payload.method is 'Encodings'")
		}

		if config.Payload.Method == types.PayloadMethodFile && config.Payload.FilePath == "" {
			return fmt.Errorf("payload.file_path is required when payload.method is 'From File'")
		}

		if config.Payload.Method == types.PayloadMethodEnterManually && len(config.Payload.Custom) == 0 {
			return fmt.Errorf("payload.custom is required when payload.method is 'Enter Manually'")
		}
	} else {
		// For "Use Existing Payloads"
		if config.Payload.Source == "" {
			return fmt.Errorf("payload.source is required for 'Use Existing Payloads'")
		}

		if config.Payload.Source == types.PayloadSourceFromFile && config.Payload.FilePath == "" {
			return fmt.Errorf("payload.file_path is required when payload.source is 'From File'")
		}

		if config.Payload.Source == types.PayloadSourceEnterManually && len(config.Payload.Custom) == 0 {
			return fmt.Errorf("payload.custom is required when payload.source is 'Enter Manually'")
		}
	}

	if config.EvasionLevel == "" {
		config.EvasionLevel = types.EvasionLevelMedium // default
	}

	if config.Target.Method == "" {
		if config.Action == types.ActionSendToURL {
			config.Target.Method = types.TargetMethodURL
		} else {
			config.Target.Method = types.TargetMethodFile
		}
	}

	if config.Target.Method == types.TargetMethodURL && config.Target.URL == "" {
		return fmt.Errorf("target.url is required when target.method is 'URL'")
	}

	if config.ReportType == "" {
		config.ReportType = types.ReportTypeHTML // default
	}

	return nil
}

// ConvertConfigToModel converts a Config to a Model (for compatibility with existing code)
func ConvertConfigToModel(config *types.Config) Model {
	model := Model{
		SelectedAction:        config.Action,
		SelectedAttackType:    config.AttackType,
		SelectedPayloadMethod: config.Payload.Method,
		SelectedEncoding:      config.Payload.Encoding,
		SelectedEvasionLevel:  config.EvasionLevel,
		SelectedPayloadSource: config.Payload.Source,
		PayloadFilePath:       config.Payload.FilePath,
		CustomPayloads:        config.Payload.Custom,
		SelectedTargetMethod:  config.Target.Method,
		URL:                   config.Target.URL,
		SelectedReportType:    config.ReportType,
		current:               stateDone, // Mark as completed
	}

	// Set defaults for backward compatibility
	if model.SelectedPayloadMethod == "" {
		model.SelectedPayloadMethod = types.PayloadMethodAuto
	}
	if model.SelectedPayloadSource == "" && model.SelectedPayloadMethod != types.PayloadMethodAuto {
		model.SelectedPayloadSource = types.PayloadSourceGenerated
	}

	// Handle auto flags based on selections
	model.autoAttack = (model.SelectedAttackType != "")
	model.autoPayload = (model.SelectedPayloadMethod == types.PayloadMethodAuto)
	// Note: autoEvasionLevel and autoTarget are not fields in the Model struct

	return model
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig(format string) ([]byte, error) {
	exampleConfig := types.Config{
		Action:     types.ActionSendToURL,
		AttackType: types.AttackTypeXSS,
		Payload: types.Payload{
			Method:   types.PayloadMethodAuto,
			Encoding: "",
			Source:   types.PayloadSourceGenerated,
			FilePath: "",
			Custom:   []string{},
		},
		EvasionLevel: types.EvasionLevelMedium,
		Target: types.Target{
			Method: types.TargetMethodURL,
			URL:    "http://example.com/vulnerable-page",
		},
		ReportType: types.ReportTypeHTML,
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
