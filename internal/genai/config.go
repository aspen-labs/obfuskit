package genai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultConfigs provides sensible defaults for different AI providers
var DefaultConfigs = map[string]*Config{
	"openai": {
		Provider:            "openai",
		Model:               "gpt-4o-mini",
		MaxTokens:           1500,
		Temperature:         0.7,
		Timeout:             60 * time.Second,
		MaxRetries:          3,
		EnableCaching:       true,
		EnableAnalytics:     true,
		EnableQualityFilter: true,
	},
	"anthropic": {
		Provider:            "anthropic",
		Model:               "claude-3-sonnet-20240229",
		MaxTokens:           1500,
		Temperature:         0.7,
		Timeout:             60 * time.Second,
		MaxRetries:          3,
		EnableCaching:       true,
		EnableAnalytics:     true,
		EnableQualityFilter: true,
	},
	"local": {
		Provider:            "local",
		Model:               "codellama:7b-instruct",
		APIEndpoint:         "http://localhost:11434/api/generate",
		MaxTokens:           1000,
		Temperature:         0.8,
		Timeout:             120 * time.Second,
		MaxRetries:          2,
		EnableCaching:       false,
		EnableAnalytics:     true,
		EnableQualityFilter: true,
	},
	"huggingface": {
		Provider:            "huggingface",
		Model:               "microsoft/DialoGPT-large",
		MaxTokens:           1000,
		Temperature:         0.7,
		Timeout:             90 * time.Second,
		MaxRetries:          3,
		EnableCaching:       true,
		EnableAnalytics:     true,
		EnableQualityFilter: true,
	},
}

// LoadConfig loads GenAI configuration from file or environment
func LoadConfig(configPath string) (*Config, error) {
	// Try to load from file first
	if configPath != "" {
		return loadConfigFromFile(configPath)
	}

	// Try to load from environment variables
	if config := loadConfigFromEnv(); config != nil {
		return config, nil
	}

	// Check for provider-specific environment variables even without OBFUSKIT_AI_PROVIDER
	if config := loadConfigFromProviderSpecificEnv(); config != nil {
		return config, nil
	}

	// Return default OpenAI config
	return getDefaultConfig("openai"), nil
}

// loadConfigFromFile loads configuration from a JSON file
func loadConfigFromFile(path string) (*Config, error) {
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %v", err)
		}
		path = filepath.Join(cwd, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Apply defaults for missing fields
	config = *mergeWithDefaults(&config)

	return &config, nil
}

// loadConfigFromEnv loads configuration from environment variables
func loadConfigFromEnv() *Config {

	provider := os.Getenv("OBFUSKIT_AI_PROVIDER")

	// If no provider is set via environment, return nil
	// (provider will be set via CLI flags later)
	if provider == "" {
		return nil
	}

	config := getDefaultConfig(provider)

	// Override with environment variables
	if apiKey := os.Getenv("OBFUSKIT_AI_API_KEY"); apiKey != "" {
		config.APIKey = apiKey
	}

	if model := os.Getenv("OBFUSKIT_AI_MODEL"); model != "" {
		config.Model = model
	}

	if endpoint := os.Getenv("OBFUSKIT_AI_ENDPOINT"); endpoint != "" {
		config.APIEndpoint = endpoint
	}

	// Provider-specific environment variables
	switch provider {
	case "openai":
		if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
			config.APIKey = apiKey
		}
	case "anthropic":
		if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
			config.APIKey = apiKey
		}
	case "huggingface":
		if apiKey := os.Getenv("HUGGINGFACE_API_KEY"); apiKey != "" {
			config.APIKey = apiKey
		}
	}

	return config
}

// loadConfigFromProviderSpecificEnv loads configuration from provider-specific environment variables
// even when OBFUSKIT_AI_PROVIDER is not set
func loadConfigFromProviderSpecificEnv() *Config {
	// Check for OpenAI API key
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		config := getDefaultConfig("openai")
		config.APIKey = apiKey
		return config
	}

	// Check for Anthropic API key
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		config := getDefaultConfig("anthropic")
		config.APIKey = apiKey
		return config
	}

	// Check for HuggingFace API key
	if apiKey := os.Getenv("HUGGINGFACE_API_KEY"); apiKey != "" {
		config := getDefaultConfig("huggingface")
		config.APIKey = apiKey
		return config
	}

	// Check for local endpoint
	if endpoint := os.Getenv("OBFUSKIT_AI_ENDPOINT"); endpoint != "" {
		config := getDefaultConfig("local")
		config.APIEndpoint = endpoint
		return config
	}

	return nil
}

// getDefaultConfig returns a copy of the default configuration for a provider
func getDefaultConfig(provider string) *Config {
	if defaultConfig, exists := DefaultConfigs[provider]; exists {
		// Create a copy to avoid modifying the default
		config := *defaultConfig
		return &config
	}

	// Return a generic default
	return &Config{
		Provider:            provider,
		Model:               "unknown",
		MaxTokens:           1000,
		Temperature:         0.7,
		Timeout:             60 * time.Second,
		MaxRetries:          3,
		EnableCaching:       true,
		EnableAnalytics:     true,
		EnableQualityFilter: true,
	}
}

// mergeWithDefaults merges user config with provider defaults
func mergeWithDefaults(userConfig *Config) *Config {
	defaults := getDefaultConfig(userConfig.Provider)

	// Only override defaults if user values are not zero/empty
	if userConfig.Model == "" {
		userConfig.Model = defaults.Model
	}
	if userConfig.MaxTokens == 0 {
		userConfig.MaxTokens = defaults.MaxTokens
	}
	if userConfig.Temperature == 0 {
		userConfig.Temperature = defaults.Temperature
	}
	if userConfig.Timeout == 0 {
		userConfig.Timeout = defaults.Timeout
	}
	if userConfig.MaxRetries == 0 {
		userConfig.MaxRetries = defaults.MaxRetries
	}

	return userConfig
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// ValidateConfig validates the configuration
func ValidateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	if config.Model == "" {
		return fmt.Errorf("model is required")
	}

	// Provider-specific validation
	switch config.Provider {
	case "openai", "anthropic", "huggingface":
		if config.APIKey == "" {
			return fmt.Errorf("API key is required for provider %s", config.Provider)
		}
	case "local":
		if config.APIEndpoint == "" {
			return fmt.Errorf("API endpoint is required for local provider")
		}
	default:
		return fmt.Errorf("unsupported provider: %s", config.Provider)
	}

	if config.MaxTokens <= 0 {
		return fmt.Errorf("max_tokens must be positive")
	}

	if config.Temperature < 0 || config.Temperature > 2 {
		return fmt.Errorf("temperature must be between 0 and 2")
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	return nil
}

// GetAvailableProviders returns a list of supported AI providers
func GetAvailableProviders() []string {
	var providers []string
	for provider := range DefaultConfigs {
		providers = append(providers, provider)
	}
	return providers
}

// GetProviderModels returns recommended models for each provider
func GetProviderModels() map[string][]string {
	return map[string][]string{
		"openai": {
			"gpt-4-turbo-preview",
			"gpt-4",
			"gpt-3.5-turbo",
			"gpt-3.5-turbo-16k",
		},
		"anthropic": {
			"claude-3-opus-20240229",
			"claude-3-sonnet-20240229",
			"claude-3-haiku-20240307",
			"claude-2.1",
		},
		"local": {
			"codellama:7b-instruct",
			"codellama:13b-instruct",
			"llama2:7b-chat",
			"llama2:13b-chat",
			"mistral:7b-instruct",
			"wizardcoder:34b",
		},
		"huggingface": {
			"microsoft/DialoGPT-large",
			"microsoft/DialoGPT-medium",
			"facebook/blenderbot-400M-distill",
			"google/flan-t5-large",
		},
	}
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig(provider string) *Config {
	config := getDefaultConfig(provider)

	// Add example values
	switch provider {
	case "openai":
		config.APIKey = "sk-your-openai-api-key-here"
	case "anthropic":
		config.APIKey = "your-anthropic-api-key-here"
	case "huggingface":
		config.APIKey = "your-huggingface-api-key-here"
	case "local":
		config.APIEndpoint = "http://localhost:11434/api/generate"
		config.Model = "codellama:7b-instruct"
	}

	return config
}

// GetCostEstimate provides cost estimation for API providers
func GetCostEstimate(provider, model string, tokens int) float64 {
	// Rough cost estimates per 1000 tokens (as of 2024)
	costs := map[string]map[string]float64{
		"openai": {
			"gpt-4-turbo-preview": 0.03,
			"gpt-4":               0.06,
			"gpt-3.5-turbo":       0.002,
			"gpt-3.5-turbo-16k":   0.004,
		},
		"anthropic": {
			"claude-3-opus-20240229":   0.075,
			"claude-3-sonnet-20240229": 0.015,
			"claude-3-haiku-20240307":  0.0025,
		},
		"huggingface": {
			// Most HF models are free or very low cost
			"default": 0.001,
		},
		"local": {
			// Local models have no API cost
			"default": 0.0,
		},
	}

	if providerCosts, exists := costs[provider]; exists {
		if cost, exists := providerCosts[model]; exists {
			return cost * float64(tokens) / 1000.0
		}
		if cost, exists := providerCosts["default"]; exists {
			return cost * float64(tokens) / 1000.0
		}
	}

	return 0.0 // Unknown cost
}
