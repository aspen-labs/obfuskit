package validation

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"obfuskit/types"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func (e ValidationError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %s (hint: %s)", e.Field, e.Message, e.Hint)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult contains all validation errors and warnings
type ValidationResult struct {
	Errors   []ValidationError `json:"errors"`
	Warnings []ValidationError `json:"warnings"`
	Valid    bool              `json:"valid"`
}

// AddError adds a validation error
func (vr *ValidationResult) AddError(field, value, message, hint string) {
	vr.Errors = append(vr.Errors, ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
		Hint:    hint,
	})
	vr.Valid = false
}

// AddWarning adds a validation warning
func (vr *ValidationResult) AddWarning(field, value, message, hint string) {
	vr.Warnings = append(vr.Warnings, ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
		Hint:    hint,
	})
}

// HasErrors returns true if there are validation errors
func (vr *ValidationResult) HasErrors() bool {
	return len(vr.Errors) > 0
}

// HasWarnings returns true if there are validation warnings
func (vr *ValidationResult) HasWarnings() bool {
	return len(vr.Warnings) > 0
}

// ValidateConfig performs comprehensive configuration validation
func ValidateConfig(config *types.Config) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Validate Action
	validateAction(config, result)

	// Validate Attack Type
	validateAttackType(config, result)

	// Validate Evasion Level
	validateEvasionLevel(config, result)

	// Validate Payload Configuration
	validatePayload(config, result)

	// Validate Target Configuration
	validateTarget(config, result)

	// Validate URL Configuration
	validateURL(config, result)

	// Validate Report Configuration
	validateReport(config, result)

	// Server and Threads are handled by CLI flags, not config file

	// Cross-field validation
	validateCrossFieldRules(config, result)

	return result
}

func validateAction(config *types.Config, result *ValidationResult) {
	validActions := []types.Action{
		types.ActionGeneratePayloads,
		types.ActionSendToURL,
		types.ActionUseExistingPayloads,
	}

	valid := false
	for _, action := range validActions {
		if config.Action == action {
			valid = true
			break
		}
	}

	if !valid {
		result.AddError("action", string(config.Action),
			"Invalid action type",
			"Valid actions: generate_payloads, send_to_url, send_existing_payloads")
	}
}

func validateAttackType(config *types.Config, result *ValidationResult) {
	validTypes := []types.AttackType{
		types.AttackTypeXSS,
		types.AttackTypeSQLI,
		types.AttackTypeUnixCMDI,
		types.AttackTypeWinCMDI,
		types.AttackTypePath,
		types.AttackTypeFileAccess,
		types.AttackTypeLDAP,
		types.AttackTypeSSRF,
		types.AttackTypeXXE,
		types.AttackTypeGeneric,
		types.AttackTypeAll,
	}

	valid := false
	for _, attackType := range validTypes {
		if config.AttackType == attackType {
			valid = true
			break
		}
	}

	if !valid {
		result.AddError("attack_type", string(config.AttackType),
			"Invalid attack type",
			"Valid types: xss, sqli, unixcmdi, wincmdi, path, fileaccess, ldapi, ssrf, xxe, generic, all")
	}
}

func validateEvasionLevel(config *types.Config, result *ValidationResult) {
	validLevels := []types.EvasionLevel{
		types.EvasionLevelBasic,
		types.EvasionLevelMedium,
		types.EvasionLevelAdvanced,
	}

	valid := false
	for _, level := range validLevels {
		if config.EvasionLevel == level {
			valid = true
			break
		}
	}

	if !valid {
		result.AddError("evasion_level", string(config.EvasionLevel),
			"Invalid evasion level",
			"Valid levels: basic, medium, advanced")
	}
}

func validatePayload(config *types.Config, result *ValidationResult) {
	// Validate payload source
	validSources := []types.PayloadSource{
		types.PayloadSourceGenerated,
		types.PayloadSourceFromFile,
		types.PayloadSourceEnterManually,
	}
	sourceValid := false
	for _, source := range validSources {
		if config.Payload.Source == source {
			sourceValid = true
			break
		}
	}

	if !sourceValid {
		result.AddError("payload.source", string(config.Payload.Source),
			"Invalid payload source",
			"Valid sources: Generated, From File, Enter Manually")
	}

	// Validate file path if source is "From File"
	if config.Payload.Source == types.PayloadSourceFromFile {
		if config.Payload.FilePath == "" {
			result.AddError("payload.file_path", "",
				"File path is required when source is 'From File'",
				"Provide a valid path to a payload file")
		} else if !fileExists(config.Payload.FilePath) {
			result.AddError("payload.file_path", config.Payload.FilePath,
				"Payload file does not exist",
				"Ensure the file path is correct and accessible")
		}
	}

	// Validate custom payloads if source is "Enter Manually"
	if config.Payload.Source == types.PayloadSourceEnterManually {
		if len(config.Payload.Custom) == 0 {
			result.AddError("payload.custom", "",
				"Custom payloads are required when source is 'Enter Manually'",
				"Provide at least one custom payload")
		}
	}

	// Validate payload method for generated payloads
	if config.Payload.Source == types.PayloadSourceGenerated {
		validMethods := []types.PayloadMethod{
			types.PayloadMethodAuto,
			types.PayloadMethodEncodings,
			types.PayloadMethodPaths,
			types.PayloadMethodCommands,
		}
		methodValid := false
		for _, method := range validMethods {
			if config.Payload.Method == method {
				methodValid = true
				break
			}
		}

		if !methodValid {
			result.AddError("payload.method", string(config.Payload.Method),
				"Invalid payload method",
				"Valid methods: auto, encodings, paths, commands")
		}
	}
}

func validateTarget(config *types.Config, result *ValidationResult) {
	validTargetMethods := []types.TargetMethod{
		types.TargetMethodFile,
		types.TargetMethodURL,
	}

	valid := false
	for _, targetMethod := range validTargetMethods {
		if config.Target.Method == targetMethod {
			valid = true
			break
		}
	}

	if !valid {
		result.AddError("target.method", string(config.Target.Method),
			"Invalid target method",
			"Valid target methods: File, URL")
	}
}

func validateURL(config *types.Config, result *ValidationResult) {
	// Skip validation if no URL is provided
	if config.Target.URL == "" {
		return
	}

	// Validate URL format
	parsedURL, err := url.Parse(config.Target.URL)
	if err != nil {
		result.AddError("target.url", config.Target.URL,
			"Invalid URL format",
			"Ensure URL is properly formatted (e.g., https://example.com)")
		return
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		result.AddError("target.url", config.Target.URL,
			"Invalid URL scheme",
			"URL must use http or https protocol")
	}

	// Validate host
	if parsedURL.Host == "" {
		result.AddError("target.url", config.Target.URL,
			"URL must include a host",
			"Provide a complete URL with hostname (e.g., https://example.com)")
	}

	// Warning for non-HTTPS URLs
	if parsedURL.Scheme == "http" {
		result.AddWarning("target.url", config.Target.URL,
			"Using HTTP instead of HTTPS",
			"Consider using HTTPS for secure testing")
	}

	// Warning for localhost/127.0.0.1
	if strings.Contains(parsedURL.Host, "localhost") || strings.Contains(parsedURL.Host, "127.0.0.1") {
		result.AddWarning("target.url", config.Target.URL,
			"Using localhost for testing",
			"Ensure your test target is running and accessible")
	}
}

func validateReport(config *types.Config, result *ValidationResult) {
	validReportTypes := []types.ReportType{
		types.ReportTypePretty,
		types.ReportTypeHTML,
		types.ReportTypePDF,
		types.ReportTypeCSV,
		types.ReportTypeNuclei,
		types.ReportTypeJSON,
	}

	valid := false
	for _, reportType := range validReportTypes {
		if config.ReportType == reportType {
			valid = true
			break
		}
	}

	if !valid {
		result.AddError("report_type", string(config.ReportType),
			"Invalid report type",
			"Valid types: pretty, html, pdf, csv, nuclei, json")
	}
}

func validateCrossFieldRules(config *types.Config, result *ValidationResult) {
	// Rule: If action is send_to_url, URL must be provided
	if config.Action == types.ActionSendToURL && config.Target.URL == "" {
		result.AddError("target.url", "",
			"URL is required when action is 'send_to_url'",
			"Provide a target URL for testing")
	}

	// Rule: If action is send_existing_payloads, payload file must exist
	if config.Action == types.ActionUseExistingPayloads {
		if config.Payload.Source != types.PayloadSourceFromFile || config.Payload.FilePath == "" {
			result.AddError("payload.file_path", "",
				"Payload file is required when action is 'send_existing_payloads'",
				"Set payload source to 'From File' and provide a file path")
		}
	}

	// Rule: Multiple attack types validation
	if len(config.AdditionalAttackTypes) > 0 {
		if config.AttackType == types.AttackTypeGeneric || config.AttackType == types.AttackTypeAll {
			result.AddWarning("attack_type", string(config.AttackType),
				"Using generic/all attack type with additional specific types",
				"Consider using only specific attack types for better performance")
		}
	}
}

// Helper functions
func fileExists(path string) bool {
	if path == "" {
		return false
	}

	// Convert relative paths to absolute
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return false
		}
		path = filepath.Join(cwd, path)
	}

	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// FormatValidationReport formats validation results for display
func FormatValidationReport(result *ValidationResult) string {
	if result.Valid && !result.HasWarnings() {
		return "✅ Configuration validation passed!"
	}

	var report strings.Builder

	if result.HasErrors() {
		report.WriteString("❌ Configuration Validation Errors:\n")
		for i, err := range result.Errors {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, err.Error()))
		}
		report.WriteString("\n")
	}

	if result.HasWarnings() {
		report.WriteString("⚠️  Configuration Warnings:\n")
		for i, warning := range result.Warnings {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, warning.Error()))
		}
		report.WriteString("\n")
	}

	if result.Valid {
		report.WriteString("✅ Configuration is valid but has warnings above.")
	} else {
		report.WriteString("❌ Configuration validation failed. Please fix the errors above.")
	}

	return report.String()
}
