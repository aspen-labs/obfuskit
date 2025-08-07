package types

import (
	"testing"
)

func TestActionConstants(t *testing.T) {
	tests := []struct {
		name     string
		action   Action
		expected string
	}{
		{"Generate Payloads", ActionGeneratePayloads, "Generate Payloads"},
		{"Send to URL", ActionSendToURL, "Send to URL"},
		{"Use Existing Payloads", ActionUseExistingPayloads, "Use Existing Payloads"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("Action constant %s = %v, want %v", tt.name, string(tt.action), tt.expected)
			}
		})
	}
}

func TestAttackTypeConstants(t *testing.T) {
	validAttackTypes := []AttackType{
		AttackTypeXSS,
		AttackTypeSQLI,
		AttackTypeUnixCMDI,
		AttackTypeWinCMDI,
		AttackTypeOsCMDI,
		AttackTypePath,
		AttackTypeFileAccess,
		AttackTypeLDAP,
		AttackTypeSSRF,
		AttackTypeXXE,
		AttackTypeGeneric,
		AttackTypeAll,
	}

	expectedValues := []string{
		"xss", "sqli", "unixcmdi", "wincmdi", "oscmdi",
		"path", "fileaccess", "ldapi", "ssrf", "xxe",
		"generic", "all",
	}

	if len(validAttackTypes) != len(expectedValues) {
		t.Errorf("Mismatch between attack types and expected values count")
	}

	for i, attackType := range validAttackTypes {
		if string(attackType) != expectedValues[i] {
			t.Errorf("AttackType %d = %v, want %v", i, string(attackType), expectedValues[i])
		}
	}
}

func TestEvasionCategoryConstants(t *testing.T) {
	tests := []struct {
		name     string
		category EvasionCategory
		expected string
	}{
		{"Encoder", EvasionCategoryEncoder, "encoder"},
		{"Command", EvasionCategoryCommand, "command"},
		{"Path", EvasionCategoryPath, "path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.category) != tt.expected {
				t.Errorf("EvasionCategory constant %s = %v, want %v", tt.name, string(tt.category), tt.expected)
			}
		})
	}
}

func TestPayloadMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		method   PayloadMethod
		expected string
	}{
		{"Auto", PayloadMethodAuto, "Auto"},
		{"Encodings", PayloadMethodEncodings, "Encodings"},
		{"Paths", PayloadMethodPaths, "Paths"},
		{"Commands", PayloadMethodCommands, "Commands"},
		{"File", PayloadMethodFile, "File"},
		{"Enter Manually", PayloadMethodEnterManually, "Enter Manually"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.method) != tt.expected {
				t.Errorf("PayloadMethod constant %s = %v, want %v", tt.name, string(tt.method), tt.expected)
			}
		})
	}
}

func TestPayloadSourceConstants(t *testing.T) {
	tests := []struct {
		name     string
		source   PayloadSource
		expected string
	}{
		{"Generated", PayloadSourceGenerated, "Generated"},
		{"From File", PayloadSourceFromFile, "From File"},
		{"Enter Manually", PayloadSourceEnterManually, "Enter Manually"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.source) != tt.expected {
				t.Errorf("PayloadSource constant %s = %v, want %v", tt.name, string(tt.source), tt.expected)
			}
		})
	}
}

func TestPayloadEncodingConstants(t *testing.T) {
	encodings := []PayloadEncoding{
		PayloadEncodingAuto,
		PayloadEncodingURL,
		PayloadEncodingDoubleURL,
		PayloadEncodingMixedCase,
		PayloadEncodingBase64,
		PayloadEncodingBestFit,
		PayloadEncodingHex,
		PayloadEncodingHTML,
		PayloadEncodingOctal,
		PayloadEncodingUnicode,
		PayloadEncodingUnixCmd,
		PayloadEncodingWindowsCmd,
		PayloadEncodingPathTraversal,
		PayloadEncodingUTF8,
	}

	expectedValues := []string{
		"Auto",
		"URLVariants",
		"DoubleURLVariants",
		"MixedCaseVariants",
		"Base64Variants",
		"BestFitVariants",
		"HexVariants",
		"HTMLVariants",
		"OctalVariants",
		"UnicodeVariants",
		"UnixCmdVariants",
		"WindowsCmdVariants",
		"PathTraversalVariants",
		"UTF8Variants",
	}

	if len(encodings) != len(expectedValues) {
		t.Errorf("Mismatch between encodings and expected values count")
	}

	for i, encoding := range encodings {
		if string(encoding) != expectedValues[i] {
			t.Errorf("PayloadEncoding %d = %v, want %v", i, string(encoding), expectedValues[i])
		}
	}
}

func TestEvasionLevelConstants(t *testing.T) {
	tests := []struct {
		name     string
		level    EvasionLevel
		expected string
	}{
		{"Basic", EvasionLevelBasic, "Basic"},
		{"Medium", EvasionLevelMedium, "Medium"},
		{"Advanced", EvasionLevelAdvanced, "Advanced"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.level) != tt.expected {
				t.Errorf("EvasionLevel constant %s = %v, want %v", tt.name, string(tt.level), tt.expected)
			}
		})
	}
}

func TestTargetMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		method   TargetMethod
		expected string
	}{
		{"URL", TargetMethodURL, "URL"},
		{"File", TargetMethodFile, "File"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.method) != tt.expected {
				t.Errorf("TargetMethod constant %s = %v, want %v", tt.name, string(tt.method), tt.expected)
			}
		})
	}
}

func TestReportTypeConstants(t *testing.T) {
	tests := []struct {
		name       string
		reportType ReportType
		expected   string
	}{
		{"HTML", ReportTypeHTML, "HTML"},
		{"Pretty Terminal", ReportTypePretty, "Pretty Terminal"},
		{"PDF", ReportTypePDF, "PDF"},
		{"CSV", ReportTypeCSV, "CSV"},
		{"Nuclei Templates", ReportTypeNuclei, "Nuclei Templates"},
		{"JSON", ReportTypeJSON, "JSON"},
		{"Auto", ReportTypeAuto, "Auto"},
		{"All", ReportTypeAll, "All"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.reportType) != tt.expected {
				t.Errorf("ReportType constant %s = %v, want %v", tt.name, string(tt.reportType), tt.expected)
			}
		})
	}
}

func TestConfigStructure(t *testing.T) {
	config := &Config{
		Action:     ActionGeneratePayloads,
		AttackType: AttackTypeXSS,
		Payload: Payload{
			Method:   PayloadMethodEncodings,
			Encoding: PayloadEncodingBase64,
			Source:   PayloadSourceGenerated,
			FilePath: "/path/to/file",
			Custom:   []string{"payload1", "payload2"},
		},
		EvasionLevel: EvasionLevelMedium,
		Target: Target{
			Method: TargetMethodURL,
			URL:    "https://example.com",
			File:   "/path/to/output",
		},
		ReportType: ReportTypeHTML,
	}

	// Test that all fields are properly set
	if config.Action != ActionGeneratePayloads {
		t.Errorf("Config.Action = %v, want %v", config.Action, ActionGeneratePayloads)
	}

	if config.AttackType != AttackTypeXSS {
		t.Errorf("Config.AttackType = %v, want %v", config.AttackType, AttackTypeXSS)
	}

	if config.Payload.Method != PayloadMethodEncodings {
		t.Errorf("Config.Payload.Method = %v, want %v", config.Payload.Method, PayloadMethodEncodings)
	}

	if config.Payload.Encoding != PayloadEncodingBase64 {
		t.Errorf("Config.Payload.Encoding = %v, want %v", config.Payload.Encoding, PayloadEncodingBase64)
	}

	if config.EvasionLevel != EvasionLevelMedium {
		t.Errorf("Config.EvasionLevel = %v, want %v", config.EvasionLevel, EvasionLevelMedium)
	}

	if config.Target.Method != TargetMethodURL {
		t.Errorf("Config.Target.Method = %v, want %v", config.Target.Method, TargetMethodURL)
	}

	if config.ReportType != ReportTypeHTML {
		t.Errorf("Config.ReportType = %v, want %v", config.ReportType, ReportTypeHTML)
	}
}

func TestPayloadStructure(t *testing.T) {
	payload := Payload{
		Method:   PayloadMethodFile,
		Encoding: PayloadEncodingHex,
		Source:   PayloadSourceFromFile,
		FilePath: "/test/path",
		Custom:   []string{"custom1", "custom2", "custom3"},
	}

	if payload.Method != PayloadMethodFile {
		t.Errorf("Payload.Method = %v, want %v", payload.Method, PayloadMethodFile)
	}

	if payload.Encoding != PayloadEncodingHex {
		t.Errorf("Payload.Encoding = %v, want %v", payload.Encoding, PayloadEncodingHex)
	}

	if payload.Source != PayloadSourceFromFile {
		t.Errorf("Payload.Source = %v, want %v", payload.Source, PayloadSourceFromFile)
	}

	if payload.FilePath != "/test/path" {
		t.Errorf("Payload.FilePath = %v, want %v", payload.FilePath, "/test/path")
	}

	if len(payload.Custom) != 3 {
		t.Errorf("len(Payload.Custom) = %v, want %v", len(payload.Custom), 3)
	}
}

func TestTargetStructure(t *testing.T) {
	target := Target{
		Method: TargetMethodFile,
		URL:    "https://test.example.com",
		File:   "/output/test.txt",
	}

	if target.Method != TargetMethodFile {
		t.Errorf("Target.Method = %v, want %v", target.Method, TargetMethodFile)
	}

	if target.URL != "https://test.example.com" {
		t.Errorf("Target.URL = %v, want %v", target.URL, "https://test.example.com")
	}

	if target.File != "/output/test.txt" {
		t.Errorf("Target.File = %v, want %v", target.File, "/output/test.txt")
	}
}

func TestTypeConversions(t *testing.T) {
	// Test string to type conversions work as expected
	actionStr := "Generate Payloads"
	action := Action(actionStr)
	if action != ActionGeneratePayloads {
		t.Errorf("Action conversion failed: got %v, want %v", action, ActionGeneratePayloads)
	}

	attackTypeStr := "xss"
	attackType := AttackType(attackTypeStr)
	if attackType != AttackTypeXSS {
		t.Errorf("AttackType conversion failed: got %v, want %v", attackType, AttackTypeXSS)
	}

	evasionLevelStr := "Advanced"
	evasionLevel := EvasionLevel(evasionLevelStr)
	if evasionLevel != EvasionLevelAdvanced {
		t.Errorf("EvasionLevel conversion failed: got %v, want %v", evasionLevel, EvasionLevelAdvanced)
	}
}

func TestConstantUniqueness(t *testing.T) {
	// Test that all constants within each type are unique
	attackTypes := []AttackType{
		AttackTypeXSS, AttackTypeSQLI, AttackTypeUnixCMDI, AttackTypeWinCMDI,
		AttackTypeOsCMDI, AttackTypePath, AttackTypeFileAccess, AttackTypeLDAP,
		AttackTypeSSRF, AttackTypeXXE, AttackTypeGeneric, AttackTypeAll,
	}

	seen := make(map[string]bool)
	for _, attackType := range attackTypes {
		str := string(attackType)
		if seen[str] {
			t.Errorf("Duplicate AttackType constant: %s", str)
		}
		seen[str] = true
	}

	// Test EvasionLevel uniqueness
	evasionLevels := []EvasionLevel{
		EvasionLevelBasic, EvasionLevelMedium, EvasionLevelAdvanced,
	}

	seenLevels := make(map[string]bool)
	for _, level := range evasionLevels {
		str := string(level)
		if seenLevels[str] {
			t.Errorf("Duplicate EvasionLevel constant: %s", str)
		}
		seenLevels[str] = true
	}
}

func TestConstantValidation(t *testing.T) {
	// Test that constants are not empty
	if string(ActionGeneratePayloads) == "" {
		t.Error("ActionGeneratePayloads should not be empty")
	}

	if string(AttackTypeXSS) == "" {
		t.Error("AttackTypeXSS should not be empty")
	}

	if string(EvasionLevelBasic) == "" {
		t.Error("EvasionLevelBasic should not be empty")
	}

	if string(PayloadMethodAuto) == "" {
		t.Error("PayloadMethodAuto should not be empty")
	}

	if string(ReportTypeHTML) == "" {
		t.Error("ReportTypeHTML should not be empty")
	}
}
