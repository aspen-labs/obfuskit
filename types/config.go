package types

const (
	ActionGeneratePayloads    Action = "Generate Payloads"
	ActionSendToURL           Action = "Send to URL"
	ActionUseExistingPayloads Action = "Use Existing Payloads"
)

type Action string

type AttackType string

const (
	AttackTypeXSS        AttackType = "xss"
	AttackTypeSQLI       AttackType = "sqli"
	AttackTypeUnixCMDI   AttackType = "unixcmdi"
	AttackTypeWinCMDI    AttackType = "wincmdi"
	AttackTypeOsCMDI     AttackType = "oscmdi"
	AttackTypePath       AttackType = "path"
	AttackTypeFileAccess AttackType = "fileaccess"
	AttackTypeLDAP       AttackType = "ldapi"
	AttackTypeSSRF       AttackType = "ssrf"
	AttackTypeXXE        AttackType = "xxe"
	AttackTypeGeneric    AttackType = "generic"
	AttackTypeAll        AttackType = "all"
)

type EvasionCategory string

const (
	EvasionCategoryEncoder EvasionCategory = "encoder"
	EvasionCategoryCommand EvasionCategory = "command"
	EvasionCategoryPath    EvasionCategory = "path"
)

type PayloadMethod string

const (
	PayloadMethodAuto          PayloadMethod = "Auto"
	PayloadMethodEncodings     PayloadMethod = "Encodings"
	PayloadMethodPaths         PayloadMethod = "Paths"
	PayloadMethodCommands      PayloadMethod = "Commands"
	PayloadMethodFile          PayloadMethod = "File"
	PayloadMethodEnterManually PayloadMethod = "Enter Manually"
)

type PayloadSource string

const (
	PayloadSourceGenerated     PayloadSource = "Generated"
	PayloadSourceFromFile      PayloadSource = "From File"
	PayloadSourceEnterManually PayloadSource = "Enter Manually"
)

type PayloadEncoding string

const (
	PayloadEncodingAuto          PayloadEncoding = "Auto"
	PayloadEncodingURL           PayloadEncoding = "URLVariants"
	PayloadEncodingDoubleURL     PayloadEncoding = "DoubleURLVariants"
	PayloadEncodingMixedCase     PayloadEncoding = "MixedCaseVariants"
	PayloadEncodingBase64        PayloadEncoding = "Base64Variants"
	PayloadEncodingBestFit       PayloadEncoding = "BestFitVariants"
	PayloadEncodingHex           PayloadEncoding = "HexVariants"
	PayloadEncodingHTML          PayloadEncoding = "HTMLVariants"
	PayloadEncodingOctal         PayloadEncoding = "OctalVariants"
	PayloadEncodingUnicode       PayloadEncoding = "UnicodeVariants"
	PayloadEncodingUnixCmd       PayloadEncoding = "UnixCmdVariants"
	PayloadEncodingWindowsCmd    PayloadEncoding = "WindowsCmdVariants"
	PayloadEncodingPathTraversal PayloadEncoding = "PathTraversalVariants"
	PayloadEncodingUTF8          PayloadEncoding = "UTF8Variants"
)

type Payload struct {
	Method   PayloadMethod   `yaml:"method" json:"method"`
	Encoding PayloadEncoding `yaml:"encoding" json:"encoding"`
	Source   PayloadSource   `yaml:"source" json:"source"`
	FilePath string          `yaml:"file_path" json:"file_path"`
	Custom   []string        `yaml:"custom" json:"custom"`
}

type EvasionLevel string

const (
	EvasionLevelBasic    EvasionLevel = "Basic"
	EvasionLevelMedium   EvasionLevel = "Medium"
	EvasionLevelAdvanced EvasionLevel = "Advanced"
)

type TargetMethod string

const (
	TargetMethodURL  TargetMethod = "URL"
	TargetMethodFile TargetMethod = "File"
)

type Target struct {
	Method TargetMethod `yaml:"method" json:"method"`
	URL    string       `yaml:"url" json:"url"`
	File   string       `yaml:"file" json:"file"`
}

type ReportType string

const (
	ReportTypeHTML   ReportType = "HTML"
	ReportTypePretty ReportType = "Pretty Terminal"
	ReportTypePDF    ReportType = "PDF"
	ReportTypeCSV    ReportType = "CSV"
	ReportTypeNuclei ReportType = "Nuclei Templates"
	ReportTypeJSON   ReportType = "JSON"
	ReportTypeAuto   ReportType = "Auto"
	ReportTypeAll    ReportType = "All"
)

type Config struct {
	// Action specifies what to do: "Generate Payloads", "Send to URL", or "Use Existing Payloads"
	Action Action `yaml:"action" json:"action"`

	// Attack configuration
	AttackType AttackType `yaml:"attack_type" json:"attack_type"`

	// Payload configuration
	Payload Payload `yaml:"payload" json:"payload"`

	// Evasion configuration
	EvasionLevel EvasionLevel `yaml:"evasion_level" json:"evasion_level"`

	// Target configuration
	Target Target `yaml:"target" json:"target"`

	// Report configuration
	ReportType ReportType `yaml:"report_type" json:"report_type"`

	// Advanced filtering options (CLI only, not part of YAML/JSON config)
	FilterOptions interface{} `yaml:"-" json:"-"`

	// WAF fingerprinting options (CLI only, not part of YAML/JSON config)
	EnableFingerprinting bool        `yaml:"-" json:"-"`
	ShowWAFReport        bool        `yaml:"-" json:"-"`
	WAFFingerprint       interface{} `yaml:"-" json:"-"`

	// Additional attack types for multi-attack processing (CLI only)
	AdditionalAttackTypes []AttackType `yaml:"-" json:"-"`
}
