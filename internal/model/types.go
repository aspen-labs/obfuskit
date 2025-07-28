package model

import (
	"obfuskit/internal/constants"
	"obfuskit/request"
)

// PayloadResults represents the structure for storing generated payloads
type PayloadResults struct {
	OriginalPayload string
	AttackType      string
	EvasionType     string
	Variants        []string
	Level           constants.Level
}

// TestResults represents the complete test execution results
type TestResults struct {
	Config         interface{} // will be replaced with actual config type
	PayloadResults []PayloadResults
	RequestResults []request.TestResult
	Summary        TestSummary
}

type TestSummary struct {
	TotalPayloads   int
	TotalVariants   int
	SuccessfulTests int
	FailedTests     int
	AttackTypes     []string
	EvasionTypes    []string
}

// BurpRequest is the expected JSON format from Burp
type BurpRequest struct {
	Payload string `json:"payload"`
}

type BurpEvadedPayload struct {
	OriginalPayload string          `json:"original_payload"`
	AttackType      string          `json:"attack_type"`
	EvasionType     string          `json:"evasion_type"`
	Level           constants.Level `json:"level"`
	Variant         string          `json:"variant"`
}

type BurpResponse struct {
	Status   string              `json:"status"`
	Payloads []BurpEvadedPayload `json:"payloads"`
}
