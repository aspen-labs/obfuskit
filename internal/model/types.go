package model

import (
	"obfuskit/request"
)

// PayloadResults represents the structure for storing generated payloads
type PayloadResults struct {
	OriginalPayload string
	AttackType      string
	EvasionType     string
	Variants        []string
	Level           string
}

// TestResults represents the complete test execution results
type TestResults struct {
	Config         interface{} // will be replaced with actual config type
	PayloadResults []PayloadResults
	RequestResults []request.TestResult
	// AllRequestResults holds the unfiltered set for summary/report baselines
	AllRequestResults []request.TestResult
	Summary           TestSummary
}

type TestSummary struct {
	TotalPayloads   int
	TotalVariants   int
	SuccessfulTests int
	FailedTests     int
	AttackTypes     []string
	EvasionTypes    []string
}

// PayloadRequest is the expected JSON format from api
type PayloadRequest struct {
	Payload string `json:"payload"`
	// Optional: raw request/response payloads for baseline/context analysis
	RequestPayload  string `json:"request_payload,omitempty"`
	ResponsePayload string `json:"response_payload,omitempty"`
}

type EvadedPayload struct {
	OriginalPayload string `json:"original_payload"`
	AttackType      string `json:"attack_type"`
	EvasionType     string `json:"evasion_type"`
	Level           string `json:"evasion_level"`
	Variant         string `json:"variant"`
}

type PayloadResponse struct {
	Status   string          `json:"status"`
	Payloads []EvadedPayload `json:"payloads"`
	// Optional baseline/context echoes for client-side correlation/analysis
	Baseline *Baseline `json:"baseline,omitempty"`
}

// Baseline contains basic analysis/echo of provided request/response payloads
type Baseline struct {
	RequestPreview  string `json:"request_preview,omitempty"`
	ResponsePreview string `json:"response_preview,omitempty"`
	RequestLength   int    `json:"request_length,omitempty"`
	ResponseLength  int    `json:"response_length,omitempty"`
}
