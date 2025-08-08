package genai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"obfuskit/types"
)

// PayloadGenerationRequest represents a request for AI payload generation
type PayloadGenerationRequest struct {
	AttackType       types.AttackType `json:"attack_type"`
	TargetContext    string           `json:"target_context"`
	WAFInfo          *WAFContext      `json:"waf_info,omitempty"`
	EvasionLevel     string           `json:"evasion_level"`
	BasePayload      string           `json:"base_payload,omitempty"`
	RequestBaseline  string           `json:"request_baseline,omitempty"`  // Raw request context
	ResponseBaseline string           `json:"response_baseline,omitempty"` // Raw response context
	Count            int              `json:"count"`
	Creativity       float64          `json:"creativity"` // 0.0-1.0
	BypassHistory    []string         `json:"bypass_history,omitempty"`
}

// WAFContext provides context about the target WAF
type WAFContext struct {
	Vendor        string   `json:"vendor,omitempty"`
	Version       string   `json:"version,omitempty"`
	KnownBlocks   []string `json:"known_blocks,omitempty"`
	WeakPoints    []string `json:"weak_points,omitempty"`
	BypassMethods []string `json:"bypass_methods,omitempty"`
}

// GeneratedPayload represents an AI-generated payload with metadata
type GeneratedPayload struct {
	Payload            string            `json:"payload"`
	Technique          string            `json:"technique"`
	Confidence         float64           `json:"confidence"`
	Explanation        string            `json:"explanation"`
	EvasionMethods     []string          `json:"evasion_methods"`
	SuccessProbability float64           `json:"success_probability"`
	Metadata           map[string]string `json:"metadata"`
}

// GenerationResult contains the complete result of AI payload generation
type GenerationResult struct {
	Payloads       []GeneratedPayload `json:"payloads"`
	TotalGenerated int                `json:"total_generated"`
	GenerationTime time.Duration      `json:"generation_time"`
	ModelUsed      string             `json:"model_used"`
	TokensUsed     int                `json:"tokens_used,omitempty"`
	Cost           float64            `json:"cost,omitempty"`
}

// Engine represents the core GenAI engine
type Engine struct {
	Config    *Config
	Client    *http.Client
	Context   context.Context
	Analytics *AnalyticsCollector
}

// Config holds configuration for the GenAI engine
type Config struct {
	Provider    string        `json:"provider"` // "openai", "anthropic", "local", "huggingface"
	APIKey      string        `json:"api_key"`
	APIEndpoint string        `json:"api_endpoint"`
	Model       string        `json:"model"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	Timeout     time.Duration `json:"timeout"`

	// Advanced settings
	EnableCaching       bool `json:"enable_caching"`
	EnableAnalytics     bool `json:"enable_analytics"`
	EnableQualityFilter bool `json:"enable_quality_filter"`
	MaxRetries          int  `json:"max_retries"`
}

// AnalyticsCollector tracks AI generation performance and costs
type AnalyticsCollector struct {
	TotalRequests   int64           `json:"total_requests"`
	TotalTokens     int64           `json:"total_tokens"`
	TotalCost       float64         `json:"total_cost"`
	AverageQuality  float64         `json:"average_quality"`
	SuccessRate     float64         `json:"success_rate"`
	GenerationTimes []time.Duration `json:"-"`
}

// NewEngine creates a new GenAI engine with the specified configuration
func NewEngine(config *Config) *Engine {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxTokens == 0 {
		config.MaxTokens = 1000
	}
	if config.Temperature == 0 {
		config.Temperature = 0.7
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	return &Engine{
		Config: config,
		Client: &http.Client{
			Timeout: config.Timeout,
		},
		Context:   context.Background(),
		Analytics: &AnalyticsCollector{},
	}
}

// GeneratePayloads generates AI-powered evasion payloads
func (e *Engine) GeneratePayloads(req *PayloadGenerationRequest) (*GenerationResult, error) {
	startTime := time.Now()

	fmt.Printf("🤖 AI Payload Generation Starting...\n")
	fmt.Printf("   Provider: %s | Model: %s | Attack: %s\n", e.Config.Provider, e.Config.Model, req.AttackType)

	// Build the AI prompt based on request context
	prompt := e.buildPrompt(req)

	// Generate payloads using the selected AI provider
	var payloads []GeneratedPayload
	var err error

	switch e.Config.Provider {
	case "openai":
		payloads, err = e.generateWithOpenAI(prompt, req)
	case "anthropic":
		payloads, err = e.generateWithAnthropic(prompt, req)
	case "local":
		payloads, err = e.generateWithLocal(prompt, req)
	case "huggingface":
		payloads, err = e.generateWithHuggingFace(prompt, req)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", e.Config.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %v", err)
	}

	// Apply quality filtering if enabled
	if e.Config.EnableQualityFilter {
		payloads = e.filterQuality(payloads, req)
	}

	// Post-process and enhance payloads
	payloads = e.enhancePayloads(payloads, req)

	duration := time.Since(startTime)

	// Update analytics
	if e.Config.EnableAnalytics {
		e.updateAnalytics(len(payloads), duration)
	}

	result := &GenerationResult{
		Payloads:       payloads,
		TotalGenerated: len(payloads),
		GenerationTime: duration,
		ModelUsed:      e.Config.Model,
	}

	fmt.Printf("✅ AI Generation Complete: %d payloads in %v\n", len(payloads), duration)

	return result, nil
}

// buildPrompt creates an intelligent prompt for AI payload generation
func (e *Engine) buildPrompt(req *PayloadGenerationRequest) string {
	var prompt strings.Builder

	// System context
	prompt.WriteString("You are an expert cybersecurity researcher specializing in Web Application Firewall (WAF) evasion techniques. ")
	prompt.WriteString("Your task is to generate sophisticated, creative evasion payloads for security testing purposes.\n\n")

	// Attack type context
	prompt.WriteString(fmt.Sprintf("ATTACK TYPE: %s\n", req.AttackType))
	prompt.WriteString(e.getAttackTypeContext(req.AttackType))

	// WAF context if available
	if req.WAFInfo != nil {
		prompt.WriteString(fmt.Sprintf("\nTARGET WAF: %s", req.WAFInfo.Vendor))
		if req.WAFInfo.Version != "" {
			prompt.WriteString(fmt.Sprintf(" (Version: %s)", req.WAFInfo.Version))
		}
		prompt.WriteString("\n")

		if len(req.WAFInfo.KnownBlocks) > 0 {
			prompt.WriteString(fmt.Sprintf("Known blocked patterns: %v\n", req.WAFInfo.KnownBlocks))
		}

		if len(req.WAFInfo.WeakPoints) > 0 {
			prompt.WriteString(fmt.Sprintf("Known weaknesses: %v\n", req.WAFInfo.WeakPoints))
		}
	}

	// Base payload context
	if req.BasePayload != "" {
		prompt.WriteString(fmt.Sprintf("\nBASE PAYLOAD: %s\n", req.BasePayload))
		prompt.WriteString("Generate advanced evasion variants of this payload.\n")
	}

	// Baseline context for enhanced AI understanding
	if req.RequestBaseline != "" {
		prompt.WriteString(fmt.Sprintf("\nREQUEST BASELINE CONTEXT:\n%s\n", req.RequestBaseline))
		prompt.WriteString("Use this request context to understand the application's input handling and generate context-aware payloads.\n")
	}

	if req.ResponseBaseline != "" {
		prompt.WriteString(fmt.Sprintf("\nRESPONSE BASELINE CONTEXT:\n%s\n", req.ResponseBaseline))
		prompt.WriteString("Use this response context to understand the application's behavior and generate more effective evasion payloads.\n")
	}

	// Evasion level and creativity
	prompt.WriteString(fmt.Sprintf("\nEVASION LEVEL: %s\n", req.EvasionLevel))
	prompt.WriteString(fmt.Sprintf("CREATIVITY LEVEL: %.1f/1.0\n", req.Creativity))

	// Historical context
	if len(req.BypassHistory) > 0 {
		prompt.WriteString("\nPREVIOUSLY SUCCESSFUL BYPASSES:\n")
		for _, bypass := range req.BypassHistory {
			prompt.WriteString(fmt.Sprintf("- %s\n", bypass))
		}
		prompt.WriteString("Use these as inspiration but create NEW, more advanced variants.\n")
	}

	// Generation instructions
	prompt.WriteString(fmt.Sprintf("\nGENERATE %d unique, sophisticated evasion payloads using advanced techniques such as:\n", req.Count))
	prompt.WriteString("- Unicode normalization and homograph attacks\n")
	prompt.WriteString("- Advanced encoding combinations (nested, mixed, custom)\n")
	prompt.WriteString("- Context-aware payload construction\n")
	prompt.WriteString("- Protocol-specific evasion methods\n")
	prompt.WriteString("- Novel obfuscation techniques\n")
	prompt.WriteString("- Polyglot and multi-context payloads\n")

	// Output format
	prompt.WriteString("\nRETURN RESULTS AS JSON with this exact structure:\n")
	prompt.WriteString("{\n")
	prompt.WriteString("  \"payloads\": [\n")
	prompt.WriteString("    {\n")
	prompt.WriteString("      \"payload\": \"actual_payload_here\",\n")
	prompt.WriteString("      \"technique\": \"technique_name\",\n")
	prompt.WriteString("      \"confidence\": 0.85,\n")
	prompt.WriteString("      \"explanation\": \"brief_explanation\",\n")
	prompt.WriteString("      \"evasion_methods\": [\"method1\", \"method2\"],\n")
	prompt.WriteString("      \"success_probability\": 0.75\n")
	prompt.WriteString("    }\n")
	prompt.WriteString("  ]\n")
	prompt.WriteString("}\n")

	return prompt.String()
}

// getAttackTypeContext provides specialized context for each attack type
func (e *Engine) getAttackTypeContext(attackType types.AttackType) string {
	contexts := map[types.AttackType]string{
		types.AttackTypeXSS: `
CONTEXT: Cross-Site Scripting (XSS) attacks inject malicious scripts into web applications.
Focus on: Event handlers, JavaScript contexts, HTML injection, DOM manipulation, CSP bypasses.
Advanced techniques: Template injection, polyglot payloads, context breaking, encoding chains.`,

		types.AttackTypeSQLI: `
CONTEXT: SQL Injection attacks manipulate database queries through user input.
Focus on: Union-based, boolean-based, time-based, error-based injection techniques.
Advanced techniques: Second-order injection, polyglot queries, database-specific functions, WAF-specific bypasses.`,

		types.AttackTypeUnixCMDI: `
CONTEXT: Unix Command Injection executes arbitrary commands on Unix/Linux systems.
Focus on: Command chaining, input/output redirection, environment variables, shell metacharacters.
Advanced techniques: Process substitution, command substitution, glob patterns, null byte injection.`,

		types.AttackTypeWinCMDI: `
CONTEXT: Windows Command Injection executes arbitrary commands on Windows systems.
Focus on: Batch commands, PowerShell injection, environment variables, Windows-specific features.
Advanced techniques: PowerShell encoded commands, batch obfuscation, Windows API calls.`,

		types.AttackTypePath: `
CONTEXT: Path Traversal attacks access files outside intended directories.
Focus on: Directory traversal, file inclusion, URL manipulation, encoding variations.
Advanced techniques: Unicode normalization, double encoding, platform-specific path handling.`,

		types.AttackTypeLDAP: `
CONTEXT: LDAP Injection manipulates LDAP queries and directory services.
Focus on: Filter injection, search manipulation, authentication bypass.
Advanced techniques: Boolean-based injection, wildcard abuse, encoding variations.`,

		types.AttackTypeSSRF: `
CONTEXT: Server-Side Request Forgery tricks servers into making unintended requests.
Focus on: URL manipulation, protocol confusion, internal network access.
Advanced techniques: DNS rebinding, cloud metadata access, protocol smuggling.`,

		types.AttackTypeXXE: `
CONTEXT: XML External Entity attacks exploit XML parsers to access local files or internal networks.
Focus on: Entity expansion, file disclosure, SSRF via XML, DoS attacks.
Advanced techniques: Blind XXE, parameter entity injection, SOAP injection.`,
	}

	if context, exists := contexts[attackType]; exists {
		return context
	}
	return "CONTEXT: Generic security testing payload generation."
}

// generateWithOpenAI generates payloads using OpenAI API
func (e *Engine) generateWithOpenAI(prompt string, req *PayloadGenerationRequest) ([]GeneratedPayload, error) {
	requestBody := map[string]interface{}{
		"model": e.Config.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a cybersecurity expert specializing in WAF evasion techniques.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":      e.Config.MaxTokens,
		"temperature":     e.Config.Temperature,
		"response_format": map[string]string{"type": "json_object"},
	}

	return e.makeAPIRequest("https://api.openai.com/v1/chat/completions", requestBody, "OpenAI")
}

// generateWithAnthropic generates payloads using Anthropic Claude API
func (e *Engine) generateWithAnthropic(prompt string, req *PayloadGenerationRequest) ([]GeneratedPayload, error) {
	requestBody := map[string]interface{}{
		"model":       e.Config.Model,
		"max_tokens":  e.Config.MaxTokens,
		"temperature": e.Config.Temperature,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	return e.makeAPIRequest("https://api.anthropic.com/v1/messages", requestBody, "Anthropic")
}

// generateWithLocal generates payloads using local LLM
func (e *Engine) generateWithLocal(prompt string, req *PayloadGenerationRequest) ([]GeneratedPayload, error) {
	// For local models (Ollama, LM Studio, etc.)
	requestBody := map[string]interface{}{
		"model":       e.Config.Model,
		"prompt":      prompt,
		"max_tokens":  e.Config.MaxTokens,
		"temperature": e.Config.Temperature,
		"stream":      false,
	}

	endpoint := e.Config.APIEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434/api/generate" // Default Ollama endpoint
	}

	return e.makeAPIRequest(endpoint, requestBody, "Local")
}

// generateWithHuggingFace generates payloads using HuggingFace API
func (e *Engine) generateWithHuggingFace(prompt string, req *PayloadGenerationRequest) ([]GeneratedPayload, error) {
	requestBody := map[string]interface{}{
		"inputs": prompt,
		"parameters": map[string]interface{}{
			"max_new_tokens":   e.Config.MaxTokens,
			"temperature":      e.Config.Temperature,
			"return_full_text": false,
		},
	}

	endpoint := fmt.Sprintf("https://api-inference.huggingface.co/models/%s", e.Config.Model)

	return e.makeAPIRequest(endpoint, requestBody, "HuggingFace")
}

// makeAPIRequest makes HTTP requests to AI providers
func (e *Engine) makeAPIRequest(endpoint string, requestBody map[string]interface{}, provider string) ([]GeneratedPayload, error) {
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequestWithContext(e.Context, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers based on provider
	req.Header.Set("Content-Type", "application/json")

	switch provider {
	case "OpenAI":
		req.Header.Set("Authorization", "Bearer "+e.Config.APIKey)
	case "Anthropic":
		req.Header.Set("x-api-key", e.Config.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "HuggingFace":
		req.Header.Set("Authorization", "Bearer "+e.Config.APIKey)
	}

	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return e.parseResponse(body, provider)
}

// parseResponse parses API responses from different providers
func (e *Engine) parseResponse(body []byte, provider string) ([]GeneratedPayload, error) {
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	var content string

	// Extract content based on provider response format
	switch provider {
	case "OpenAI":
		if choices, ok := response["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					content, _ = message["content"].(string)
				}
			}
		}
	case "Anthropic":
		if contentArray, ok := response["content"].([]interface{}); ok && len(contentArray) > 0 {
			if contentObj, ok := contentArray[0].(map[string]interface{}); ok {
				content, _ = contentObj["text"].(string)
			}
		}
	case "Local":
		content, _ = response["response"].(string)
	case "HuggingFace":
		if results, ok := response["generated_text"].(string); ok {
			content = results
		}
	}

	if content == "" {
		return nil, fmt.Errorf("no content received from %s API", provider)
	}

	// Parse the JSON content to extract payloads
	return e.parsePayloadJSON(content)
}

// parsePayloadJSON parses the AI-generated JSON content
func (e *Engine) parsePayloadJSON(content string) ([]GeneratedPayload, error) {
	// Clean up the content (remove markdown code blocks if present)
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
	}
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}
	if strings.HasSuffix(content, "```") {
		content = strings.TrimSuffix(content, "```")
	}
	content = strings.TrimSpace(content)

	var result struct {
		Payloads []GeneratedPayload `json:"payloads"`
	}

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI response JSON: %v\nContent: %s", err, content)
	}

	return result.Payloads, nil
}

// filterQuality applies quality filtering to generated payloads
func (e *Engine) filterQuality(payloads []GeneratedPayload, req *PayloadGenerationRequest) []GeneratedPayload {
	var filtered []GeneratedPayload

	for _, payload := range payloads {
		// Basic quality checks
		if len(payload.Payload) < 3 {
			continue // Too short
		}

		if payload.Confidence < 0.3 {
			continue // Too low confidence
		}

		// Check for originality (not just the base payload)
		if req.BasePayload != "" && payload.Payload == req.BasePayload {
			continue // Not modified
		}

		// Additional quality metrics could be added here
		filtered = append(filtered, payload)
	}

	return filtered
}

// enhancePayloads post-processes and enhances AI-generated payloads
func (e *Engine) enhancePayloads(payloads []GeneratedPayload, req *PayloadGenerationRequest) []GeneratedPayload {
	for i := range payloads {
		// Add metadata
		if payloads[i].Metadata == nil {
			payloads[i].Metadata = make(map[string]string)
		}

		payloads[i].Metadata["generation_method"] = "ai"
		payloads[i].Metadata["model"] = e.Config.Model
		payloads[i].Metadata["provider"] = e.Config.Provider
		payloads[i].Metadata["attack_type"] = string(req.AttackType)

		// Enhance confidence based on various factors
		if len(payloads[i].EvasionMethods) > 2 {
			payloads[i].Confidence += 0.1 // Multiple evasion methods
		}

		if len(payloads[i].Explanation) > 50 {
			payloads[i].Confidence += 0.05 // Detailed explanation
		}

		// Ensure confidence stays within bounds
		if payloads[i].Confidence > 1.0 {
			payloads[i].Confidence = 1.0
		}
	}

	return payloads
}

// updateAnalytics updates the analytics collector
func (e *Engine) updateAnalytics(payloadCount int, duration time.Duration) {
	e.Analytics.TotalRequests++
	e.Analytics.GenerationTimes = append(e.Analytics.GenerationTimes, duration)

	// Calculate success rate (simplified for now)
	if payloadCount > 0 {
		e.Analytics.SuccessRate = float64(payloadCount) / float64(e.Analytics.TotalRequests)
	}
}

// GetAnalytics returns current analytics data
func (e *Engine) GetAnalytics() *AnalyticsCollector {
	return e.Analytics
}

// IsConfigured checks if the engine is properly configured
func (e *Engine) IsConfigured() bool {
	if e.Config == nil {
		return false
	}

	// Check provider-specific requirements
	switch e.Config.Provider {
	case "openai", "anthropic", "huggingface":
		return e.Config.APIKey != ""
	case "local":
		return e.Config.APIEndpoint != "" || e.Config.Model != ""
	default:
		return false
	}
}
