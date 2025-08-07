package waf

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

// WAFType represents different types of Web Application Firewalls
type WAFType string

const (
	WAFTypeUnknown     WAFType = "Unknown"
	WAFTypeCloudFlare  WAFType = "CloudFlare"
	WAFTypeAWSWAF      WAFType = "AWS WAF"
	WAFTypeAzureWAF    WAFType = "Azure WAF"
	WAFTypeAkamai      WAFType = "Akamai"
	WAFTypeModSecurity WAFType = "ModSecurity"
	WAFTypeImperva     WAFType = "Imperva"
	WAFTypeF5BigIP     WAFType = "F5 BIG-IP ASM"
	WAFTypeBarracuda   WAFType = "Barracuda"
	WAFTypeFortinet    WAFType = "Fortinet FortiWeb"
	WAFTypeCitrix      WAFType = "Citrix NetScaler"
	WAFTypeWallarm     WAFType = "Wallarm"
	WAFTypeSucuri      WAFType = "Sucuri"
	WAFTypeRadware     WAFType = "Radware"
	WAFTypeNginx       WAFType = "Nginx WAF"
)

// WAFFingerprint represents detected WAF information
type WAFFingerprint struct {
	WAFType     WAFType           `json:"waf_type"`
	Confidence  float64           `json:"confidence"`
	Evidence    []string          `json:"evidence"`
	Headers     map[string]string `json:"headers"`
	StatusCodes []int             `json:"status_codes"`
	Behavior    WAFBehavior       `json:"behavior"`
	Detected    time.Time         `json:"detected"`
}

// WAFBehavior describes how the WAF behaves
type WAFBehavior struct {
	BlocksBasicXSS         bool `json:"blocks_basic_xss"`
	BlocksBasicSQLi        bool `json:"blocks_basic_sqli"`
	BlocksCommandInjection bool `json:"blocks_command_injection"`
	HasRateLimiting        bool `json:"has_rate_limiting"`
	CustomErrorPages       bool `json:"custom_error_pages"`
	JavaScriptChallenge    bool `json:"javascript_challenge"`
}

// WAFSignature represents detection patterns for a specific WAF
type WAFSignature struct {
	Name         WAFType
	Headers      map[string]*regexp.Regexp
	Content      []*regexp.Regexp
	StatusCodes  []int
	TestPayloads []string
	Confidence   float64
}

// GetWAFSignatures returns known WAF signatures for detection
func GetWAFSignatures() []WAFSignature {
	return []WAFSignature{
		{
			Name: WAFTypeCloudFlare,
			Headers: map[string]*regexp.Regexp{
				"Server":          regexp.MustCompile(`(?i)cloudflare`),
				"CF-Ray":          regexp.MustCompile(`.+`),
				"CF-Cache-Status": regexp.MustCompile(`.+`),
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)cloudflare`),
				regexp.MustCompile(`(?i)attention required`),
				regexp.MustCompile(`(?i)ray id`),
			},
			StatusCodes: []int{403, 503},
			TestPayloads: []string{
				"<script>alert(1)</script>",
				"' OR 1=1 --",
				"../../../etc/passwd",
			},
			Confidence: 0.9,
		},
		{
			Name: WAFTypeAWSWAF,
			Headers: map[string]*regexp.Regexp{
				"Server":           regexp.MustCompile(`(?i)awselb|cloudfront`),
				"X-Amzn-RequestId": regexp.MustCompile(`.+`),
				"X-Amz-Cf-Id":      regexp.MustCompile(`.+`),
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)aws`),
				regexp.MustCompile(`(?i)request blocked`),
			},
			StatusCodes: []int{403},
			Confidence:  0.8,
		},
		{
			Name: WAFTypeModSecurity,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)mod_security|modsecurity`),
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)mod_security|modsecurity`),
				regexp.MustCompile(`(?i)not acceptable`),
				regexp.MustCompile(`(?i)blocked by.*rule`),
			},
			StatusCodes: []int{403, 406},
			Confidence:  0.85,
		},
		{
			Name: WAFTypeImperva,
			Headers: map[string]*regexp.Regexp{
				"X-Iinfo": regexp.MustCompile(`.+`),
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)imperva`),
				regexp.MustCompile(`(?i)incapsula`),
			},
			StatusCodes: []int{403},
			Confidence:  0.9,
		},
		{
			Name: WAFTypeF5BigIP,
			Headers: map[string]*regexp.Regexp{
				"Server":     regexp.MustCompile(`(?i)big-?ip|f5`),
				"X-WA-Info":  regexp.MustCompile(`.+`),
				"X-Cnection": regexp.MustCompile(`.+`), // F5 typo
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)f5|big-?ip`),
				regexp.MustCompile(`(?i)the requested url was rejected`),
			},
			StatusCodes: []int{403},
			Confidence:  0.85,
		},
		{
			Name: WAFTypeAkamai,
			Headers: map[string]*regexp.Regexp{
				"Server":              regexp.MustCompile(`(?i)akamai`),
				"Akamai-Ghost-IP":     regexp.MustCompile(`.+`),
				"X-Akamai-Request-ID": regexp.MustCompile(`.+`),
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)akamai`),
				regexp.MustCompile(`(?i)reference.*\d+`),
			},
			StatusCodes: []int{403},
			Confidence:  0.9,
		},
		{
			Name: WAFTypeBarracuda,
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)barracuda`),
				regexp.MustCompile(`(?i)blocked.*barracuda`),
			},
			StatusCodes: []int{403},
			Confidence:  0.8,
		},
		{
			Name: WAFTypeSucuri,
			Headers: map[string]*regexp.Regexp{
				"Server":         regexp.MustCompile(`(?i)sucuri`),
				"X-Sucuri-ID":    regexp.MustCompile(`.+`),
				"X-Sucuri-Cache": regexp.MustCompile(`.+`),
			},
			Content: []*regexp.Regexp{
				regexp.MustCompile(`(?i)sucuri`),
				regexp.MustCompile(`(?i)access denied.*sucuri`),
			},
			StatusCodes: []int{403},
			Confidence:  0.9,
		},
	}
}

// FingerprintWAF attempts to identify the WAF protecting a URL
func FingerprintWAF(targetURL string) (*WAFFingerprint, error) {
	fmt.Printf("🔍 Fingerprinting WAF at %s...\n", targetURL)

	fingerprint := &WAFFingerprint{
		WAFType:     WAFTypeUnknown,
		Confidence:  0.0,
		Evidence:    []string{},
		Headers:     make(map[string]string),
		StatusCodes: []int{},
		Detected:    time.Now(),
	}

	signatures := GetWAFSignatures()

	// Test with benign request first
	normalResponse, err := makeRequest(targetURL, "")
	if err != nil {
		return fingerprint, fmt.Errorf("failed to make normal request: %w", err)
	}

	// Store baseline headers
	normalResponse.Header.VisitAll(func(key, value []byte) {
		fingerprint.Headers[string(key)] = string(value)
	})

	// Test with malicious payloads
	testPayloads := []string{
		"<script>alert('XSS')</script>",
		"' OR 1=1 --",
		"' UNION SELECT 1,2,3 --",
		"../../../etc/passwd",
		"; cat /etc/passwd",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"' AND (SELECT COUNT(*) FROM users) > 0 --",
	}

	var maliciousResponses []*fasthttp.Response
	for _, payload := range testPayloads {
		resp, err := makeRequest(targetURL, payload)
		if err == nil {
			maliciousResponses = append(maliciousResponses, resp)
			fingerprint.StatusCodes = append(fingerprint.StatusCodes, resp.StatusCode())
		}
	}

	// Analyze responses against signatures
	bestMatch := findBestMatch(signatures, normalResponse, maliciousResponses)
	if bestMatch != nil {
		fingerprint.WAFType = bestMatch.Name
		fingerprint.Confidence = bestMatch.Confidence
		fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("Matched signature for %s", bestMatch.Name))
	}

	// Analyze WAF behavior
	fingerprint.Behavior = analyzeBehavior(normalResponse, maliciousResponses)

	// Additional heuristics
	fingerprint = applyHeuristics(fingerprint, normalResponse, maliciousResponses)

	fmt.Printf("✅ WAF Fingerprinting complete: %s (%.1f%% confidence)\n",
		fingerprint.WAFType, fingerprint.Confidence*100)

	return fingerprint, nil
}

// makeRequest makes an HTTP request with optional payload injection
func makeRequest(targetURL, payload string) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)

	// Build URL with payload
	if payload != "" {
		if strings.Contains(targetURL, "?") {
			targetURL += "&test=" + payload
		} else {
			targetURL += "?test=" + payload
		}
	}

	req.SetRequestURI(targetURL)
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &fasthttp.Client{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := client.Do(req, resp)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}

	// Create a copy to return
	respCopy := fasthttp.AcquireResponse()
	resp.CopyTo(respCopy)
	fasthttp.ReleaseResponse(resp)

	return respCopy, nil
}

// findBestMatch finds the WAF signature that best matches the responses
func findBestMatch(signatures []WAFSignature, normal *fasthttp.Response, malicious []*fasthttp.Response) *WAFSignature {
	var bestMatch *WAFSignature
	bestScore := 0.0

	for _, sig := range signatures {
		score := 0.0

		// Check headers
		for headerName, pattern := range sig.Headers {
			headerValue := string(normal.Header.Peek(headerName))
			if pattern.MatchString(headerValue) {
				score += 0.3
			}
		}

		// Check content patterns
		normalBody := string(normal.Body())
		for _, pattern := range sig.Content {
			if pattern.MatchString(normalBody) {
				score += 0.2
			}
		}

		// Check malicious responses
		for _, resp := range malicious {
			body := string(resp.Body())
			for _, pattern := range sig.Content {
				if pattern.MatchString(body) {
					score += 0.3
				}
			}

			// Check status codes
			for _, expectedCode := range sig.StatusCodes {
				if resp.StatusCode() == expectedCode {
					score += 0.2
				}
			}
		}

		// Apply signature confidence
		score *= sig.Confidence

		if score > bestScore {
			bestScore = score
			bestMatch = &sig
		}
	}

	// Only return if confidence is above threshold
	if bestScore > 0.3 {
		return bestMatch
	}

	return nil
}

// analyzeBehavior analyzes WAF behavior patterns
func analyzeBehavior(normal *fasthttp.Response, malicious []*fasthttp.Response) WAFBehavior {
	behavior := WAFBehavior{}

	// Check if malicious requests are blocked
	normalStatus := normal.StatusCode()

	for _, resp := range malicious {
		if resp.StatusCode() != normalStatus && (resp.StatusCode() == 403 || resp.StatusCode() == 406) {
			// Determine what was blocked based on response content
			body := strings.ToLower(string(resp.Body()))
			if strings.Contains(body, "script") || strings.Contains(body, "xss") {
				behavior.BlocksBasicXSS = true
			}
			if strings.Contains(body, "sql") || strings.Contains(body, "union") {
				behavior.BlocksBasicSQLi = true
			}
			if strings.Contains(body, "command") || strings.Contains(body, "injection") {
				behavior.BlocksCommandInjection = true
			}
		}

		// Check for JavaScript challenges
		body := string(resp.Body())
		if strings.Contains(body, "challenge") || strings.Contains(body, "javascript") {
			behavior.JavaScriptChallenge = true
		}

		// Check for custom error pages
		if resp.StatusCode() >= 400 && len(body) > 1000 {
			behavior.CustomErrorPages = true
		}
	}

	return behavior
}

// applyHeuristics applies additional detection heuristics
func applyHeuristics(fingerprint *WAFFingerprint, normal *fasthttp.Response, malicious []*fasthttp.Response) *WAFFingerprint {
	// Check for rate limiting patterns
	if len(malicious) > 0 {
		statusCodes := make(map[int]int)
		for _, resp := range malicious {
			statusCodes[resp.StatusCode()]++
		}

		if statusCodes[429] > 0 || statusCodes[503] > 2 {
			fingerprint.Behavior.HasRateLimiting = true
			fingerprint.Evidence = append(fingerprint.Evidence, "Rate limiting detected")
		}
	}

	// Check server header patterns
	server := string(normal.Header.Peek("Server"))
	if server != "" {
		fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("Server header: %s", server))

		// Additional server-based detection
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "nginx") && fingerprint.WAFType == WAFTypeUnknown {
			fingerprint.WAFType = WAFTypeNginx
			fingerprint.Confidence = 0.6
		}
	}

	return fingerprint
}

// GetOptimalEvasions returns WAF-specific evasion techniques
func GetOptimalEvasions(wafType WAFType) []string {
	switch wafType {
	case WAFTypeCloudFlare:
		return []string{
			"unicode", "mixedcase", "bestfit", "doubleurl",
		}
	case WAFTypeModSecurity:
		return []string{
			"unicode", "hex", "octal", "html",
		}
	case WAFTypeAWSWAF:
		return []string{
			"url", "unicode", "utf8", "bestfit",
		}
	case WAFTypeF5BigIP:
		return []string{
			"unicode", "hex", "doubleurl", "mixedcase",
		}
	case WAFTypeImperva:
		return []string{
			"bestfit", "unicode", "mixedcase", "utf8",
		}
	case WAFTypeAkamai:
		return []string{
			"unicode", "doubleurl", "bestfit", "html",
		}
	default:
		return []string{
			"unicode", "url", "html", "hex", "base64",
		}
	}
}

// GenerateWAFReport generates a detailed WAF analysis report
func GenerateWAFReport(fingerprint *WAFFingerprint) string {
	report := fmt.Sprintf(`
🛡️  WAF ANALYSIS REPORT
════════════════════════════════════════════════════════════════

WAF Type: %s
Confidence: %.1f%%
Detection Time: %s

DETECTION EVIDENCE:
`, fingerprint.WAFType, fingerprint.Confidence*100, fingerprint.Detected.Format(time.RFC3339))

	for _, evidence := range fingerprint.Evidence {
		report += fmt.Sprintf("  • %s\n", evidence)
	}

	report += fmt.Sprintf(`
BEHAVIORAL ANALYSIS:
  • Blocks Basic XSS: %t
  • Blocks Basic SQLi: %t  
  • Blocks Command Injection: %t
  • Has Rate Limiting: %t
  • Custom Error Pages: %t
  • JavaScript Challenge: %t

RESPONSE HEADERS:
`, fingerprint.Behavior.BlocksBasicXSS, fingerprint.Behavior.BlocksBasicSQLi,
		fingerprint.Behavior.BlocksCommandInjection, fingerprint.Behavior.HasRateLimiting,
		fingerprint.Behavior.CustomErrorPages, fingerprint.Behavior.JavaScriptChallenge)

	for key, value := range fingerprint.Headers {
		if isSecurityHeader(key) {
			report += fmt.Sprintf("  • %s: %s\n", key, value)
		}
	}

	report += fmt.Sprintf(`
RECOMMENDED EVASION TECHNIQUES:
`)

	evasions := GetOptimalEvasions(fingerprint.WAFType)
	for _, evasion := range evasions {
		report += fmt.Sprintf("  • %s\n", evasion)
	}

	report += "\n════════════════════════════════════════════════════════════════\n"

	return report
}

// isSecurityHeader checks if a header is security-related
func isSecurityHeader(header string) bool {
	securityHeaders := []string{
		"server", "x-powered-by", "x-frame-options", "x-content-type-options",
		"x-xss-protection", "content-security-policy", "strict-transport-security",
		"cf-ray", "x-amzn-requestid", "x-iinfo", "x-wa-info", "akamai-ghost-ip",
	}

	headerLower := strings.ToLower(header)
	for _, secHeader := range securityHeaders {
		if strings.Contains(headerLower, secHeader) {
			return true
		}
	}
	return false
}
