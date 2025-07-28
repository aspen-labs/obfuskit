package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"obfuskit/request"
)

// NucleiTemplate represents a nuclei template structure
type NucleiTemplate struct {
	ID       string              `yaml:"id"`
	Info     NucleiInfo          `yaml:"info"`
	Payloads map[string][]string `yaml:"payloads,omitempty"`
	Requests []NucleiRequest     `yaml:"requests"`
}

type NucleiInfo struct {
	Name        string   `yaml:"name"`
	Author      []string `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

type NucleiRequest struct {
	Method   string            `yaml:"method"`
	Path     []string          `yaml:"path"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Body     string            `yaml:"body,omitempty"`
	Matchers []NucleiMatcher   `yaml:"matchers"`
}

type NucleiMatcher struct {
	Type     string   `yaml:"type"`
	Status   []int    `yaml:"status,omitempty"`
	Words    []string `yaml:"words,omitempty"`
	Negative bool     `yaml:"negative,omitempty"`
}

// GenerateNucleiTemplates creates nuclei templates from test results
func GenerateNucleiTemplates(results []request.TestResult, outputPath string) error {
	if len(results) == 0 {
		return fmt.Errorf("no test results provided")
	}

	// Group results by attack type/payload pattern
	templates := generateTemplateGroups(results)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Generate individual template files
	for i, template := range templates {
		filename := fmt.Sprintf("%s/template_%d_%s.yaml", outputPath, i+1, sanitizeFilename(template.ID))
		if err := writeNucleiTemplate(template, filename); err != nil {
			return fmt.Errorf("failed to write template %s: %v", filename, err)
		}
	}

	// Generate a master template that includes all payloads
	masterTemplate := generateMasterTemplate(results)
	masterFilename := fmt.Sprintf("%s/master_template.yaml", outputPath)
	if err := writeNucleiTemplate(masterTemplate, masterFilename); err != nil {
		return fmt.Errorf("failed to write master template: %v", err)
	}

	return nil
}

// generateTemplateGroups creates nuclei templates grouped by attack patterns
func generateTemplateGroups(results []request.TestResult) []NucleiTemplate {
	var templates []NucleiTemplate

	// Group by evasion technique
	evasionGroups := make(map[string][]request.TestResult)
	for _, result := range results {
		key := result.EvasionTechnique
		if key == "" {
			key = "basic"
		}
		evasionGroups[key] = append(evasionGroups[key], result)
	}

	// Create template for each evasion group
	for evasionType, groupResults := range evasionGroups {
		template := NucleiTemplate{
			ID: fmt.Sprintf("waf-bypass-%s", strings.ToLower(evasionType)),
			Info: NucleiInfo{
				Name:        fmt.Sprintf("WAF Bypass - %s", evasionType),
				Author:      []string{"obfuskit"},
				Severity:    "high",
				Description: fmt.Sprintf("WAF bypass techniques using %s evasion methods", evasionType),
				Tags:        []string{"waf", "bypass", strings.ToLower(evasionType)},
			},
		}

		// Create requests for different injection points
		requests := generateRequestsForGroup(groupResults)
		template.Requests = requests

		templates = append(templates, template)
	}

	return templates
}

// generateRequestsForGroup creates nuclei requests for a group of results
func generateRequestsForGroup(results []request.TestResult) []NucleiRequest {
	var requests []NucleiRequest

	// Group by request part (header, query, body, etc.)
	partGroups := make(map[string][]request.TestResult)
	for _, result := range results {
		partGroups[result.RequestPart] = append(partGroups[result.RequestPart], result)
	}

	// Create requests for each injection point
	for requestPart, partResults := range partGroups {
		request := NucleiRequest{
			Method: "GET", // Default method
		}

		// Collect unique payloads
		payloadMap := make(map[string]bool)
		for _, result := range partResults {
			payloadMap[result.Payload] = true
		}

		var payloads []string
		for payload := range payloadMap {
			payloads = append(payloads, payload)
		}

		// Configure request based on injection point
		switch strings.ToLower(requestPart) {
		case "header":
			request.Headers = map[string]string{
				"X-Test-Header": "{{payload}}",
				"User-Agent":    "{{payload}}",
			}
			request.Path = []string{"/"}
		case "query":
			request.Path = []string{"/?param={{payload}}"}
		case "body":
			request.Method = "POST"
			request.Headers = map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
			request.Body = "param={{payload}}"
			request.Path = []string{"/"}
		default:
			request.Path = []string{"/{{payload}}"}
		}

		// Add matchers to detect successful bypass
		request.Matchers = []NucleiMatcher{
			{
				Type:     "status",
				Status:   []int{200, 201, 202},
				Negative: false,
			},
			{
				Type:     "status",
				Status:   []int{403, 406, 429},
				Negative: true,
			},
		}

		requests = append(requests, request)
	}

	return requests
}

// generateMasterTemplate creates a comprehensive template with all payloads
func generateMasterTemplate(results []request.TestResult) NucleiTemplate {
	template := NucleiTemplate{
		ID: "waf-bypass-comprehensive",
		Info: NucleiInfo{
			Name:        "WAF Bypass - Comprehensive Test",
			Author:      []string{"obfuskit"},
			Severity:    "high",
			Description: "Comprehensive WAF bypass test using multiple evasion techniques",
			Tags:        []string{"waf", "bypass", "comprehensive"},
		},
	}

	// Create requests for all injection points with all payloads
	requests := []NucleiRequest{
		// Query parameter injection
		{
			Method: "GET",
			Path:   []string{"/?test={{payload}}"},
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429}, Negative: true},
			},
		},
		// Header injection
		{
			Method: "GET",
			Path:   []string{"/"},
			Headers: map[string]string{
				"X-Test-Header": "{{payload}}",
			},
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429}, Negative: true},
			},
		},
		// Body injection
		{
			Method: "POST",
			Path:   []string{"/"},
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: "param={{payload}}",
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429}, Negative: true},
			},
		},
	}

	template.Requests = requests
	return template
}

// writeNucleiTemplate writes a nuclei template to a YAML file
func writeNucleiTemplate(template NucleiTemplate, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write YAML content manually (avoiding external YAML library dependency)
	yamlContent := generateYAMLContent(template)
	_, err = file.WriteString(yamlContent)
	return err
}

// generateYAMLContent creates YAML content for the nuclei template
func generateYAMLContent(template NucleiTemplate) string {
	var builder strings.Builder

	// Template header comment
	builder.WriteString(fmt.Sprintf("# Generated by obfuskit on %s\n", time.Now().Format("2006-01-02 15:04:05")))
	builder.WriteString("# WAF Bypass Nuclei Template\n\n")

	// Template ID
	builder.WriteString(fmt.Sprintf("id: %s\n\n", template.ID))

	// Info section
	builder.WriteString("info:\n")
	builder.WriteString(fmt.Sprintf("  name: \"%s\"\n", template.Info.Name))
	builder.WriteString("  author:\n")
	for _, author := range template.Info.Author {
		builder.WriteString(fmt.Sprintf("    - %s\n", author))
	}
	builder.WriteString(fmt.Sprintf("  severity: %s\n", template.Info.Severity))
	builder.WriteString(fmt.Sprintf("  description: \"%s\"\n", template.Info.Description))
	builder.WriteString("  tags:\n")
	for _, tag := range template.Info.Tags {
		builder.WriteString(fmt.Sprintf("    - %s\n", tag))
	}
	builder.WriteString("\n")

	// Payloads section
	if len(template.Payloads) > 0 {
		builder.WriteString("payloads:\n")
		for key, payloads := range template.Payloads {
			builder.WriteString(fmt.Sprintf("  %s:\n", key))
			for _, payload := range payloads {
				// Escape quotes and special characters in payloads
				escapedPayload := strings.ReplaceAll(payload, "\"", "\\\"")
				escapedPayload = strings.ReplaceAll(escapedPayload, "\n", "\\n")
				builder.WriteString(fmt.Sprintf("    - \"%s\"\n", escapedPayload))
			}
		}
		builder.WriteString("\n")
	}

	// Requests section
	builder.WriteString("requests:\n")
	for _, req := range template.Requests {
		builder.WriteString(fmt.Sprintf("  - method: %s\n", req.Method))
		builder.WriteString("    path:\n")
		for _, path := range req.Path {
			builder.WriteString(fmt.Sprintf("      - \"%s\"\n", path))
		}

		// Headers
		if len(req.Headers) > 0 {
			builder.WriteString("    headers:\n")
			for key, value := range req.Headers {
				builder.WriteString(fmt.Sprintf("      %s: \"%s\"\n", key, value))
			}
		}

		// Body
		if req.Body != "" {
			builder.WriteString(fmt.Sprintf("    body: \"%s\"\n", req.Body))
		}

		// Matchers
		builder.WriteString("    matchers:\n")
		for _, matcher := range req.Matchers {
			builder.WriteString(fmt.Sprintf("      - type: %s\n", matcher.Type))
			if len(matcher.Status) > 0 {
				builder.WriteString("        status:\n")
				for _, status := range matcher.Status {
					builder.WriteString(fmt.Sprintf("          - %d\n", status))
				}
			}
			if len(matcher.Words) > 0 {
				builder.WriteString("        words:\n")
				for _, word := range matcher.Words {
					builder.WriteString(fmt.Sprintf("          - \"%s\"\n", word))
				}
			}
			if matcher.Negative {
				builder.WriteString("        negative: true\n")
			}
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// sanitizeFilename removes invalid characters from filename
func sanitizeFilename(filename string) string {
	// Replace invalid filename characters
	replacer := strings.NewReplacer(
		" ", "_",
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return strings.ToLower(replacer.Replace(filename))
}

// PayloadResult represents a payload with its metadata for nuclei template generation
type PayloadResult struct {
	OriginalPayload string
	AttackType      string
	EvasionType     string
	Variants        []string
	Level           string
}

// GenerateNucleiTemplatesFromPayloads creates nuclei templates from payload results
func GenerateNucleiTemplatesFromPayloads(payloadResults []PayloadResult, outputPath string) error {
	if len(payloadResults) == 0 {
		return fmt.Errorf("no payload results provided")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Group payloads by attack type and evasion type
	templates := generateTemplateGroupsFromPayloads(payloadResults)

	// Generate individual template files
	for i, template := range templates {
		filename := fmt.Sprintf("%s/template_%d_%s.yaml", outputPath, i+1, sanitizeFilename(template.ID))
		if err := writeNucleiTemplate(template, filename); err != nil {
			return fmt.Errorf("failed to write template %s: %v", filename, err)
		}
	}

	// Generate a comprehensive master template
	masterTemplate := generateMasterTemplateFromPayloads(payloadResults)
	masterFilename := fmt.Sprintf("%s/master_template.yaml", outputPath)
	if err := writeNucleiTemplate(masterTemplate, masterFilename); err != nil {
		return fmt.Errorf("failed to write master template: %v", err)
	}

	return nil
}

// generateTemplateGroupsFromPayloads creates nuclei templates grouped by attack and evasion type
func generateTemplateGroupsFromPayloads(payloadResults []PayloadResult) []NucleiTemplate {
	var templates []NucleiTemplate

	// Group by attack type and evasion type combination
	groups := make(map[string][]PayloadResult)
	for _, result := range payloadResults {
		key := fmt.Sprintf("%s_%s", result.AttackType, result.EvasionType)
		groups[key] = append(groups[key], result)
	}

	// Create template for each group
	for _, groupResults := range groups {
		if len(groupResults) == 0 {
			continue
		}

		first := groupResults[0]
		template := NucleiTemplate{
			ID: fmt.Sprintf("waf-bypass-%s-%s",
				strings.ToLower(first.AttackType),
				strings.ToLower(first.EvasionType)),
			Info: NucleiInfo{
				Name:        fmt.Sprintf("WAF Bypass - %s using %s", first.AttackType, first.EvasionType),
				Author:      []string{"obfuskit"},
				Severity:    "high",
				Description: fmt.Sprintf("WAF bypass for %s attacks using %s evasion techniques", first.AttackType, first.EvasionType),
				Tags:        []string{"waf", "bypass", strings.ToLower(first.AttackType), strings.ToLower(first.EvasionType)},
			},
		}

		// Collect all variants from this group
		var allPayloads []string
		for _, result := range groupResults {
			allPayloads = append(allPayloads, result.Variants...)
		}

		// Add payloads section
		template.Payloads = map[string][]string{
			"payload": allPayloads,
		}

		// Create requests for different injection points
		requests := generateRequestsForPayloads(allPayloads, first.AttackType)
		template.Requests = requests

		templates = append(templates, template)
	}

	return templates
}

// generateRequestsForPayloads creates nuclei requests for given payloads
func generateRequestsForPayloads(payloads []string, attackType string) []NucleiRequest {
	var requests []NucleiRequest

	// Create templates for different injection points based on attack type
	injectionPoints := getInjectionPointsForAttackType(attackType)

	for _, injectionPoint := range injectionPoints {
		request := NucleiRequest{}

		switch injectionPoint {
		case "header":
			request.Method = "GET"
			request.Path = []string{"/"}
			request.Headers = map[string]string{
				"X-Test-Header":   "{{payload}}",
				"User-Agent":      "{{payload}}",
				"X-Forwarded-For": "{{payload}}",
				"X-Real-IP":       "{{payload}}",
			}
		case "query":
			request.Method = "GET"
			request.Path = []string{"/?test={{payload}}", "/?q={{payload}}", "/?search={{payload}}"}
		case "body":
			request.Method = "POST"
			request.Path = []string{"/"}
			request.Headers = map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
			request.Body = "param={{payload}}&test={{payload}}"
		case "json":
			request.Method = "POST"
			request.Path = []string{"/"}
			request.Headers = map[string]string{
				"Content-Type": "application/json",
			}
			request.Body = `{"test": "{{payload}}", "param": "{{payload}}"}`
		default:
			request.Method = "GET"
			request.Path = []string{"/{{payload}}"}
		}

		// Add matchers to detect successful bypass
		request.Matchers = []NucleiMatcher{
			{
				Type:     "status",
				Status:   []int{200, 201, 202},
				Negative: false,
			},
			{
				Type:     "status",
				Status:   []int{403, 406, 429, 451},
				Negative: true,
			},
		}

		requests = append(requests, request)
	}

	return requests
}

// getInjectionPointsForAttackType returns appropriate injection points for attack type
func getInjectionPointsForAttackType(attackType string) []string {
	switch strings.ToLower(attackType) {
	case "xss":
		return []string{"query", "body", "header"}
	case "sqli":
		return []string{"query", "body", "json"}
	case "unixcmdi", "windowscmdi":
		return []string{"query", "body", "header"}
	case "lfi", "rfi":
		return []string{"query", "body"}
	default:
		return []string{"query", "body", "header"}
	}
}

// generateMasterTemplateFromPayloads creates a comprehensive template with all payloads
func generateMasterTemplateFromPayloads(payloadResults []PayloadResult) NucleiTemplate {
	template := NucleiTemplate{
		ID: "waf-bypass-comprehensive-payloads",
		Info: NucleiInfo{
			Name:        "WAF Bypass - Comprehensive Payload Test",
			Author:      []string{"obfuskit"},
			Severity:    "high",
			Description: "Comprehensive WAF bypass test using generated payloads with multiple evasion techniques",
			Tags:        []string{"waf", "bypass", "comprehensive", "payloads"},
		},
	}

	// Collect all payloads from all results
	var allPayloads []string
	for _, result := range payloadResults {
		allPayloads = append(allPayloads, result.Variants...)
	}

	// Add payloads section
	template.Payloads = map[string][]string{
		"payload": allPayloads,
	}

	// Create requests for all common injection points
	requests := []NucleiRequest{
		// Query parameter injection
		{
			Method: "GET",
			Path:   []string{"/?test={{payload}}", "/?q={{payload}}", "/?search={{payload}}"},
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429, 451}, Negative: true},
			},
		},
		// Header injection
		{
			Method: "GET",
			Path:   []string{"/"},
			Headers: map[string]string{
				"X-Test-Header":   "{{payload}}",
				"User-Agent":      "{{payload}}",
				"X-Forwarded-For": "{{payload}}",
			},
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429, 451}, Negative: true},
			},
		},
		// Form body injection
		{
			Method: "POST",
			Path:   []string{"/"},
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: "param={{payload}}&test={{payload}}",
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429, 451}, Negative: true},
			},
		},
		// JSON body injection
		{
			Method: "POST",
			Path:   []string{"/"},
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: `{"test": "{{payload}}", "param": "{{payload}}"}`,
			Matchers: []NucleiMatcher{
				{Type: "status", Status: []int{200, 201, 202}},
				{Type: "status", Status: []int{403, 406, 429, 451}, Negative: true},
			},
		},
	}

	template.Requests = requests
	return template
}
