package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"obfuskit/cmd"
	"obfuskit/constants"
	"obfuskit/report"
	"obfuskit/request"

	"gopkg.in/yaml.v3"
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
	Config         cmd.Model
	PayloadResults []PayloadResults
	RequestResults []request.TestResult // Using the actual TestResult type from request package
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
// Example: {"method":"GET", "url":"http://target", "headers":{"X-Test":"1"}, "body":"..."}
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

// ServerHandler is a struct handler for Burp integration
type ServerHandler struct {
	Config *cmd.Config
}

func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	processServerRequestHandler(w, r, h.Config)
}

func main() {
	// Define command line flags
	helpFlag := flag.Bool("help", false, "Show help information")
	configFlag := flag.String("config", "", "Path to configuration file (YAML or JSON)")
	generateConfigFlag := flag.String("generate-config", "", "Generate example config file (yaml or json)")
	serverFlag := flag.Bool("server", false, "Start integration webservice")
	flag.Parse()

	// Show help if requested
	if *helpFlag {
		showHelp()
		return
	}

	// Generate example config if requested
	if *generateConfigFlag != "" {
		err := generateExampleConfig(*generateConfigFlag)
		if err != nil {
			log.Fatalf("Error generating config: %v", err)
		}
		return
	}

	// Start integration webservice if requested
	if *serverFlag {
		var config *cmd.Config
		if *configFlag != "" {
			var configErr error
			config, configErr = cmd.LoadConfig(*configFlag)
			if configErr != nil {
				log.Fatalf("Error loading config: %v", configErr)
			}
			configErr = cmd.ValidateConfig(config)
			if configErr != nil {
				log.Fatalf("Invalid config: %v", configErr)
			}
		}

		handler := &ServerHandler{Config: config}
		http.Handle("/api/payloads", handler)
		log.Println("[+] Integration webservice listening on :8181 (/api/payloads)")
		if err := http.ListenAndServe(":8181", nil); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
		return
	}

	fmt.Println("=== Obfuskit. A WAF Efficacy Testing Tool ===")

	var finalSelection cmd.Model
	var err error

	// Load configuration from file or use interactive mode
	if *configFlag != "" {
		fmt.Printf("Loading configuration from: %s\n", *configFlag)
		config, configErr := cmd.LoadConfig(*configFlag)
		if configErr != nil {
			log.Fatalf("Error loading config: %v", configErr)
		}

		configErr = cmd.ValidateConfig(config)
		if configErr != nil {
			log.Fatalf("Invalid config: %v", configErr)
		}

		finalSelection = cmd.ConvertConfigToModel(config)
		fmt.Println("Configuration loaded successfully!")
	} else {
		fmt.Println("Initializing interactive configuration...")
		// Get user configuration through interactive UI
		finalSelection = cmd.GetFinalSelection()
	}

	// Use evasion level from interactive selection (default to Medium if not set)
	evasionLevel := constants.Medium
	if finalSelection.SelectedEvasionLevel != "" {
		evasionLevel = parseEvasionLevel(finalSelection.SelectedEvasionLevel)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("CONFIGURATION SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Action: %s\n", finalSelection.Selection)
	fmt.Printf("Attack: %s\n", finalSelection.SelectedAttack)
	fmt.Printf("Payload: %s\n", finalSelection.SelectedPayload)
	fmt.Printf("Evasion Level: %s\n", evasionLevel)
	fmt.Printf("Target: %s\n", finalSelection.SelectedTarget)
	fmt.Printf("Report: %s\n", finalSelection.SelectedReportType)
	fmt.Printf("URL: %s\n", finalSelection.URL)
	fmt.Println(strings.Repeat("=", 60))

	// Generate payloads based on configuration
	testResults := &TestResults{
		Config: finalSelection,
	}

	switch finalSelection.Selection {
	case "Generate Payloads":
		err = handleGeneratePayloads(testResults, evasionLevel)
	case "Send to URL":
		err = handleSendToURL(testResults, evasionLevel)
	case "Use Existing Payloads":
		err = handleExistingPayloads(testResults, evasionLevel)
	default:
		err = fmt.Errorf("unknown selection: %s", finalSelection.Selection)
	}

	if err != nil {
		log.Fatalf("Error processing selection: %v", err)
	}

	// Generate summary
	generateSummary(testResults)

	// Generate reports only if we ran tests (not just generating payloads)
	if finalSelection.Selection != "Generate Payloads" {
		reportErr := generateReports(testResults)
		if reportErr != nil {
			log.Fatalf("Error generating reports: %v", reportErr)
		}
	} else {
		fmt.Println("\n📝 Skipping report generation (payloads generated only)")
	}

	fmt.Println("\n✅ WAF testing completed successfully!")
}

// processServerRequestHandler handles POST requests from Burp
func processServerRequestHandler(w http.ResponseWriter, r *http.Request, config *cmd.Config) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST supported", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received Burp request")
	var req BurpRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	payload := req.Payload
	attackType := detectAttackType(payload)

	// Load config.yaml for evasion level if available
	level := constants.Medium // default
	if config != nil {
		attackType = config.Attack.Type
		level = parseEvasionLevel(config.Evasion.Level)
	}

	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		log.Println("No evasions found for attack type: ", attackType)
		evasions = []string{"Base64Variants", "HexVariants", "UnicodeVariants"}
	}

	var results []BurpEvadedPayload
	for _, evasionType := range evasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			continue
		}
		for _, variant := range variants {
			results = append(results, BurpEvadedPayload{
				OriginalPayload: payload,
				AttackType:      attackType,
				EvasionType:     evasionType,
				Level:           level,
				Variant:         variant,
			})
		}
	}

	resp := BurpResponse{
		Status:   "ok",
		Payloads: results,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// yamlUnmarshal is a helper to unmarshal YAML config
func yamlUnmarshal(data []byte, out interface{}) error {
	type yamlUnmarshalFunc func([]byte, interface{}) error
	var fn yamlUnmarshalFunc
	if y, err := importYAML(); err == nil {
		fn = y
	} else {
		return err
	}
	return fn(data, out)
}

// importYAML tries to import yaml.v2
func importYAML() (func([]byte, interface{}) error, error) {
	// Use reflection to avoid hard dependency if needed
	return yaml.Unmarshal, nil // assuming yaml is imported
}

// showHelp displays usage information
func showHelp() {
	fmt.Println("Obfuskit. A WAF Efficacy Testing Tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  obfuskit [flags]")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  -help                    Show this help information")
	fmt.Println("  -config <file>           Use configuration file (YAML or JSON)")
	fmt.Println("  -generate-config <fmt>   Generate example config (yaml or json)")
	fmt.Println("")
	fmt.Println("Features:")
	fmt.Println("  • Interactive menu-driven interface")
	fmt.Println("  • Configuration file support (YAML/JSON)")
	fmt.Println("  • Multiple evasion levels (Basic, Medium, Advanced)")
	fmt.Println("  • Support for various attack types (XSS, SQLi, Command Injection, etc.)")
	fmt.Println("  • Multiple encoding options")
	fmt.Println("  • Payload generation and testing capabilities")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  obfuskit                            # Run with interactive interface")
	fmt.Println("  obfuskit -config config.yaml        # Run with config file")
	fmt.Println("  obfuskit -generate-config yaml      # Generate example YAML config")
	fmt.Println("  obfuskit -generate-config json      # Generate example JSON config")
	fmt.Println("  obfuskit -burp                      # Run Burp integration webservice")
}

// generateExampleConfig generates and saves an example configuration file
func generateExampleConfig(format string) error {
	data, err := cmd.GenerateExampleConfig(format)
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	filename := fmt.Sprintf("config.%s", format)
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("✅ Example %s configuration generated: %s\n", strings.ToUpper(format), filename)
	fmt.Println("\nTo use this config file, run:")
	fmt.Printf("  obfuskit -config %s\n", filename)
	return nil
}

// parseEvasionLevel converts string level to constants.Level
func parseEvasionLevel(level string) constants.Level {
	switch strings.ToLower(level) {
	case "basic":
		return constants.Basic
	case "medium":
		return constants.Medium
	case "advanced":
		return constants.Advanced
	default:
		fmt.Printf("Warning: Unknown evasion level '%s', using 'medium' as default\n", level)
		return constants.Medium
	}
}

func handleGeneratePayloads(results *TestResults, level constants.Level) error {
	fmt.Println("\n🔧 Generating payloads...")

	// Load base payloads
	basePayloads, err := loadBasePayloads(results.Config.SelectedAttack)
	if err != nil {
		return fmt.Errorf("failed to load base payloads: %v", err)
	}

	// Generate variants for each base payload
	for attackType, payloads := range basePayloads {
		for _, payload := range payloads {
			if err := generateVariantsForPayload(results, payload, attackType, level); err != nil {
				return err
			}
		}
	}

	fmt.Printf("✅ Generated %d payload variants across %d base payloads\n",
		getTotalVariants(results), len(results.PayloadResults))

	// Save payloads to file
	if err := savePayloadsToFile(results); err != nil {
		fmt.Printf("Warning: Failed to save payloads to file: %v\n", err)
	} else {
		fmt.Println("✅ Payloads saved to:")
		fmt.Println("  - payloads_output.txt (detailed with metadata)")
		fmt.Println("  - payloads_simple.txt (one payload per line)")
	}

	// Generate nuclei templates from payloads
	if err := generateNucleiTemplatesFromPayloads(results, level); err != nil {
		fmt.Printf("Warning: Failed to generate nuclei templates: %v\n", err)
	} else {
		fmt.Println("✅ Nuclei templates generated in nuclei_templates/ directory")
	}

	return nil
}

func handleSendToURL(results *TestResults, level constants.Level) error {
	fmt.Println("\n🌐 Generating payloads and sending to URL...")

	// First generate the payloads
	err := handleGeneratePayloads(results, level)
	if err != nil {
		return err
	}

	// Then send them to the target URL
	fmt.Printf("🚀 Sending %d payload variants to %s\n", getTotalVariants(results), results.Config.URL)

	for i, payloadResult := range results.PayloadResults {
		for j, variant := range payloadResult.Variants {
			fmt.Printf("Testing payload %d/%d variant %d/%d\r",
				i+1, len(results.PayloadResults), j+1, len(payloadResult.Variants))

			// Send request using the available request package functions
			// Create a logger for the request
			logger := request.NewLogger(os.Stdout)

			// Test this single variant
			injectors := []request.FastHTTPInjector{
				request.NewFastHTTPHeaderInjector(),
				request.NewFastHTTPQueryInjector(),
				request.NewFastHTTPBodyInjector(),
				request.NewFastHTTPProtocolInjector(),
			}

			for _, injector := range injectors {
				testResults := injector.Inject(results.Config.URL, variant, logger)
				results.RequestResults = append(results.RequestResults, testResults...)
			}
		}
	}

	fmt.Printf("\n✅ Completed testing %d payloads against target\n", getTotalVariants(results))
	return nil
}

func handleExistingPayloads(results *TestResults, level constants.Level) error {
	fmt.Println("\n📁 Processing existing payloads...")

	var payloads []string
	var err error

	switch results.Config.SelectedPayloadSource {
	case "From File":
		payloads, err = loadPayloadsFromFile(results.Config.PayloadFilePath)
		if err != nil {
			return fmt.Errorf("failed to load payloads from file: %w", err)
		}
	case "Enter Manually":
		payloads = results.Config.CustomPayloads
	default:
		return fmt.Errorf("unknown payload source: %s", results.Config.SelectedPayloadSource)
	}

	// Process each existing payload
	for _, payload := range payloads {
		// Try to detect attack type or use a generic approach
		attackType := detectAttackType(payload)
		err := generateVariantsForPayload(results, payload, attackType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to generate variants for payload '%s': %v\n", payload, err)
			continue
		}
	}

	fmt.Printf("✅ Processed %d existing payloads into %d variants\n",
		len(payloads), getTotalVariants(results))

	return nil
}

func loadBasePayloads(attackType string) (map[string][]string, error) {
	payloads := make(map[string][]string)

	attackTypes := []string{}
	if attackType == "All" {
		attackTypes = []string{"xss", "sqli", "unixcmdi", "wincmdi", "path", "fileaccess", "ldapi"}
	} else {
		// Map UI attack names to payload file names
		attackTypeMap := map[string]string{
			"XSS":               "xss",
			"SQLi":              "sqli",
			"Command Injection": "unixcmdi", // Default to unix, could be made smarter
			"LFI":               "fileaccess",
			"RFI":               "fileaccess",
			"SSRF":              "ldapi", // Or create separate SSRF payloads
			"XXE":               "ldapi", // Or create separate XXE payloads
		}

		if mappedType, exists := attackTypeMap[attackType]; exists {
			attackTypes = []string{mappedType}
		} else {
			attackTypes = []string{strings.ToLower(attackType)}
		}
	}

	for _, aType := range attackTypes {
		filePath := filepath.Join("payloads", aType+".txt")
		filePayloads, err := loadPayloadsFromFile(filePath)
		if err != nil {
			fmt.Printf("Warning: Could not load payloads for %s: %v\n", aType, err)
			continue
		}
		payloads[aType] = filePayloads
	}

	if len(payloads) == 0 {
		return nil, fmt.Errorf("no payloads could be loaded for attack type: %s", attackType)
	}

	return payloads, nil
}

func loadPayloadsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { // Skip empty lines and comments
			payloads = append(payloads, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return payloads, nil
}

func generateVariantsForPayload(results *TestResults, payload, attackType string, level constants.Level) error {

	// Get applicable evasions for this attack type
	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		// Fallback to generic evasions
		evasions = []string{"Base64Variants", "HexVariants", "UnicodeVariants"}
	}

	// Filter evasions based on user selection
	filteredEvasions := filterEvasions(evasions, results.Config)

	for _, evasionType := range filteredEvasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to apply %s to payload: %v\n", evasionType, err)
			continue
		}

		if len(variants) > 0 {
			results.PayloadResults = append(results.PayloadResults, PayloadResults{
				OriginalPayload: payload,
				AttackType:      attackType,
				EvasionType:     evasionType,
				Variants:        variants,
				Level:           level,
			})
		}
	}

	return nil
}

func filterEvasions(evasions []string, config cmd.Model) []string {
	// If user selected "All", return all evasions
	if config.SelectedPayload == "All" {
		return evasions
	}

	// Filter based on user's specific selections
	var filtered []string

	switch config.SelectedPayload {
	case "Encodings":
		encodingTypes := map[string]bool{
			"Base64Variants": true, "HexVariants": true, "HTMLVariants": true,
			"UnicodeVariants": true, "OctalVariants": true, "BestFitVariants": true,
		}
		for _, evasion := range evasions {
			if encodingTypes[evasion] {
				filtered = append(filtered, evasion)
			}
		}
	case "Paths":
		for _, evasion := range evasions {
			if evasion == "PathTraversalVariants" {
				filtered = append(filtered, evasion)
			}
		}
	case "Commands":
		commandTypes := map[string]bool{
			"UnixCmdVariants": true, "WindowsCmdVariants": true,
		}
		for _, evasion := range evasions {
			if commandTypes[evasion] {
				filtered = append(filtered, evasion)
			}
		}
	default:
		// If no specific filter, return all
		filtered = evasions
	}

	return filtered
}

func detectAttackType(payload string) string {
	payload = strings.ToLower(payload)

	// Simple heuristics to detect attack type
	if strings.Contains(payload, "<script") || strings.Contains(payload, "javascript:") ||
		strings.Contains(payload, "onerror") || strings.Contains(payload, "onload") {
		return "xss"
	}
	if strings.Contains(payload, "union") || strings.Contains(payload, "select") ||
		strings.Contains(payload, "' or ") || strings.Contains(payload, "1=1") {
		return "sqli"
	}
	if strings.Contains(payload, "../") || strings.Contains(payload, "..\\") ||
		strings.Contains(payload, "/etc/passwd") || strings.Contains(payload, "c:\\windows") {
		return "path"
	}
	if strings.Contains(payload, "cmd") || strings.Contains(payload, "bash") ||
		strings.Contains(payload, "powershell") || strings.Contains(payload, "wget") {
		return "unixcmdi"
	}

	// Default to generic if we can't detect
	return "generic"
}

func generateSummary(results *TestResults) {
	summary := &results.Summary
	summary.TotalPayloads = len(results.PayloadResults)

	attackTypes := make(map[string]bool)
	evasionTypes := make(map[string]bool)

	for _, result := range results.PayloadResults {
		summary.TotalVariants += len(result.Variants)
		attackTypes[result.AttackType] = true
		evasionTypes[result.EvasionType] = true
	}

	for attackType := range attackTypes {
		summary.AttackTypes = append(summary.AttackTypes, attackType)
	}
	for evasionType := range evasionTypes {
		summary.EvasionTypes = append(summary.EvasionTypes, evasionType)
	}

	// Count successful/failed tests if we have request results
	for _, reqResult := range results.RequestResults {
		if !reqResult.Blocked { // TestResult uses Blocked field (inverted logic)
			summary.SuccessfulTests++
		} else {
			summary.FailedTests++
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("TEST SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total Base Payloads: %d\n", summary.TotalPayloads)
	fmt.Printf("Total Variants Generated: %d\n", summary.TotalVariants)
	fmt.Printf("Attack Types: %s\n", strings.Join(summary.AttackTypes, ", "))
	fmt.Printf("Evasion Types: %s\n", strings.Join(summary.EvasionTypes, ", "))

	if len(results.RequestResults) > 0 {
		fmt.Printf("Successful Tests: %d\n", summary.SuccessfulTests)
		fmt.Printf("Failed Tests: %d\n", summary.FailedTests)
		fmt.Printf("Success Rate: %.2f%%\n",
			float64(summary.SuccessfulTests)/float64(len(results.RequestResults))*100)
	}
	fmt.Println(strings.Repeat("=", 60))
}

func generateReports(results *TestResults) error {
	fmt.Println("\n📊 Generating reports...")

	reportTypes := []string{}
	if results.Config.SelectedReportType == "All" {
		reportTypes = []string{"HTML", "Pretty Terminal", "PDF", "Nuclei Templates"}
	} else {
		reportTypes = []string{results.Config.SelectedReportType}
	}

	for _, reportType := range reportTypes {
		switch reportType {
		case "HTML":
			err := report.GenerateHTMLReport(results.RequestResults, "waf_test_report.html")
			if err != nil {
				fmt.Printf("Warning: Failed to generate HTML report: %v\n", err)
			} else {
				fmt.Println("✅ HTML report generated: waf_test_report.html")
			}
		case "Pretty Terminal":
			report.PrintTerminalReport(results.RequestResults)
			fmt.Println("✅ Terminal report displayed above")
		case "PDF":
			err := report.GeneratePDFReport(results.RequestResults, "waf_test_report.pdf")
			if err != nil {
				fmt.Printf("Warning: Failed to generate PDF report: %v\n", err)
			} else {
				fmt.Println("✅ PDF report generated: waf_test_report.pdf")
			}
		case "CSV":
			err := generateCSVReport(results)
			if err != nil {
				fmt.Printf("Warning: Failed to generate CSV report: %v\n", err)
			} else {
				fmt.Println("✅ CSV report generated: waf_test_report.csv")
			}
		case "Nuclei Templates":
			err := report.GenerateNucleiTemplates(results.RequestResults, "nuclei_templates")
			if err != nil {
				fmt.Printf("Warning: Failed to generate nuclei templates: %v\n", err)
			} else {
				fmt.Println("✅ Nuclei templates generated in nuclei_templates/ directory")
			}
		}
	}

	return nil
}

// generateNucleiTemplatesFromPayloads converts payload results to nuclei templates
func generateNucleiTemplatesFromPayloads(results *TestResults, level constants.Level) error {
	// Convert TestResults.PayloadResults to report.PayloadResult format
	var payloadResults []report.PayloadResult
	for _, payloadResult := range results.PayloadResults {
		payloadResults = append(payloadResults, report.PayloadResult{
			OriginalPayload: payloadResult.OriginalPayload,
			AttackType:      payloadResult.AttackType,
			EvasionType:     payloadResult.EvasionType,
			Variants:        payloadResult.Variants,
			Level:           string(level),
		})
	}

	// Generate nuclei templates
	return report.GenerateNucleiTemplatesFromPayloads(payloadResults, "nuclei_templates")
}

func generateCSVReport(results *TestResults) error {
	filename := "waf_test_report.csv"
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write CSV header
	_, err = file.WriteString("Original Payload,Attack Type,Evasion Type,Variant,Level\n")
	if err != nil {
		return err
	}

	// Write data
	for _, result := range results.PayloadResults {
		for _, variant := range result.Variants {
			line := fmt.Sprintf("%q,%s,%s,%q,%s\n",
				result.OriginalPayload,
				result.AttackType,
				result.EvasionType,
				variant,
				result.Level)
			_, err = file.WriteString(line)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getTotalVariants(results *TestResults) int {
	total := 0
	for _, result := range results.PayloadResults {
		total += len(result.Variants)
	}
	return total
}

// savePayloadsToFile saves all generated payloads to text files
func savePayloadsToFile(results *TestResults) error {
	// Create detailed output file
	file, err := os.Create("payloads_output.txt")
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	fmt.Fprintf(writer, "# Generated Payloads - %s\n", fmt.Sprintf("%d payloads", len(results.PayloadResults)))
	fmt.Fprintf(writer, "# Generated at: %s\n\n", "2025-07-25")

	// Write payloads organized by attack type and evasion type
	for _, payloadResult := range results.PayloadResults {
		fmt.Fprintf(writer, "## Attack Type: %s\n", payloadResult.AttackType)
		fmt.Fprintf(writer, "## Evasion Type: %s\n", payloadResult.EvasionType)
		fmt.Fprintf(writer, "## Original Payload: %s\n\n", payloadResult.OriginalPayload)

		for _, variant := range payloadResult.Variants {
			fmt.Fprintf(writer, "%s\n", variant)
		}
		fmt.Fprintf(writer, "\n---\n\n")
	}

	// Create simple payloads-only file
	simpleFile, err := os.Create("payloads_simple.txt")
	if err != nil {
		return fmt.Errorf("failed to create simple file: %v", err)
	}
	defer simpleFile.Close()

	simpleWriter := bufio.NewWriter(simpleFile)
	defer simpleWriter.Flush()

	// Write only the payload variants, one per line
	for _, payloadResult := range results.PayloadResults {
		for _, variant := range payloadResult.Variants {
			fmt.Fprintf(simpleWriter, "%s\n", variant)
		}
	}

	return nil
}
