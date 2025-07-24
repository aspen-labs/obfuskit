package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"obfuskit/cmd"
	"obfuskit/constants"
	"obfuskit/report"
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

func main() {
	// Define command line flags
	levelFlag := flag.String("level", "medium", "Evasion level: basic, medium, or advanced")
	helpFlag := flag.Bool("help", false, "Show help information")
	flag.Parse()

	// Show help if requested
	if *helpFlag {
		showHelp()
		return
	}

	// Parse evasion level from command line (will be overridden by interactive selection if provided)
	defaultEvasionLevel := parseEvasionLevel(*levelFlag)

	fmt.Println("=== WAF Efficacy Testing Tool ===")
	fmt.Printf("Default Evasion Level: %s\n", defaultEvasionLevel)
	fmt.Println("Initializing interactive configuration...")

	// Get user configuration through interactive UI
	finalSelection := cmd.GetFinalSelection()

	// Use interactive evasion level if provided, otherwise use command line default
	evasionLevel := defaultEvasionLevel
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

	var err error
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
		err = generateReports(testResults)
		if err != nil {
			log.Fatalf("Error generating reports: %v", err)
		}
	} else {
		fmt.Println("\n📝 Skipping report generation (payloads generated only)")
	}

	fmt.Println("\n✅ WAF testing completed successfully!")
}

// showHelp displays usage information
func showHelp() {
	fmt.Println("WAF Efficacy Testing Tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  obfuskit [flags]")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  -level string    Evasion level: basic, medium, or advanced (default: medium)")
	fmt.Println("  -help           Show this help information")
	fmt.Println("")
	fmt.Println("Evasion Levels:")
	fmt.Println("  basic      - Uses simple evasion techniques (fastest)")
	fmt.Println("  medium     - Uses moderate evasion techniques (balanced)")
	fmt.Println("  advanced   - Uses all available evasion techniques (comprehensive)")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  obfuskit                    # Run with medium evasion level")
	fmt.Println("  obfuskit -level basic       # Run with basic evasion level")
	fmt.Println("  obfuskit -level advanced    # Run with advanced evasion level")
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
		reportTypes = []string{"HTML", "Pretty Terminal", "PDF"}
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
		}
	}

	return nil
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
