package util

import (
	"bufio"
	"fmt"
	"obfuskit/cmd"
	"obfuskit/internal/constants"
	"obfuskit/internal/model"
	"obfuskit/report"
	"os"
	"path/filepath"
	"strings"
)

func LoadBasePayloads(attackType string) (map[string][]string, error) {
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
		filePayloads, err := LoadPayloadsFromFile(filePath)
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

func LoadPayloadsFromFile(filePath string) ([]string, error) {
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

func GenerateVariantsForPayload(results *model.TestResults, payload, attackType string, level constants.Level) error {

	config, ok := results.Config.(*cmd.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	// Get applicable evasions for this attack type
	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		// Fallback to generic evasions
		evasions = []string{"Base64Variants", "HexVariants", "UnicodeVariants"}
	}

	// Filter evasions based on user selection
	filteredEvasions := filterEvasions(evasions, config)

	for _, evasionType := range filteredEvasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to apply %s to payload: %v\n", evasionType, err)
			continue
		}

		if len(variants) > 0 {
			results.PayloadResults = append(results.PayloadResults, model.PayloadResults{
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

func filterEvasions(evasions []string, config *cmd.Config) []string {
	// If user selected "All", return all evasions
	if config.Payload.Method == "All" {
		return evasions
	}

	// Filter based on user's specific selections
	var filtered []string

	switch config.Payload.Method {
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

func GenerateSummary(results *model.TestResults) {
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

func GenerateReports(results *model.TestResults) error {
	fmt.Println("\n📊 Generating reports...")

	config, ok := results.Config.(*cmd.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	reportTypes := []string{}
	if config.Report.Type == "All" {
		reportTypes = []string{"HTML", "Pretty Terminal", "PDF", "Nuclei Templates"}
	} else {
		reportTypes = []string{config.Report.Type}
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
			err := GenerateCSVReport(results)
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
func GenerateNucleiTemplatesFromPayloads(results *model.TestResults, level constants.Level) error {
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

func GenerateCSVReport(results *model.TestResults) error {
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

func GetTotalVariants(results *model.TestResults) int {
	total := 0
	for _, result := range results.PayloadResults {
		total += len(result.Variants)
	}
	return total
}

// savePayloadsToFile saves all generated payloads to text files
func SavePayloadsToFile(results *model.TestResults) error {
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
