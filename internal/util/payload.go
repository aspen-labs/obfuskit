package util

import (
	"bufio"
	"fmt"
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
