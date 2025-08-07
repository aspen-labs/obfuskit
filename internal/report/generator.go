package report

import (
	"encoding/json"
	"fmt"
	"obfuskit/internal/model"
	"obfuskit/report"
	"obfuskit/types"
	"os"
	"strings"
	"time"
)

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

	for _, reqResult := range results.RequestResults {
		if !reqResult.Blocked {
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

	config, ok := results.Config.(*types.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	reportTypes := []types.ReportType{}
	if config.ReportType == types.ReportTypeAll {
		reportTypes = []types.ReportType{
			types.ReportTypeHTML,
			types.ReportTypePretty,
			types.ReportTypePDF,
			types.ReportTypeNuclei,
			types.ReportTypeJSON,
		}
	} else {
		reportTypes = []types.ReportType{config.ReportType}
	}

	for _, reportType := range reportTypes {
		switch reportType {
		case types.ReportTypeHTML:
			err := report.GenerateHTMLReport(results.RequestResults, "waf_test_report.html")
			if err != nil {
				fmt.Printf("Warning: Failed to generate HTML report: %v\n", err)
			} else {
				fmt.Println("✅ HTML report generated: waf_test_report.html")
			}
		case types.ReportTypePretty:
			report.PrintTerminalReport(results.RequestResults)
			fmt.Println("✅ Terminal report displayed above")
		case types.ReportTypePDF:
			err := report.GeneratePDFReport(results.RequestResults, "waf_test_report.pdf")
			if err != nil {
				fmt.Printf("Warning: Failed to generate PDF report: %v\n", err)
			} else {
				fmt.Println("✅ PDF report generated: waf_test_report.pdf")
			}
		case types.ReportTypeCSV:
			err := GenerateCSVReport(results)
			if err != nil {
				fmt.Printf("Warning: Failed to generate CSV report: %v\n", err)
			} else {
				fmt.Println("✅ CSV report generated: waf_test_report.csv")
			}
		case types.ReportTypeNuclei:
			err := report.GenerateNucleiTemplates(results.RequestResults, "nuclei_templates")
			if err != nil {
				fmt.Printf("Warning: Failed to generate nuclei templates: %v\n", err)
			} else {
				fmt.Println("✅ Nuclei templates generated in nuclei_templates/ directory")
			}
		case types.ReportTypeJSON:
			err := GenerateJSONReport(results)
			if err != nil {
				fmt.Printf("Warning: Failed to generate JSON report: %v\n", err)
			} else {
				fmt.Println("✅ JSON report generated: waf_test_report.json")
			}
		}
	}

	return nil
}

func GenerateNucleiTemplatesFromPayloads(results *model.TestResults, level types.EvasionLevel) error {
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
	return report.GenerateNucleiTemplatesFromPayloads(payloadResults, "nuclei_templates")
}

func GenerateCSVReport(results *model.TestResults) error {
	filename := "waf_test_report.csv"
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("Original Payload,Attack Type,Evasion Type,Variant,Level\n")
	if err != nil {
		return err
	}

	for _, result := range results.PayloadResults {
		for _, variant := range result.Variants {
			line := fmt.Sprintf("%q,%s,%s,%q\n",
				result.OriginalPayload,
				result.AttackType,
				result.EvasionType,
				variant)
			_, err = file.WriteString(line)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// JSONReport represents the structure for JSON output
type JSONReport struct {
	Metadata struct {
		Timestamp string `json:"timestamp"`
		Tool      string `json:"tool"`
		Version   string `json:"version"`
	} `json:"metadata"`
	Config struct {
		Action       string `json:"action"`
		AttackType   string `json:"attack_type"`
		EvasionLevel string `json:"evasion_level"`
		TargetURL    string `json:"target_url,omitempty"`
	} `json:"config"`
	Summary struct {
		TotalPayloads   int      `json:"total_payloads"`
		TotalVariants   int      `json:"total_variants"`
		SuccessfulTests int      `json:"successful_tests"`
		FailedTests     int      `json:"failed_tests"`
		SuccessRate     float64  `json:"success_rate"`
		AttackTypes     []string `json:"attack_types"`
		EvasionTypes    []string `json:"evasion_types"`
	} `json:"summary"`
	PayloadResults []struct {
		OriginalPayload string   `json:"original_payload"`
		AttackType      string   `json:"attack_type"`
		EvasionType     string   `json:"evasion_type"`
		Variants        []string `json:"variants"`
	} `json:"payload_results"`
	RequestResults []struct {
		Payload      string `json:"payload"`
		URL          string `json:"url"`
		Method       string `json:"method"`
		StatusCode   int    `json:"status_code"`
		Blocked      bool   `json:"blocked"`
		ResponseTime int64  `json:"response_time_ms"`
		Technique    string `json:"technique"`
		Part         string `json:"part"`
	} `json:"request_results,omitempty"`
}

func GenerateJSONReport(results *model.TestResults) error {
	filename := "waf_test_report.json"

	// Create JSON report structure
	jsonReport := JSONReport{}

	// Metadata
	jsonReport.Metadata.Timestamp = time.Now().Format(time.RFC3339)
	jsonReport.Metadata.Tool = "ObfusKit"
	jsonReport.Metadata.Version = "1.0.0"

	// Config
	if config, ok := results.Config.(*types.Config); ok {
		jsonReport.Config.Action = string(config.Action)
		jsonReport.Config.AttackType = string(config.AttackType)
		jsonReport.Config.EvasionLevel = string(config.EvasionLevel)
		jsonReport.Config.TargetURL = config.Target.URL
	}

	// Summary
	summary := &results.Summary
	jsonReport.Summary.TotalPayloads = summary.TotalPayloads
	jsonReport.Summary.TotalVariants = summary.TotalVariants
	jsonReport.Summary.SuccessfulTests = summary.SuccessfulTests
	jsonReport.Summary.FailedTests = summary.FailedTests
	jsonReport.Summary.AttackTypes = summary.AttackTypes
	jsonReport.Summary.EvasionTypes = summary.EvasionTypes

	if len(results.RequestResults) > 0 {
		jsonReport.Summary.SuccessRate = float64(summary.SuccessfulTests) / float64(len(results.RequestResults)) * 100
	}

	// Payload Results
	for _, result := range results.PayloadResults {
		jsonReport.PayloadResults = append(jsonReport.PayloadResults, struct {
			OriginalPayload string   `json:"original_payload"`
			AttackType      string   `json:"attack_type"`
			EvasionType     string   `json:"evasion_type"`
			Variants        []string `json:"variants"`
		}{
			OriginalPayload: result.OriginalPayload,
			AttackType:      result.AttackType,
			EvasionType:     result.EvasionType,
			Variants:        result.Variants,
		})
	}

	// Request Results
	for _, result := range results.RequestResults {
		jsonReport.RequestResults = append(jsonReport.RequestResults, struct {
			Payload      string `json:"payload"`
			URL          string `json:"url"`
			Method       string `json:"method"`
			StatusCode   int    `json:"status_code"`
			Blocked      bool   `json:"blocked"`
			ResponseTime int64  `json:"response_time_ms"`
			Technique    string `json:"technique"`
			Part         string `json:"part"`
		}{
			Payload:      result.Payload,
			URL:          result.Request.URI().String(),
			Method:       string(result.Request.Header.Method()),
			StatusCode:   result.StatusCode,
			Blocked:      result.Blocked,
			ResponseTime: result.ResponseTime.Milliseconds(),
			Technique:    result.EvasionTechnique,
			Part:         result.RequestPart,
		})
	}

	// Write JSON to file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonReport)
}
