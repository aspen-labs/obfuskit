package report

import (
	"fmt"
	"obfuskit/constants"
	"obfuskit/internal/model"
	"obfuskit/report"
	"obfuskit/types"
	"os"
	"strings"
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
		}
	}

	return nil
}

func GenerateNucleiTemplatesFromPayloads(results *model.TestResults, level constants.Level) error {
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
