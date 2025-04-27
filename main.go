package main

import (
	"fmt"
	"obfuskit/report"
	"obfuskit/request"
	"time"
)

func main() {
	results := []request.TestResult{
		{
			Payload:          "<script>alert(1)</script>",
			EvasionTechnique: "None",
			RequestPart:      "Body",
			StatusCode:       403,
			ResponseTime:     50 * time.Millisecond,
			Blocked:          true,
		},
		{
			Payload:          "SELECT * FROM users",
			EvasionTechnique: "Case Manipulation",
			RequestPart:      "URL",
			StatusCode:       200,
			ResponseTime:     30 * time.Millisecond,
			Blocked:          false,
		},
	}

	err := report.GeneratePDFReport(results, "security_report.pdf")
	if err != nil {
		fmt.Printf("Error generating PDF report: %v\n", err)
	} else {
		fmt.Println("PDF report generated successfully!")
	}
}
