package report

import (
	"fmt"
	"obfuskit/request"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// GeneratePDFReport creates a PDF report from a list of test results
func GeneratePDFReport(results []request.TestResult, outputPath string) error {
	// Count statistics
	total := len(results)
	blocked := 0
	for _, result := range results {
		if result.Blocked {
			blocked++
		}
	}

	// Calculate block rate
	blockRate := 0.0
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
	}

	// Create new PDF with A4 portrait orientation
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Set fonts
	pdf.SetFont("Arial", "B", 16)

	// Add title
	pdf.CellFormat(190, 10, "Security Test Results Report", "", 1, "C", false, 0, "")

	// Add summary section
	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(190, 10, "Summary", "", 1, "", false, 0, "")
	pdf.Ln(10)

	// Add summary table
	pdf.SetFont("Arial", "", 12)
	pdf.SetFillColor(240, 240, 240)

	// Total tests
	pdf.CellFormat(60, 8, "Total Tests:", "1", 0, "", true, 0, "")
	pdf.CellFormat(130, 8, fmt.Sprintf("%d", total), "1", 1, "", false, 0, "")

	// Blocked tests
	pdf.CellFormat(60, 8, "Blocked:", "1", 0, "", true, 0, "")
	pdf.CellFormat(130, 8, fmt.Sprintf("%d", blocked), "1", 1, "", false, 0, "")

	// Unblocked tests
	pdf.CellFormat(60, 8, "Unblocked:", "1", 0, "", true, 0, "")
	pdf.CellFormat(130, 8, fmt.Sprintf("%d", total-blocked), "1", 1, "", false, 0, "")

	// Block rate
	pdf.CellFormat(60, 8, "Block Rate:", "1", 0, "", true, 0, "")
	pdf.CellFormat(130, 8, fmt.Sprintf("%.2f%%", blockRate), "1", 1, "", false, 0, "")
	pdf.Ln(15)

	// Add detailed results section
	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(190, 10, "Detailed Results", "", 1, "", false, 0, "")
	pdf.Ln(10)

	// Add table header
	pdf.SetFont("Arial", "B", 10)
	pdf.SetFillColor(200, 200, 200)

	// Calculate column widths
	colWidths := []float64{55, 30, 25, 25, 25, 30}

	pdf.CellFormat(colWidths[0], 8, "Payload", "1", 0, "", true, 0, "")
	pdf.CellFormat(colWidths[1], 8, "Evasion Technique", "1", 0, "", true, 0, "")
	pdf.CellFormat(colWidths[2], 8, "Request Part", "1", 0, "", true, 0, "")
	pdf.CellFormat(colWidths[3], 8, "Status Code", "1", 0, "", true, 0, "")
	pdf.CellFormat(colWidths[4], 8, "Time (ms)", "1", 0, "", true, 0, "")
	pdf.CellFormat(colWidths[5], 8, "Blocked", "1", 1, "", true, 0, "")
	pdf.Ln(-1)

	// Add table rows
	pdf.SetFont("Arial", "", 10)
	for i, result := range results {
		// Alternate row colors
		fill := i%2 == 0
		if fill {
			pdf.SetFillColor(240, 240, 240)
		}

		// Truncate payload if too long
		payload := result.Payload
		if len(payload) > 27 {
			payload = payload[:24] + "..."
		}

		pdf.CellFormat(colWidths[0], 8, payload, "1", 0, "", fill, 0, "")
		pdf.CellFormat(colWidths[1], 8, result.EvasionTechnique, "1", 0, "", fill, 0, "")
		pdf.CellFormat(colWidths[2], 8, result.RequestPart, "1", 0, "", fill, 0, "")
		pdf.CellFormat(colWidths[3], 8, fmt.Sprintf("%d", result.StatusCode), "1", 0, "", fill, 0, "")
		pdf.CellFormat(colWidths[4], 8, fmt.Sprintf("%d", result.ResponseTime.Milliseconds()), "1", 0, "", fill, 0, "")

		// Set color for blocked status
		if result.Blocked {
			pdf.SetTextColor(0, 128, 0) // Green for blocked
		} else {
			pdf.SetTextColor(192, 0, 0) // Red for not blocked
		}

		pdf.CellFormat(colWidths[5], 8, fmt.Sprintf("%t", result.Blocked), "1", 1, "", fill, 0, "")

		// Reset text color
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(-1)
	}

	// Add footer
	pdf.Ln(10)
	pdf.SetFont("Arial", "I", 8)
	pdf.CellFormat(190, 10, fmt.Sprintf("Report generated at %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "", false, 0, "")

	// Save the PDF
	return pdf.OutputFileAndClose(outputPath)
}
