package report

import (
	"fmt"
	"obfuskit/request"
	"strings"
	"time"

	"github.com/fatih/color"
)

// PrintTerminalReport prints a formatted report to the terminal
func PrintTerminalReport(results []request.TestResult) {
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

	// Colors
	headerColor := color.New(color.FgHiWhite, color.Bold, color.BgBlue)
	sectionColor := color.New(color.FgHiWhite, color.Bold, color.BgCyan)
	successColor := color.New(color.FgGreen, color.Bold)
	failColor := color.New(color.FgRed, color.Bold)
	infoColor := color.New(color.FgYellow)

	// Print header
	headerColor.Println(strings.Repeat(" ", 80))
	headerColor.Println(center("SECURITY TEST RESULTS REPORT", 80))
	headerColor.Println(strings.Repeat(" ", 80))
	fmt.Println()

	// Print summary
	sectionColor.Println(" SUMMARY ")
	fmt.Println()
	fmt.Printf("  Total Tests:  %d\n", total)
	fmt.Printf("  Blocked:      ")
	successColor.Printf("%d\n", blocked)
	fmt.Printf("  Unblocked:    ")
	failColor.Printf("%d\n", total-blocked)
	fmt.Printf("  Block Rate:   %.2f%%\n", blockRate)
	fmt.Println()

	// Print detailed results
	sectionColor.Println(" DETAILED RESULTS ")
	fmt.Println()

	// Print table header
	fmt.Printf("%-30s %-20s %-10s %-10s %-10s %-10s\n",
		"PAYLOAD", "EVASION", "PART", "STATUS", "TIME(ms)", "BLOCKED")
	fmt.Println(strings.Repeat("-", 90))

	// Print table rows
	for _, result := range results {
		// Truncate payload if too long
		payload := result.Payload
		if len(payload) > 27 {
			payload = payload[:24] + "..."
		}

		// Print row data
		fmt.Printf("%-30s %-20s %-10s %-10d %-10d ",
			payload, result.EvasionTechnique, result.RequestPart,
			result.StatusCode, result.ResponseTime.Milliseconds())

		// Print blocked status with color
		if result.Blocked {
			successColor.Println("YES")
		} else {
			failColor.Println("NO")
		}
	}

	fmt.Println()
	infoColor.Printf("Report generated at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()
}

// Helper function to center text
func center(s string, width int) string {
	if len(s) >= width {
		return s
	}

	spaces := width - len(s)
	padding := spaces / 2

	return strings.Repeat(" ", padding) + s + strings.Repeat(" ", spaces-padding)
}

// Example usage:
/*
func main() {
	results := []TestResult{
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

	PrintTerminalReport(results)
}
*/
