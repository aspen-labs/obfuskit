package report

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"obfuskit/request"
)

func GenerateHTMLReport(results []request.TestResult, outputPath string) error {
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

	// Prepare data for the template
	data := struct {
		Results     []request.TestResult
		Total       int
		Blocked     int
		Unblocked   int
		BlockRate   float64
		GeneratedAt string
	}{
		Results:     results,
		Total:       total,
		Blocked:     blocked,
		Unblocked:   total - blocked,
		BlockRate:   blockRate,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	// HTML template
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Test Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
        }
        h1, h2 {
            color: #333;
        }
        .summary {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .total {
            background-color: #e3f2fd;
        }
        .blocked {
            background-color: #e8f5e9;
        }
        .unblocked {
            background-color: #ffebee;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .blocked-yes {
            color: green;
            font-weight: bold;
        }
        .blocked-no {
            color: red;
            font-weight: bold;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #666;
        }
    </style>
</head>
<body>
    <h1>Security Test Results Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="stats">
            <div class="stat-box total">
                <h3>Total Tests</h3>
                <p>{{.Total}}</p>
            </div>
            <div class="stat-box blocked">
                <h3>Blocked</h3>
                <p>{{.Blocked}}</p>
            </div>
            <div class="stat-box unblocked">
                <h3>Unblocked</h3>
                <p>{{.Unblocked}}</p>
            </div>
        </div>
        <h3>Block Rate: {{printf "%.2f" .BlockRate}}%</h3>
    </div>

    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>Payload</th>
                <th>Evasion Technique</th>
                <th>Request Part</th>
                <th>Status Code</th>
                <th>Response Time (ms)</th>
                <th>Blocked</th>
            </tr>
        </thead>
        <tbody>
            {{range .Results}}
            <tr>
                <td>{{.Payload}}</td>
                <td>{{.EvasionTechnique}}</td>
                <td>{{.RequestPart}}</td>
                <td>{{.StatusCode}}</td>
                <td>{{.ResponseTime.Milliseconds}}</td>
                <td class="{{if .Blocked}}blocked-yes{{else}}blocked-no{{end}}">
                    {{if .Blocked}}Yes{{else}}No{{end}}
                </td>
            </tr>
            {{end}}
        </tbody>
    </table>

    <div class="footer">
        <p>Report generated at {{.GeneratedAt}}</p>
    </div>
</body>
</html>`

	// Parse the template
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// Execute the template
	if err := t.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	return nil
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

	err := GenerateHTMLReport(results, "security_report.html")
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
	} else {
		fmt.Println("Report generated successfully!")
	}
}
*/
