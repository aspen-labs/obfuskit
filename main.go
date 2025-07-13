package main

import (
	"fmt"
	"obfuskit/cmd"
)

func main() {
	/*
		Input is going to be interactive.
		1. You pick an attack/leave it upto us.
		2. You pick a payload/leave it upto us.
		3. You pick a target/we add it to file
		4. You pick a report type/leave it upto us
	*/
	finalSelection := cmd.GetFinalSelection()
	fmt.Println("Chosen action:", finalSelection.Selection)
	fmt.Println("Chosen attack:", finalSelection.SelectedAttack)
	fmt.Println("Chosen payload:", finalSelection.SelectedPayload)
	fmt.Println("Chosen target:", finalSelection.SelectedTarget)
	fmt.Println("Chosen report type:", finalSelection.SelectedReportType)
	fmt.Println("Chosen URL: ", finalSelection.URL)

	// results, err := request.RunTests(
	// 	request.WithTargetURL("http://3txqcwxqw466fnzzw1wh10yyhpngb7zw.oastify.com"),
	// 	request.WithPayloadFile("payloads.txt"),
	// 	request.WithLogLevel("info"),
	// 	request.WithConcurrency(5), // Use 5 concurrent workers
	// )

	// if err != nil {
	// 	fmt.Printf("Error running tests: %v\n", err)
	// 	os.Exit(1)
	// }

	// // Create a default logger if one doesn't exist
	// logger, _ := request.ConfigureLogging("log.txt", "info")

	// // Write results to CSV file
	// outputFile := "results_" + time.Now().Format("20060102_150405") + ".csv"
	// if err := request.WriteResultsToFile(results, outputFile, "csv", logger); err != nil {
	// 	fmt.Printf("Error writing results: %v\n", err)
	// }

}
