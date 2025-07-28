package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"obfuskit/cmd"
	"obfuskit/internal/model"
	"obfuskit/internal/payload"
	"obfuskit/internal/report"
	"obfuskit/internal/server"
	"obfuskit/internal/util"
	"obfuskit/types"
)

func main() {
	// Define command line flags
	helpFlag := flag.Bool("help", false, "Show help information")
	configFlag := flag.String("config", "", "Path to configuration file (YAML or JSON)")
	generateConfigFlag := flag.String("generate-config", "", "Generate example config file (yaml or json)")
	serverFlag := flag.Bool("server", false, "Start integration webservice")
	flag.Parse()

	// Show help if requested
	if *helpFlag {
		showHelp()
		return
	}

	// Generate example config if requested
	if *generateConfigFlag != "" {
		config, err := cmd.GenerateExampleConfig(*generateConfigFlag)
		if err != nil {
			log.Fatalf("Error generating config: %v", err)
		}
		filename := fmt.Sprintf("config.%s", *generateConfigFlag)
		err = os.WriteFile(filename, config, 0644)
		if err != nil {
			log.Fatalf("Error writing config file: %v", err)
		}
		fmt.Printf("Configuration generated successfully!\n")
		return
	}

	// Start integration webservice if requested
	if *serverFlag {
		var config *types.Config
		if *configFlag != "" {
			var configErr error
			config, configErr = cmd.LoadConfig(*configFlag)
			if configErr != nil {
				log.Fatalf("Error loading config: %v", configErr)
			}
			configErr = cmd.ValidateConfig(config)
			if configErr != nil {
				log.Fatalf("Invalid config: %v", configErr)
			}
		}

		handler := &server.ServerHandler{Config: config}
		http.Handle("/api/payloads", handler)
		log.Println("[+] Integration webservice listening on :8181 (/api/payloads)")
		if err := http.ListenAndServe(":8181", nil); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
		return
	}

	var config *types.Config
	var finalSelection cmd.Model
	var configErr error
	if *configFlag != "" {
		config, configErr = cmd.LoadConfig(*configFlag)
		if configErr != nil {
			log.Fatalf("Invalid config: %v", configErr)
		}
		configErr = cmd.ValidateConfig(config)
		if configErr != nil {
			log.Fatalf("Invalid config: %v", configErr)
		}
		fmt.Println("Configuration loaded successfully!")
	} else {
		fmt.Println("Initializing interactive configuration...")
		// You may want to implement an interactive UI or fallback logic here
		finalSelection = cmd.GetFinalSelection()
	}

	evasionLevel := types.EvasionLevelMedium
	if finalSelection.SelectedEvasionLevel != "" {
		evasionLevel = util.ParseEvasionLevel(finalSelection.SelectedEvasionLevel)
	}

	fmt.Println("\n==============================")
	fmt.Println("CONFIGURATION SUMMARY")
	fmt.Println("==============================")
	fmt.Printf("Action: %s\n", config.Action)
	fmt.Printf("Attack: %s\n", config.AttackType)
	fmt.Printf("Payload: %s\n", config.Payload.Method)
	fmt.Printf("Evasion Level: %s\n", config.EvasionLevel)
	fmt.Printf("Target: %s\n", config.Target.Method)
	fmt.Printf("Report: %s\n", config.ReportType)
	fmt.Printf("URL: %s\n", config.Target.URL)
	fmt.Println("==============================")

	// Prepare results
	results := &model.TestResults{
		Config: config,
	}

	var err error
	switch config.Action {
	case types.ActionGeneratePayloads:
		err = payload.HandleGeneratePayloads(results, evasionLevel)
	case types.ActionSendToURL:
		err = payload.HandleSendToURL(results, evasionLevel)
	case types.ActionUseExistingPayloads:
		err = payload.HandleExistingPayloads(results, evasionLevel)
	default:
		err = fmt.Errorf("unknown action: %s", config.Action)
	}

	if err != nil {
		log.Fatalf("Error processing action: %v", err)
	}

	report.GenerateSummary(results)

	if config.Action != "Generate Payloads" {
		reportErr := report.GenerateReports(results)
		if reportErr != nil {
			log.Fatalf("Error generating reports: %v", reportErr)
		}
	} else {
		fmt.Println("\n📝 Skipping report generation (payloads generated only)")
	}

	fmt.Println("\n✅ WAF testing completed successfully!")
}

// showHelp displays usage information
func showHelp() {
	fmt.Println("Obfuskit. A WAF Efficacy Testing Tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  obfuskit [flags]")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  -help                    Show this help information")
	fmt.Println("  -config <file>		        Use configuration file (YAML or JSON)")
	fmt.Println("  -generate-config <fmt>	  Generate example config (yaml or json)")
	fmt.Println("  -server			            Start integration webservice")
	fmt.Println("  -server -config <file>	  Start integration webservice with config")
	fmt.Println("")
	fmt.Println("Features:")
	fmt.Println("  • Interactive menu-driven interface")
	fmt.Println("  • Configuration file support (YAML/JSON)")
	fmt.Println("  • Multiple evasion levels (Basic, Medium, Advanced)")
	fmt.Println("  • Support for various attack types (XSS, SQLi, Command Injection, etc.)")
	fmt.Println("  • Multiple encoding options")
	fmt.Println("  • Payload generation and testing capabilities")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  obfuskit                                    # Run with interactive interface")
	fmt.Println("  obfuskit -config config.yaml                # Run with config file")
	fmt.Println("  obfuskit -generate-config yaml              # Generate example YAML config")
	fmt.Println("  obfuskit -generate-config json              # Generate example JSON config")
	fmt.Println("  obfuskit -server -config config_server.yaml # Run Burp integration webservice")
}
