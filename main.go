package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"obfuskit/cmd"
	"obfuskit/internal/model"
	"obfuskit/internal/payload"
	"obfuskit/internal/report"
	"obfuskit/internal/server"
	"obfuskit/types"
)

func main() {
	// Define command line flags
	helpFlag := flag.Bool("help", false, "Show help information")
	configFlag := flag.String("config", "", "Path to configuration file (YAML or JSON)")
	generateConfigFlag := flag.String("generate-config", "", "Generate example config file (yaml or json)")
	serverFlag := flag.Bool("server", false, "Start integration webservice")

	// Simple CLI flags for common use cases
	attackTypeFlag := flag.String("attack", "", "Attack type (xss, sqli, unixcmdi, wincmdi, path, fileaccess, ldapi)")
	payloadFlag := flag.String("payload", "", "Single payload to generate evasions for")
	payloadFileFlag := flag.String("payload-file", "", "File containing payloads (one per line)")
	urlFlag := flag.String("url", "", "Target URL to test payloads against")
	outputFlag := flag.String("output", "", "Output file path (default: print to console)")
	levelFlag := flag.String("level", "medium", "Evasion level (basic, medium, advanced)")
	encodingFlag := flag.String("encoding", "", "Specific encoding method (url, html, unicode, base64, hex, etc.)")
	reportFlag := flag.String("report", "pretty", "Report format (pretty, html, pdf, csv, nuclei, json)")

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
	var configErr error

	// Check if simple CLI flags are used
	if hasSimpleCLIFlags(*attackTypeFlag, *payloadFlag, *payloadFileFlag) {
		config, configErr = createConfigFromCLIFlags(*attackTypeFlag, *payloadFlag, *payloadFileFlag,
			*urlFlag, *outputFlag, *levelFlag, *encodingFlag, *reportFlag)
		if configErr != nil {
			log.Fatalf("Invalid CLI arguments: %v", configErr)
		}
		fmt.Println("Using command line arguments...")
	} else if *configFlag != "" {
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
		finalSelection := cmd.GetFinalSelection()
		fmt.Println("Interactive configuration completed successfully!")
		config = cmd.ConvertSelectionToConfig(finalSelection)
	}

	evasionLevel := types.EvasionLevelMedium
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

// hasSimpleCLIFlags checks if any of the simple CLI flags are provided
func hasSimpleCLIFlags(attackType, payload, payloadFile string) bool {
	return attackType != "" || payload != "" || payloadFile != ""
}

// createConfigFromCLIFlags creates a configuration from CLI flags
func createConfigFromCLIFlags(attackType, payload, payloadFile, url, output, level, encoding, report string) (*types.Config, error) {
	config := &types.Config{}

	// Validate attack type
	if attackType == "" {
		return nil, fmt.Errorf("attack type is required (use -attack flag)")
	}

	// Convert and validate attack type
	switch strings.ToLower(attackType) {
	case "xss":
		config.AttackType = types.AttackTypeXSS
	case "sqli", "sql":
		config.AttackType = types.AttackTypeSQLI
	case "unixcmdi", "unix":
		config.AttackType = types.AttackTypeUnixCMDI
	case "wincmdi", "windows":
		config.AttackType = types.AttackTypeWinCMDI
	case "oscmdi", "os":
		config.AttackType = types.AttackTypeOsCMDI
	case "path":
		config.AttackType = types.AttackTypePath
	case "fileaccess", "file":
		config.AttackType = types.AttackTypeFileAccess
	case "ldapi", "ldap":
		config.AttackType = types.AttackTypeLDAP
	case "ssrf":
		config.AttackType = types.AttackTypeSSRF
	case "xxe":
		config.AttackType = types.AttackTypeXXE
	case "generic":
		config.AttackType = types.AttackTypeGeneric
	case "all":
		config.AttackType = types.AttackTypeAll
	default:
		return nil, fmt.Errorf("unsupported attack type '%s'. Supported types: xss, sqli, unixcmdi, wincmdi, oscmdi, path, fileaccess, ldapi, ssrf, xxe, generic, all", attackType)
	}

	// Set action based on whether URL is provided
	if url != "" {
		config.Action = types.ActionSendToURL
		config.Target = types.Target{
			Method: types.TargetMethodURL,
			URL:    url,
		}
	} else {
		config.Action = types.ActionGeneratePayloads
		if output != "" {
			config.Target = types.Target{
				Method: types.TargetMethodFile,
				File:   output,
			}
		} else {
			config.Target = types.Target{
				Method: types.TargetMethodFile,
				File:   "console", // Special value to indicate console output
			}
		}
	}

	// Set payload configuration
	if payload != "" && payloadFile != "" {
		return nil, fmt.Errorf("cannot specify both -payload and -payload-file")
	}

	if payload != "" {
		config.Payload = types.Payload{
			Method: types.PayloadMethodEnterManually,
			Source: types.PayloadSourceEnterManually,
			Custom: []string{payload},
		}
	} else if payloadFile != "" {
		config.Payload = types.Payload{
			Method:   types.PayloadMethodFile,
			Source:   types.PayloadSourceFromFile,
			FilePath: payloadFile,
		}
	} else {
		// Use auto-generated payloads
		config.Payload = types.Payload{
			Method: types.PayloadMethodAuto,
			Source: types.PayloadSourceGenerated,
		}
	}

	// Set encoding if specified
	if encoding != "" {
		config.Payload.Method = types.PayloadMethodEncodings
		switch strings.ToLower(encoding) {
		case "url":
			config.Payload.Encoding = types.PayloadEncodingURL
		case "doubleurl", "double-url":
			config.Payload.Encoding = types.PayloadEncodingDoubleURL
		case "html":
			config.Payload.Encoding = types.PayloadEncodingHTML
		case "unicode":
			config.Payload.Encoding = types.PayloadEncodingUnicode
		case "base64", "b64":
			config.Payload.Encoding = types.PayloadEncodingBase64
		case "hex":
			config.Payload.Encoding = types.PayloadEncodingHex
		case "octal":
			config.Payload.Encoding = types.PayloadEncodingOctal
		case "bestfit", "best-fit":
			config.Payload.Encoding = types.PayloadEncodingBestFit
		case "mixedcase", "mixed-case":
			config.Payload.Encoding = types.PayloadEncodingMixedCase
		case "utf8", "utf-8":
			config.Payload.Encoding = types.PayloadEncodingUTF8
		case "unixcmd", "unix-cmd":
			config.Payload.Encoding = types.PayloadEncodingUnixCmd
		case "windowscmd", "windows-cmd":
			config.Payload.Encoding = types.PayloadEncodingWindowsCmd
		case "pathtraversal", "path-traversal":
			config.Payload.Encoding = types.PayloadEncodingPathTraversal
		default:
			return nil, fmt.Errorf("unsupported encoding '%s'. Supported encodings: url, html, unicode, base64, hex, octal, bestfit, mixedcase, utf8, unixcmd, windowscmd, pathtraversal", encoding)
		}
	}

	// Set evasion level
	switch strings.ToLower(level) {
	case "basic":
		config.EvasionLevel = types.EvasionLevelBasic
	case "medium":
		config.EvasionLevel = types.EvasionLevelMedium
	case "advanced":
		config.EvasionLevel = types.EvasionLevelAdvanced
	default:
		return nil, fmt.Errorf("unsupported evasion level '%s'. Supported levels: basic, medium, advanced", level)
	}

	// Set report type
	switch strings.ToLower(report) {
	case "pretty", "terminal":
		config.ReportType = types.ReportTypePretty
	case "html":
		config.ReportType = types.ReportTypeHTML
	case "pdf":
		config.ReportType = types.ReportTypePDF
	case "csv":
		config.ReportType = types.ReportTypeCSV
	case "nuclei":
		config.ReportType = types.ReportTypeNuclei
	case "json":
		config.ReportType = types.ReportTypeJSON
	case "auto":
		config.ReportType = types.ReportTypeAuto
	case "all":
		config.ReportType = types.ReportTypeAll
	default:
		return nil, fmt.Errorf("unsupported report format '%s'. Supported formats: pretty, html, pdf, csv, nuclei, json, auto, all", report)
	}

	return config, nil
}

// showHelp displays usage information
func showHelp() {
	fmt.Println("Obfuskit. A WAF Efficacy Testing Tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  obfuskit [flags]")
	fmt.Println("")
	fmt.Println("General Flags:")
	fmt.Println("  -help                       Show this help information")
	fmt.Println("  -config <file>              Use configuration file (YAML or JSON)")
	fmt.Println("  -generate-config <fmt>      Generate example config (yaml or json)")
	fmt.Println("  -server                     Start integration webservice")
	fmt.Println("")
	fmt.Println("Simple CLI Flags (can be used without config):")
	fmt.Println("  -attack <type>              Attack type (xss, sqli, unixcmdi, wincmdi, path, fileaccess, ldapi)")
	fmt.Println("  -payload <string>           Single payload to generate evasions for")
	fmt.Println("  -payload-file <file>        File containing payloads (one per line)")
	fmt.Println("  -url <url>                  Target URL to test payloads against")
	fmt.Println("  -output <file>              Output file path (default: print to console)")
	fmt.Println("  -level <level>              Evasion level: basic, medium, advanced (default: medium)")
	fmt.Println("  -encoding <method>          Specific encoding: url, html, unicode, base64, hex, etc.")
	fmt.Println("  -report <format>            Report format: pretty, html, pdf, csv, nuclei, json (default: pretty)")
	fmt.Println("")
	fmt.Println("Features:")
	fmt.Println("  • Interactive menu-driven interface (when no flags provided)")
	fmt.Println("  • Configuration file support (YAML/JSON)")
	fmt.Println("  • Simple command-line interface for quick testing")
	fmt.Println("  • Multiple evasion levels (Basic, Medium, Advanced)")
	fmt.Println("  • Support for various attack types (XSS, SQLi, Command Injection, etc.)")
	fmt.Println("  • Multiple encoding options")
	fmt.Println("  • Payload generation and testing capabilities")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  # Interactive mode")
	fmt.Println("  obfuskit")
	fmt.Println("")
	fmt.Println("  # Quick payload generation")
	fmt.Println("  obfuskit -attack xss -payload '<script>alert(1)</script>'")
	fmt.Println("  obfuskit -attack sqli -payload \"' OR 1=1 --\" -level advanced")
	fmt.Println("")
	fmt.Println("  # Test against URL")
	fmt.Println("  obfuskit -attack xss -payload '<script>alert(1)</script>' -url https://example.com")
	fmt.Println("")
	fmt.Println("  # Use payload file and save to output")
	fmt.Println("  obfuskit -attack xss -payload-file payloads.txt -output results.txt")
	fmt.Println("")
	fmt.Println("  # Specific encoding")
	fmt.Println("  obfuskit -attack xss -payload '<script>alert(1)</script>' -encoding unicode")
	fmt.Println("")
	fmt.Println("  # Configuration file")
	fmt.Println("  obfuskit -config config.yaml")
	fmt.Println("  obfuskit -generate-config yaml")
	fmt.Println("")
	fmt.Println("  # Server mode")
	fmt.Println("  obfuskit -server -config config_server.yaml")
}
