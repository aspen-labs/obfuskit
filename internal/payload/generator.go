package payload

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"obfuskit/cmd"
	"obfuskit/constants"
	"obfuskit/internal/model"
	"obfuskit/internal/util"
	"obfuskit/request"
)

func HandleGeneratePayloads(results *model.TestResults, level constants.Level) error {
	fmt.Println("\n🔧 Generating payloads...")

	config, ok := results.Config.(*cmd.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	basePayloads, err := LoadBasePayloads(config.Attack.Type)
	if err != nil {
		return fmt.Errorf("failed to load base payloads: %v", err)
	}

	for attackType, payloads := range basePayloads {
		for _, payload := range payloads {
			if err := GenerateVariantsForPayload(results, payload, attackType, level); err != nil {
				return err
			}
		}
	}

	fmt.Printf("✅ Generated %d payload variants across %d base payloads\n",
		GetTotalVariants(results), len(results.PayloadResults))

	if err := SavePayloadsToFile(results); err != nil {
		fmt.Printf("Warning: Failed to save payloads to file: %v\n", err)
	} else {
		fmt.Println("✅ Payloads saved to:")
		fmt.Println("  - payloads_output.txt (detailed with metadata)")
		fmt.Println("  - payloads_simple.txt (one payload per line)")
	}

	// Generate nuclei templates from payloads
	// (to be implemented in report package)

	return nil
}

func HandleSendToURL(results *model.TestResults, level constants.Level) error {
	fmt.Println("\n🌐 Generating payloads and sending to URL...")

	config, ok := results.Config.(*cmd.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	// First generate the payloads
	err := HandleGeneratePayloads(results, level)
	if err != nil {
		return err
	}

	// Then send them to the target URL
	fmt.Printf("🚀 Sending %d payload variants to %s\n", GetTotalVariants(results), config.Target.URL)

	for i, payloadResult := range results.PayloadResults {
		for j, variant := range payloadResult.Variants {
			fmt.Printf("Testing payload %d/%d variant %d/%d\r",
				i+1, len(results.PayloadResults), j+1, len(payloadResult.Variants))

			// Send request using the available request package functions
			// Create a logger for the request
			logger := request.NewLogger(os.Stdout)

			// Test this single variant
			injectors := []request.FastHTTPInjector{
				request.NewFastHTTPHeaderInjector(),
				request.NewFastHTTPQueryInjector(),
				request.NewFastHTTPBodyInjector(),
				request.NewFastHTTPProtocolInjector(),
			}

			for _, injector := range injectors {
				testResults := injector.Inject(config.Target.URL, variant, logger)
				results.RequestResults = append(results.RequestResults, testResults...)
			}
		}
	}

	fmt.Printf("\n✅ Completed testing %d payloads against target\n", GetTotalVariants(results))
	return nil
}

func HandleExistingPayloads(results *model.TestResults, level constants.Level) error {
	fmt.Println("\n📁 Processing existing payloads...")

	config, ok := results.Config.(*cmd.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	var payloads []string
	var err error

	switch config.Payload.Source {
	case "From File":
		payloads, err = util.LoadPayloadsFromFile(config.Payload.FilePath)
		if err != nil {
			return fmt.Errorf("failed to load payloads from file: %w", err)
		}
	case "Enter Manually":
		payloads = config.Payload.Custom
	default:
		return fmt.Errorf("unknown payload source: %s", config.Payload.Source)
	}

	// Process each existing payload
	for _, payload := range payloads {
		// Try to detect attack type or use a generic approach
		attackType := util.DetectAttackType(payload)
		err := util.GenerateVariantsForPayload(results, payload, attackType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to generate variants for payload '%s': %v\n", payload, err)
			continue
		}
	}

	fmt.Printf("✅ Processed %d existing payloads into %d variants\n",
		len(payloads), util.GetTotalVariants(results))

	return nil
}

func GenerateVariantsForPayload(results *model.TestResults, payload, attackType string, level constants.Level) error {
	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		evasions = []string{"Base64Variants", "HexVariants", "UnicodeVariants"}
	}

	filteredEvasions := FilterEvasions(evasions, results.Config)

	for _, evasionType := range filteredEvasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to apply %s to payload: %v\n", evasionType, err)
			continue
		}
		if len(variants) > 0 {
			results.PayloadResults = append(results.PayloadResults, model.PayloadResults{
				OriginalPayload: payload,
				AttackType:      attackType,
				EvasionType:     evasionType,
				Variants:        variants,
				Level:           level,
			})
		}
	}
	return nil
}

func FilterEvasions(evasions []string, config interface{}) []string {
	cfg, ok := config.(cmd.Model)
	if !ok {
		return evasions
	}
	if cfg.SelectedPayload == "All" {
		return evasions
	}
	var filtered []string
	switch cfg.SelectedPayload {
	case "Encodings":
		encodingTypes := map[string]bool{
			"Base64Variants": true, "HexVariants": true, "HTMLVariants": true,
			"UnicodeVariants": true, "OctalVariants": true, "BestFitVariants": true,
		}
		for _, evasion := range evasions {
			if encodingTypes[evasion] {
				filtered = append(filtered, evasion)
			}
		}
	case "Paths":
		for _, evasion := range evasions {
			if evasion == "PathTraversalVariants" {
				filtered = append(filtered, evasion)
			}
		}
	case "Commands":
		commandTypes := map[string]bool{
			"UnixCmdVariants": true, "WindowsCmdVariants": true,
		}
		for _, evasion := range evasions {
			if commandTypes[evasion] {
				filtered = append(filtered, evasion)
			}
		}
	default:
		filtered = evasions
	}
	return filtered
}

func LoadBasePayloads(attackType string) (map[string][]string, error) {
	payloads := make(map[string][]string)
	attackTypes := []string{}
	if attackType == "All" {
		attackTypes = []string{"xss", "sqli", "unixcmdi", "wincmdi", "path", "fileaccess", "ldapi"}
	} else {
		attackTypeMap := map[string]string{
			"XSS":               "xss",
			"SQLi":              "sqli",
			"Command Injection": "unixcmdi",
			"LFI":               "fileaccess",
			"RFI":               "fileaccess",
			"SSRF":              "ldapi",
			"XXE":               "ldapi",
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
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return payloads, nil
}

func GetTotalVariants(results *model.TestResults) int {
	total := 0
	for _, pr := range results.PayloadResults {
		total += len(pr.Variants)
	}
	return total
}

func SavePayloadsToFile(results *model.TestResults) error {
	// Implementation placeholder (move from main.go if needed)
	return nil
}
