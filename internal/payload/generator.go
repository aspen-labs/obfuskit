package payload

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"obfuskit/cmd"
	"obfuskit/internal/model"
	"obfuskit/internal/util"
	"obfuskit/request"
	"obfuskit/types"
)

func HandleGeneratePayloads(results *model.TestResults, level types.EvasionLevel) error {
	fmt.Println("\n🔧 Generating payloads...")

	config, ok := results.Config.(*types.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	basePayloads, err := LoadBasePayloads(config.AttackType)
	if err != nil {
		return fmt.Errorf("failed to load base payloads: %v", err)
	}

	for attackType, payloads := range basePayloads {
		for _, payload := range payloads {
			if err := GenerateVariantsForPayload(results, payload, types.AttackType(attackType), level); err != nil {
				return err
			}
		}
	}

	fmt.Printf("✅ Generated %d payload variants across %d base payloads\n",
		GetTotalVariants(results), len(results.PayloadResults))

	if err := util.SavePayloadsToFile(results); err != nil {
		fmt.Printf("Warning: Failed to save payloads to file: %v\n", err)
	} else {
		fmt.Println("✅ Payloads saved to:")
		fmt.Println("  - payloads_output.txt (detailed with metadata)")
		fmt.Println("  - payloads_simple.txt (one payload per line)")
	}

	return nil
}

func HandleSendToURL(results *model.TestResults, level types.EvasionLevel) error {
	fmt.Println("\n🌐 Generating payloads and sending to URL...")

	config, ok := results.Config.(*types.Config)
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

func HandleExistingPayloads(results *model.TestResults, level types.EvasionLevel) error {
	fmt.Println("\n📁 Processing existing payloads...")

	config, ok := results.Config.(*types.Config)
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
		err := GenerateVariantsForPayload(results, payload, attackType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to generate variants for payload '%s': %v\n", payload, err)
			continue
		}
	}

	fmt.Printf("✅ Processed %d existing payloads into %d variants\n",
		len(payloads), util.GetTotalVariants(results))

	return nil
}

func GenerateVariantsForPayload(results *model.TestResults, payload string, attackType types.AttackType, level types.EvasionLevel) error {
	evasions, exists := cmd.GetEvasionsForPayload(attackType)
	if !exists {
		evasions = []types.PayloadEncoding{
			types.PayloadEncodingBase64,
			types.PayloadEncodingHex,
			types.PayloadEncodingUnicode,
		}
	}

	filteredEvasions := FilterEvasionEncodings(evasions, results.Config)

	for _, evasionType := range filteredEvasions {
		variants, err := cmd.ApplyEvasion(payload, evasionType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to apply %s to payload: %v\n", evasionType, err)
			continue
		}
		if len(variants) > 0 {
			results.PayloadResults = append(results.PayloadResults, model.PayloadResults{
				OriginalPayload: payload,
				AttackType:      string(attackType),
				EvasionType:     string(evasionType),
				Variants:        variants,
				Level:           string(level),
			})
		}
	}
	return nil
}

func FilterEvasionEncodings(evasions []types.PayloadEncoding, config interface{}) []types.PayloadEncoding {
	cfg, ok := config.(*types.Config)
	if !ok {
		return evasions
	}
	if cfg.Payload.Method == types.PayloadMethodAuto {
		return evasions
	}
	var filtered []types.PayloadEncoding
	switch cfg.Payload.Method {
	case types.PayloadMethodEncodings:
		encodingTypes := map[types.PayloadEncoding]bool{
			types.PayloadEncodingBase64: true, types.PayloadEncodingHex: true, types.PayloadEncodingHTML: true,
			types.PayloadEncodingUnicode: true, types.PayloadEncodingOctal: true, types.PayloadEncodingBestFit: true,
		}
		for _, evasion := range evasions {
			if encodingTypes[evasion] {
				filtered = append(filtered, evasion)
			}
		}
	case types.PayloadMethodPaths:
		for _, evasion := range evasions {
			if evasion == types.PayloadEncodingPathTraversal {
				filtered = append(filtered, evasion)
			}
		}
	case types.PayloadMethodCommands:
		commandTypes := map[types.PayloadEncoding]bool{
			types.PayloadEncodingUnixCmd: true, types.PayloadEncodingWindowsCmd: true,
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

func LoadBasePayloads(attackType types.AttackType) (map[string][]string, error) {
	payloads := make(map[string][]string)
	attackTypes := []types.AttackType{}
	if attackType == types.AttackTypeGeneric {
		attackTypes = []types.AttackType{
			types.AttackTypeXSS,
			types.AttackTypeSQLI,
			types.AttackTypeUnixCMDI,
			types.AttackTypeWinCMDI,
			types.AttackTypePath,
			types.AttackTypeFileAccess,
			types.AttackTypeLDAP,
			types.AttackTypeSSRF,
			types.AttackTypeXXE,
		}
	} else {
		attackTypes = []types.AttackType{attackType}
	}
	for _, aType := range attackTypes {
		filePath := filepath.Join("payloads", string(aType)+".txt")
		filePayloads, err := LoadPayloadsFromFile(filePath)
		if err != nil {
			fmt.Printf("Warning: Could not load payloads for %s: %v\n", aType, err)
			continue
		}
		payloads[string(aType)] = filePayloads
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
