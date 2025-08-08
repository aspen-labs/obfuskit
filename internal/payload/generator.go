package payload

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"obfuskit/cmd"
	"obfuskit/internal/genai"
	"obfuskit/internal/logging"
	"obfuskit/internal/model"
	"obfuskit/internal/util"
	"obfuskit/internal/waf"
	"obfuskit/request"
	"obfuskit/types"
)

func HandleGeneratePayloads(results *model.TestResults, level types.EvasionLevel, showProgress bool, threads int) error {
	logging.Infoln("\n🔧 Generating payloads...")

	config, ok := results.Config.(*types.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	// Handle multiple attack types
	attackTypesToProcess := []types.AttackType{config.AttackType}

	// Check if there are additional attack types
	if len(config.AdditionalAttackTypes) > 0 {
		attackTypesToProcess = append(attackTypesToProcess, config.AdditionalAttackTypes...)
		fmt.Printf("🔀 Processing multiple attack types: %v\n", attackTypesToProcess)
	}

	// Load base payloads for all attack types
	allBasePayloads := make(map[string][]string)
	for _, attackType := range attackTypesToProcess {
		basePayloads, err := LoadBasePayloads(attackType)
		if err != nil {
			logging.Warnf("Warning: Failed to load payloads for %s: %v\n", attackType, err)
			continue
		}

		// Merge payloads from this attack type
		for key, payloads := range basePayloads {
			allBasePayloads[key] = append(allBasePayloads[key], payloads...)
		}
	}

	// If AI is enabled, generate additional base payloads using GenAI
	if config.EnableAI && config.AIConfig != nil {
		aiCfg, ok := config.AIConfig.(*genai.Config)
		if !ok {
			fmt.Println("Warning: Invalid AI configuration; skipping AI generation")
		} else {
			engine := genai.NewEngine(aiCfg)
			logging.Infoln("🤖 Using GenAI to generate additional base payloads...")

			// Attempt to construct WAF context if available
			var wafCtx *genai.WAFContext
			if fp, ok := config.WAFFingerprint.(*waf.WAFFingerprint); ok && fp != nil {
				wafCtx = &genai.WAFContext{
					Vendor: string(fp.WAFType),
				}
			}

			for _, attackType := range attackTypesToProcess {
				req := &genai.PayloadGenerationRequest{
					AttackType:      attackType,
					TargetContext:   config.Target.URL,
					WAFInfo:         wafCtx,
					EvasionLevel:    string(level),
					RequestBaseline: config.AIContext, // Pass baseline context for enhanced AI generation
					Count:           10,
					Creativity:      0.7,
				}

				// If user provided manual payload, seed as base
				if config.Payload.Source == "Enter Manually" && len(config.Payload.Custom) > 0 {
					req.BasePayload = config.Payload.Custom[0]
				}

				genResult, err := engine.GeneratePayloads(req)
				if err != nil {
					logging.Warnf("AI generation failed for %s: %v\n", attackType, err)
					continue
				}

				added := 0
				for _, gp := range genResult.Payloads {
					if strings.TrimSpace(gp.Payload) == "" {
						continue
					}
					allBasePayloads[string(attackType)] = append(allBasePayloads[string(attackType)], gp.Payload)
					added++
				}

				if added > 0 {
					logging.Infof("🤖 Added %d AI-generated base payloads for %s\n", added, attackType)
				}
			}
		}
	}

	if len(allBasePayloads) == 0 {
		return fmt.Errorf("no payloads could be loaded for any attack types")
	}

	basePayloads := allBasePayloads

	// Count total payloads for progress tracking
	totalPayloads := 0
	for _, payloads := range basePayloads {
		totalPayloads += len(payloads)
	}

	// Initialize progress bar
	var progress *util.TaskProgress
	if showProgress && totalPayloads > 0 {
		progress = util.NewTaskProgress("Generating payloads", totalPayloads, true)
	}

	currentPayload := 0
	for attackType, payloads := range basePayloads {
		for _, payload := range payloads {
			if err := GenerateVariantsForPayload(results, payload, types.AttackType(attackType), level); err != nil {
				return err
			}

			currentPayload++
			if progress != nil {
				progress.Update(currentPayload)
			}
		}
	}

	if progress != nil {
		progress.Finish()
	}

	// Apply filtering if configured
	originalCount := len(results.PayloadResults)
	if config, ok := results.Config.(*types.Config); ok && config.FilterOptions != nil {
		if filterOptions, ok := config.FilterOptions.(*util.FilterOptions); ok {
			results.PayloadResults = util.FilterPayloadResults(results.PayloadResults, filterOptions)
			util.PrintFilterSummary(filterOptions, originalCount, len(results.PayloadResults))
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

func HandleSendToURL(results *model.TestResults, level types.EvasionLevel, showProgress bool, threads int) error {
	fmt.Println("\n🌐 Generating payloads and sending to URL...")

	config, ok := results.Config.(*types.Config)
	if !ok {
		return fmt.Errorf("invalid config type in TestResults")
	}

	// Perform WAF fingerprinting if enabled
	var wafFingerprint *waf.WAFFingerprint
	if config.EnableFingerprinting {
		var err error
		wafFingerprint, err = waf.FingerprintWAF(config.Target.URL)
		if err != nil {
			fmt.Printf("⚠️  WAF fingerprinting failed: %v\n", err)
		} else {
			// Store fingerprint in config for adaptive evasion
			config.WAFFingerprint = wafFingerprint

			// Show WAF report if requested
			if config.ShowWAFReport {
				fmt.Println(waf.GenerateWAFReport(wafFingerprint))
			}

			// Adapt evasion strategy based on WAF type
			adaptEvasionStrategy(config, wafFingerprint)
		}
	}

	// First generate the payloads
	err := HandleGeneratePayloads(results, level, showProgress, threads)
	if err != nil {
		return err
	}

	// Then send them to the target URL
	fmt.Printf("🚀 Sending %d payload variants to %s\n", GetTotalVariants(results), config.Target.URL)

	totalVariants := GetTotalVariants(results)
	var urlProgress *util.TaskProgress
	if showProgress && totalVariants > 0 {
		urlProgress = util.NewTaskProgress("Testing payloads", totalVariants, true)
	}

	// Create a work queue for parallel processing
	type workItem struct {
		variant      string
		payloadIndex int
		variantIndex int
	}

	workQueue := make(chan workItem, totalVariants)
	var resultsMutex sync.Mutex
	var wg sync.WaitGroup
	var currentVariant int
	var progressMutex sync.Mutex

	// Create worker function
	worker := func() {
		defer wg.Done()

		// Create a logger for this worker
		logger := request.NewLogger(os.Stdout)

		// Create injectors for this worker
		injectors := []request.FastHTTPInjector{
			request.NewFastHTTPHeaderInjector(),
			request.NewFastHTTPQueryInjector(),
			request.NewFastHTTPBodyInjector(),
			request.NewFastHTTPProtocolInjector(),
		}

		for work := range workQueue {
			if !showProgress {
				fmt.Printf("Testing payload %d variant %d\r", work.payloadIndex+1, work.variantIndex+1)
			}

			// Test this variant with all injectors
			for _, injector := range injectors {
				testResults := injector.Inject(config.Target.URL, work.variant, logger)

				// Thread-safe append to results
				resultsMutex.Lock()
				results.RequestResults = append(results.RequestResults, testResults...)
				resultsMutex.Unlock()
			}

			// Update progress thread-safely
			if urlProgress != nil {
				progressMutex.Lock()
				currentVariant++
				urlProgress.Update(currentVariant)
				progressMutex.Unlock()
			}
		}
	}

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker()
	}

	// Queue all work items
	for i, payloadResult := range results.PayloadResults {
		for j, variant := range payloadResult.Variants {
			workQueue <- workItem{
				variant:      variant,
				payloadIndex: i,
				variantIndex: j,
			}
		}
	}

	// Close queue and wait for completion
	close(workQueue)
	wg.Wait()

	if urlProgress != nil {
		urlProgress.Finish()
	}

	// Preserve full set before filtering for consistent reporting baselines
	if len(results.AllRequestResults) == 0 {
		results.AllRequestResults = append(results.AllRequestResults, results.RequestResults...)
	}

	// Apply request result filtering if configured
	originalRequestCount := len(results.RequestResults)
	if config, ok := results.Config.(*types.Config); ok && config.FilterOptions != nil {
		if filterOptions, ok := config.FilterOptions.(*util.FilterOptions); ok {
			results.RequestResults = util.FilterRequestResults(results.RequestResults, filterOptions)
			if len(filterOptions.FilterStatusCodes) > 0 || filterOptions.OnlySuccessful || filterOptions.MaxResponseTime > 0 {
				fmt.Printf("🔍 Filtered %d -> %d request results based on response criteria\n",
					originalRequestCount, len(results.RequestResults))
			}
		}
	}

	fmt.Printf("\n✅ Completed testing %d payloads against target\n", GetTotalVariants(results))
	return nil
}

func HandleExistingPayloads(results *model.TestResults, level types.EvasionLevel, showProgress bool, threads int) error {
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

	// Initialize progress bar for existing payloads
	var existingProgress *util.TaskProgress
	if showProgress && len(payloads) > 0 {
		existingProgress = util.NewTaskProgress("Processing payloads", len(payloads), true)
	}

	// Process each existing payload
	for i, payload := range payloads {
		// Try to detect attack type or use a generic approach
		attackType := util.DetectAttackType(payload)
		err := GenerateVariantsForPayload(results, payload, attackType, level)
		if err != nil {
			fmt.Printf("Warning: Failed to generate variants for payload '%s': %v\n", payload, err)
			continue
		}

		if existingProgress != nil {
			existingProgress.Update(i + 1)
		}
	}

	if existingProgress != nil {
		existingProgress.Finish()
	}

	// Apply filtering if configured
	originalCount := len(results.PayloadResults)
	if config, ok := results.Config.(*types.Config); ok && config.FilterOptions != nil {
		if filterOptions, ok := config.FilterOptions.(*util.FilterOptions); ok {
			results.PayloadResults = util.FilterPayloadResults(results.PayloadResults, filterOptions)
			util.PrintFilterSummary(filterOptions, originalCount, len(results.PayloadResults))
		}
	}

	fmt.Printf("✅ Processed %d existing payloads into %d variants\n",
		len(payloads), GetTotalVariants(results))

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
	} else if attackType == types.AttackTypeAll {
		// When "all" is specified, it means multiple attack types were provided
		// We'll get the actual types from the config's custom payload data
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

// adaptEvasionStrategy adapts the evasion strategy based on detected WAF
func adaptEvasionStrategy(config *types.Config, fingerprint *waf.WAFFingerprint) {
	if fingerprint == nil {
		return
	}

	fmt.Printf("🎯 Adapting evasion strategy for %s WAF\n", fingerprint.WAFType)

	// Get optimal evasions for detected WAF
	optimalEvasions := waf.GetOptimalEvasions(fingerprint.WAFType)

	// If we have filter options, update the excluded encodings to prioritize optimal ones
	if config.FilterOptions != nil {
		if filterOptions, ok := config.FilterOptions.(*util.FilterOptions); ok {
			// Remove optimal evasions from excluded list if they were excluded
			for _, optimal := range optimalEvasions {
				for i, excluded := range filterOptions.ExcludeEncodings {
					if strings.Contains(strings.ToLower(excluded), strings.ToLower(optimal)) {
						// Remove this exclusion
						filterOptions.ExcludeEncodings = append(filterOptions.ExcludeEncodings[:i], filterOptions.ExcludeEncodings[i+1:]...)
						break
					}
				}
			}

			fmt.Printf("🔧 Prioritizing evasion techniques: %s\n", strings.Join(optimalEvasions, ", "))
		}
	}

	// Store optimal evasions in config for potential future use
	// This could be used to influence payload generation order
}
