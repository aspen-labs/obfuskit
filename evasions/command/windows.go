package command

import (
	"fmt"
	"math/rand"
	"obfuskit/constants"
	"obfuskit/evasions"
	"regexp"
	"strings"
)

// WindowsCmdVariants generates various Windows command evasion techniques
// based on the specified obfuscation level
func WindowsCmdVariants(payload string, level constants.Level) []string {
	var variants []string

	// Basic evasion techniques
	variants = append(variants,
		randomQuoteEvasion(payload),   // Using quotes at random places to break commands
		randomCaretEvasion(payload),   // Using ^ to escape characters
		variableSubstitution(payload), // %var% style substitution
		commaEvasion(payload),         // Command commas (,)
		spacingVariations(payload),    // Various spacing techniques
		delayedExpansion(payload),     // Delayed expansion with !var!
		envVarObfuscation(payload),    // Environment variable obfuscation
		commandSeparators(payload),    // Using & and | for separation
		forTokens(payload),            // FOR /F tokens obfuscation
		doubleQuoteEvasion(payload),   // Double quote variations
		parenthesisEvasion(payload),   // Parenthesis variations
		randomCase(payload),           // Random capitalization
	)

	// Return basic variants if level is Basic
	if level == constants.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more complex techniques
	variants = append(variants,
		quoteEvasion(payload), // Using quotes to break commands
		caretEvasion(payload),
		setCommands(payload),            // SET command obfuscation
		forCommands(payload),            // FOR command obfuscation
		multiLevelQuoting(payload),      // Nested quoting
		combinedEvasions(payload),       // Combining multiple techniques
		callWrapping(payload),           // CALL command wrapping
		cmdFlags(payload),               // constants.exe flags like /v:on /c
		substitutionTechniques(payload), // Multiple substitution techniques
		comSpecEvasion(payload),         // %COMSPEC% variations
	)

	// Return medium variants if level is Medium
	if level == constants.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds the most complex evasion techniques
	variants = append(variants,
		encodedCommands(payload),         // Encoded powershell commands
		batCompression(payload),          // Batch compression techniques
		multiStageExecution(payload),     // Multi-stage command execution
		powerShellObfuscation(payload),   // PowerShell obfuscation techniques
		regexBypass(payload),             // Regex bypass techniques
		unicodeEvasion(payload),          // Unicode character evasions
		tempFileExecution(payload),       // Temp file execution techniques
		environmentMisdirection(payload), // Environment misdirection
		charCodeEvasion(payload),         // Character code concatenation
		batchFileAlternatives(payload),   // Alternative batch file techniques
		advancedForLoops(payload),        // Advanced FOR loop techniques
	)

	return evasions.UniqueStrings(variants)
}

// Basic evasion techniques

func quoteEvasion(payload string) string {
	words := strings.Fields(payload)
	if len(words) < 2 {
		return payload
	}

	for i := 1; i < len(words); i++ {
		words[i] = "\"" + words[i] + "\""
	}

	return strings.Join(words, " ")
}

func randomQuoteEvasion(payload string) string {
	words := strings.Fields(payload)
	if len(words) < 2 {
		return payload
	}

	for i := 1; i < len(words); i++ {
		if rand.Intn(2) == 0 {
			words[i] = "\"" + words[i] + "\""
		}
	}

	return strings.Join(words, " ")
}

func caretEvasion(payload string) string {
	result := ""
	for _, char := range payload {
		if strings.ContainsRune(" &|()<>^", char) {
			result += string(char)
		} else {
			result += string('^') + string(char)
		}
	}
	return result
}

func randomCaretEvasion(payload string) string {
	result := ""
	for _, char := range payload {
		if rand.Intn(3) == 0 && !strings.ContainsRune(" &|()<>^", char) {
			result += string('^') + string(char)
		} else {
			result += string(char)
		}
	}
	return result
}

func variableSubstitution(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	result := "set c=" + parts[0] + " && %c%"
	if len(parts) > 1 {
		result += " " + strings.Join(parts[1:], " ")
	}
	return result
}

func commaEvasion(payload string) string {
	// Replace some spaces with commas
	words := strings.Fields(payload)
	result := words[0]

	for i := 1; i < len(words); i++ {
		if rand.Intn(3) == 0 {
			result += "," + words[i]
		} else {
			result += " " + words[i]
		}
	}

	return result
}

func spacingVariations(payload string) string {
	words := strings.Fields(payload)
	result := words[0]

	for i := 1; i < len(words); i++ {
		// Add random number of spaces
		spaces := 1 + rand.Intn(3)
		result += strings.Repeat(" ", spaces) + words[i]
	}

	return result
}

func delayedExpansion(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	return "setlocal enabledelayedexpansion && set v=" + parts[0] + " && !v! " + strings.Join(parts[1:], " ")
}

func envVarObfuscation(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Choose a random common env var
	envVars := []string{"%TEMP%\\", "%WINDIR%\\", "%SYSTEMROOT%\\"}
	prefix := envVars[rand.Intn(len(envVars))]

	return prefix + parts[0] + " " + strings.Join(parts[1:], " ")
}

func commandSeparators(payload string) string {
	separators := []string{" & ", " && ", " | ", " || "}
	sep := separators[rand.Intn(len(separators))]

	// Add a harmless command
	harmlessCommands := []string{"echo.", "ver", "dir", "type nul", "cls"}
	harmless := harmlessCommands[rand.Intn(len(harmlessCommands))]

	if rand.Intn(2) == 0 {
		return harmless + sep + payload
	} else {
		return payload + sep + harmless
	}
}

func forTokens(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	args := strings.Join(parts[1:], " ")

	return fmt.Sprintf("for /F \"tokens=*\" %%a in ('%s') do %%a %s", cmd, args)
}

func doubleQuoteEvasion(payload string) string {
	// Replace characters with quoted versions
	re := regexp.MustCompile(`([a-zA-Z0-9])`)
	result := re.ReplaceAllStringFunc(payload, func(s string) string {
		if rand.Intn(4) == 0 {
			return "\"" + s + "\""
		}
		return s
	})

	return result
}

func parenthesisEvasion(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) < 2 {
		return payload
	}

	return "(" + parts[0] + ")" + " " + strings.Join(parts[1:], " ")
}

func randomCase(payload string) string {
	result := ""
	for _, char := range payload {
		if rand.Intn(2) == 0 && (char >= 'a' && char <= 'z') {
			result += strings.ToUpper(string(char))
		} else if rand.Intn(2) == 0 && (char >= 'A' && char <= 'Z') {
			result += strings.ToLower(string(char))
		} else {
			result += string(char)
		}
	}
	return result
}

// Medium evasion techniques

func setCommands(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Create multiple SET commands
	result := "set a=" + parts[0]
	args := ""

	for i, part := range parts[1:] {
		varName := string(rune('b' + i))
		result += " && set " + varName + "=" + part
		args += " %" + varName + "%"
	}

	return result + " && %a%" + args
}

func forCommands(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = strings.Join(parts[1:], " ")
	}

	return fmt.Sprintf("for %%X in (%s) do %%X %s", cmd, args)
}

func multiLevelQuoting(payload string) string {
	return "constants.exe /V:ON /C \"set cmd=\"" + payload + "\" && !cmd!\""
}

func combinedEvasions(payload string) string {
	// Apply multiple techniques at once
	result := caretEvasion(payload)
	result = randomCase(result)
	result = commandSeparators(result)
	return result
}

func callWrapping(payload string) string {
	return "call " + payload
}

func cmdFlags(payload string) string {
	flags := []string{"/c", "/v:on /c", "/r /c", "/v:on /r /c", "/q /c"}
	flag := flags[rand.Intn(len(flags))]

	return "constants.exe " + flag + " " + quoteEvasion(payload)
}

func substitutionTechniques(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	// Break the command into individual characters
	var cmdChars []string
	for _, c := range cmd {
		cmdChars = append(cmdChars, string(c))
	}

	// Build SET commands for each character
	var setCmds []string
	for i, c := range cmdChars {
		setCmds = append(setCmds, fmt.Sprintf("set _c%d=%s", i, c))
	}

	// Create the combined command variable
	combineCmdParts := []string{"set command="}
	for i := range cmdChars {
		combineCmdParts = append(combineCmdParts, fmt.Sprintf("%%%_c%d%%", i))
	}

	// Build the final command
	finalCmd := strings.Join(setCmds, " && ")
	finalCmd += " && " + strings.Join(combineCmdParts, "")

	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	return finalCmd + " && %command%" + args
}

func comSpecEvasion(payload string) string {
	comspecVariations := []string{
		"%COMSPEC%",
		"%SYSTEMROOT%\\system32\\constants.exe",
		"%WINDIR%\\system32\\constants.exe",
	}

	comspec := comspecVariations[rand.Intn(len(comspecVariations))]
	return comspec + " /c " + payload
}

// Advanced evasion techniques

func encodedCommands(payload string) string {
	// Base64 encode the command for PowerShell
	// This is just a template - actual implementation would encode the payload
	encoded := "ZQBjAGgAbwAgAEgAZQBsAGwAbwA=" // Example encoding of "echo Hello"
	return "powershell -e " + encoded
}

func batCompression(payload string) string {
	// Simulate a compressed/packed batch command
	// Real implementation would compress the payload
	return "set a=e&&set b=x&&set c=e&&%a%%b%%c% \"" + payload + "\""
}

func multiStageExecution(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Create a multi-stage execution with temporary variables
	return "constants.exe /V:ON /C \"set p=" + parts[0] + " && " +
		"set a=" + strings.Join(parts[1:], " ") + " && " +
		"!p! !a!\""
}

func powerShellObfuscation(payload string) string {
	// Use PowerShell to execute the command with obfuscation
	encodedPayload := strings.ReplaceAll(payload, " ", "' '")
	return "powershell -nop -c \"&([scriptblock]::Create('" + encodedPayload + "'))\""
}

func regexBypass(payload string) string {
	// Insert regex-breaking characters
	re := regexp.MustCompile(`([a-zA-Z0-9_])`)
	result := re.ReplaceAllStringFunc(payload, func(s string) string {
		if rand.Intn(5) == 0 {
			return "[" + s + "]"
		}
		return s
	})

	return result
}

func unicodeEvasion(payload string) string {
	// Use Unicode escape sequences in batch
	result := ""
	for _, c := range payload {
		if rand.Intn(3) == 0 && c > 32 && c < 127 {
			result += fmt.Sprintf("%%u%04x", c)
		} else {
			result += string(c)
		}
	}

	return result
}

func tempFileExecution(payload string) string {
	// Create a technique that simulates writing to a temp file
	tempFile := "%TEMP%\\x" + fmt.Sprintf("%d", rand.Intn(10000)) + ".bat"
	return fmt.Sprintf("(echo %s)>%s && call %s", payload, tempFile, tempFile)
}

func environmentMisdirection(payload string) string {
	// Use environment variables to confuse WAF
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	envVars := []string{
		"ALLUSERSPROFILE", "APPDATA", "COMMONPROGRAMFILES", "COMPUTERNAME",
		"COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "LOGONSERVER",
	}

	// Create a complex chain of environment variables
	result := "set x=%"
	result += envVars[rand.Intn(len(envVars))]
	result += "% && set y=" + cmd + " && call %y%"

	if len(parts) > 1 {
		result += " " + strings.Join(parts[1:], " ")
	}

	return result
}

func charCodeEvasion(payload string) string {
	// For commands that accept character codes
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	// Only encode the command part
	cmd := parts[0]
	var encodedCmd string
	for _, c := range cmd {
		encodedCmd += fmt.Sprintf("%%~a%d", int(c))
	}

	// Set up character variables
	result := ""
	for i, c := range cmd {
		result += fmt.Sprintf("set a%d=%d && ", i, int(c))
	}

	// Build the final command
	result += "set cmd="
	for i := 0; i < len(cmd); i++ {
		result += fmt.Sprintf("%%~a%d", i)
	}

	args := ""
	if len(parts) > 1 {
		args = " " + strings.Join(parts[1:], " ")
	}

	return result + " && %cmd%" + args
}

func batchFileAlternatives(payload string) string {
	alternatives := []string{
		"constants.exe /k " + payload + " & exit",
		"constants.exe /c start /b " + payload,
		"constants.exe /c start \"\" /b " + payload,
		"wmic process call create \"" + payload + "\"",
	}

	return alternatives[rand.Intn(len(alternatives))]
}

func advancedForLoops(payload string) string {
	parts := strings.Fields(payload)
	if len(parts) == 0 {
		return payload
	}

	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = strings.Join(parts[1:], " ")
	}

	// Create complex FOR loop structures
	loopVariants := []string{
		fmt.Sprintf("for /l %%a in (1,1,1) do %s %s", cmd, args),
		fmt.Sprintf("for /f \"tokens=1,* delims=.\" %%a in (\"a.%s\") do %%a %s", cmd, args),
		fmt.Sprintf("for /f \"usebackq tokens=*\" %%a in (`echo %s`) do %%a %s", cmd, args),
	}

	return loopVariants[rand.Intn(len(loopVariants))]
}
