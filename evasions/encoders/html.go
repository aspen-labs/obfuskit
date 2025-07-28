package encoders

import (
	"fmt"
	"math/rand"
	"obfuskit/evasions"
	"obfuskit/types"
	"strings"
)

func HTMLVariants(payload string, level types.EvasionLevel) []string {
	var variants []string

	htmlDecimalEntities := toHTMLDecimalEntities(payload)
	htmlHexEntities := toHTMLHexEntities(payload, false)
	htmlHexEntitiesUpper := toHTMLHexEntities(payload, true)
	namedEntities := toNamedEntities(payload)

	// Add basic variants
	variants = append(variants,
		htmlDecimalEntities,    // Decimal HTML entities (&#104;&#101;&#108;&#108;&#111;)
		htmlHexEntities,        // Hex HTML entities (&#x68;&#x65;&#x6c;&#x6c;&#x6f;)
		htmlHexEntitiesUpper,   // Uppercase hex HTML entities (&#X68;&#X65;&#X6C;&#X6C;&#X6F;)
		namedEntities,          // Named entities (&lt;&gt;&quot;&amp;)
		mixedEntities(payload), // Mixed named and numeric entities
	)

	if level == types.EvasionLevelBasic {
		return evasions.UniqueStrings(variants)
	}

	variants = append(variants,
		partialHTMLEncoding(payload),       // Only encode special chars
		mixedCaseEntities(payload),         // Mixed case in hex entities (&#x6A;&#X6b;)
		entityWithoutSemicolon(payload),    // Some entities without semicolons
		unnecessaryLeadingZeros(payload),   // Extra zeros (&#00104;&#x00068;)
		jsInHtmlContext(payload),           // JavaScript syntax in HTML context
		entitiesWithComments(payload),      // Entities with HTML comments
		doubleEncodedEntities(payload),     // Double-encoded entities
		attributeEncodingVariants(payload), // Attribute encoding variants
	)

	if level == types.EvasionLevelMedium {
		return evasions.UniqueStrings(variants)
	}

	variants = append(variants,
		multipleEncodingLayers(payload),    // Multiple encoding layers
		cssEscapeSequences(payload),        // CSS escape sequences
		urlEncodedEntities(payload),        // URL-encoded entities
		invalidEntityPadding(payload),      // Invalid padding in entities
		caseNormalizationTrick(payload),    // Case normalization tricks
		entityFragmentation(payload),       // Entity fragmentation with whitespace
		encodingWithBase(payload),          // Using different bases (decimal, octal, hex)
		nonStandardEntityFormats(payload),  // Non-standard entity formats
		conditionalCommentsBypass(payload), // Conditional comments bypass
		dataAttributeObfuscation(payload),  // Data attribute obfuscation
		svgContentEncoding(payload),        // SVG content encoding
		templateOverrideEncoding(payload),  // Template override encoding
		javascriptEscapeSequences(payload), // JavaScript escape sequences in HTML
		encodingWithCharacterSets(payload), // Character set tricks
	)

	return evasions.UniqueStrings(variants)
}

func toHTMLDecimalEntities(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		b.WriteString(fmt.Sprintf("&#%d;", c))
	}
	return b.String()
}

func toHTMLHexEntities(s string, uppercase bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if uppercase {
			b.WriteString(fmt.Sprintf("&#X%X;", c))
		} else {
			b.WriteString(fmt.Sprintf("&#x%x;", c))
		}
	}
	return b.String()
}

func toNamedEntities(s string) string {
	entities := map[byte]string{
		'<':  "&lt;",
		'>':  "&gt;",
		'"':  "&quot;",
		'\'': "&apos;",
		'&':  "&amp;",
		'¢':  "&cent;",
		'£':  "&pound;",
		'¥':  "&yen;",
		// '€':  "&euro;",
		'©': "&copy;",
		'®': "&reg;",
	}

	var b strings.Builder
	for _, c := range []byte(s) {
		if entity, ok := entities[c]; ok {
			b.WriteString(entity)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func mixedEntities(s string) string {
	entities := map[byte]string{
		'<':  "&lt;",
		'>':  "&gt;",
		'"':  "&quot;",
		'\'': "&apos;",
		'&':  "&amp;",
	}

	var b strings.Builder
	for i, c := range []byte(s) {
		if entity, ok := entities[c]; ok {
			b.WriteString(entity)
		} else {
			if i%3 == 0 {
				b.WriteString(fmt.Sprintf("&#%d;", c))
			} else if i%3 == 1 {
				b.WriteString(fmt.Sprintf("&#x%x;", c))
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func partialHTMLEncoding(s string) string {
	toEncode := map[byte]bool{
		'<': true, '>': true, '&': true, '"': true, '\'': true,
		';': true, '(': true, ')': true, '{': true, '}': true,
	}

	var b strings.Builder
	for _, c := range []byte(s) {
		if toEncode[c] || rand.Intn(3) == 0 {
			if rand.Intn(2) == 0 {
				b.WriteString(fmt.Sprintf("&#%d;", c))
			} else {
				b.WriteString(fmt.Sprintf("&#x%x;", c))
			}
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func mixedCaseEntities(s string) string {
	var b strings.Builder
	for i, c := range []byte(s) {
		if i%2 == 0 {
			b.WriteString(fmt.Sprintf("&#x%x;", c))
		} else {
			b.WriteString(fmt.Sprintf("&#X%X;", c))
		}
	}
	return b.String()
}

func entityWithoutSemicolon(s string) string {
	var b strings.Builder
	for i, c := range []byte(s) {
		if i%3 == 0 {
			b.WriteString(fmt.Sprintf("&#%d", c))
		} else {
			b.WriteString(fmt.Sprintf("&#%d;", c))
		}
	}
	return b.String()
}

func unnecessaryLeadingZeros(s string) string {
	var b strings.Builder
	for i, c := range []byte(s) {
		if i%2 == 0 {
			zeros := rand.Intn(4) + 2
			b.WriteString(fmt.Sprintf("&#%0*d;", zeros+len(fmt.Sprintf("%d", c)), c))
		} else {
			zeros := rand.Intn(4) + 2
			b.WriteString(fmt.Sprintf("&#x%0*x;", zeros+len(fmt.Sprintf("%x", c)), c))
		}
	}
	return b.String()
}

func jsInHtmlContext(s string) string {
	var b strings.Builder
	b.WriteString("<script>document.write('")

	for _, c := range []byte(s) {
		switch rand.Intn(3) {
		case 0:
			b.WriteString(fmt.Sprintf("\\x%02x", c))
		case 1:
			b.WriteString(fmt.Sprintf("\\u00%02x", c))
		case 2:
			b.WriteByte(c)
		}
	}

	b.WriteString("');</script>")
	return b.String()
}

func entitiesWithComments(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		b.WriteString("&#")
		if rand.Intn(2) == 0 {
			b.WriteString("<!---->")
		}
		b.WriteString(fmt.Sprintf("%d;", c))
	}
	return b.String()
}

func doubleEncodedEntities(s string) string {
	// First encode
	firstPass := toHTMLHexEntities(s, false)

	// Then encode again
	var b strings.Builder
	for _, c := range []byte(firstPass) {
		b.WriteString(fmt.Sprintf("&#%d;", c))
	}

	return b.String()
}

func attributeEncodingVariants(s string) string {
	var b strings.Builder
	b.WriteString("<div title=\"")

	for _, c := range []byte(s) {
		switch rand.Intn(3) {
		case 0:
			b.WriteString(fmt.Sprintf("&#%d;", c))
		case 1:
			b.WriteString(fmt.Sprintf("&#x%x;", c))
		case 2:
			if c == '"' {
				b.WriteString("&quot;")
			} else {
				b.WriteByte(c)
			}
		}
	}

	b.WriteString("\"></div>")
	return b.String()
}

func multipleEncodingLayers(s string) string {
	firstPass := toHTMLHexEntities(s, false)
	var b strings.Builder
	for _, c := range []byte(firstPass) {
		b.WriteString(fmt.Sprintf("%%%02X", c))
	}

	return "<div data-content=\"" + b.String() + "\"></div>"
}

func cssEscapeSequences(s string) string {
	var b strings.Builder
	b.WriteString("<style>content:'")

	for _, c := range []byte(s) {
		b.WriteString(fmt.Sprintf("\\%x ", c))
	}

	b.WriteString("';</style>")
	return b.String()
}

func urlEncodedEntities(s string) string {
	var b strings.Builder

	for _, c := range []byte(s) {
		b.WriteString("%26%23")
		b.WriteString(fmt.Sprintf("%d;", c))
	}

	return b.String()
}

func invalidEntityPadding(s string) string {
	var b strings.Builder

	for _, c := range []byte(s) {
		switch rand.Intn(3) {
		case 0:
			b.WriteString(fmt.Sprintf("&#\u200B%d;", c))
		case 1:
			b.WriteString(fmt.Sprintf("&# %d;", c))
		case 2:
			b.WriteString(fmt.Sprintf("&#\t%d;", c))
		}
	}

	return b.String()
}

func caseNormalizationTrick(s string) string {
	var b strings.Builder

	specialChars := map[byte]string{
		'<': "&LT;",
		'>': "&GT;",
		'&': "&AMP;",
	}

	for _, c := range []byte(s) {
		if entity, ok := specialChars[c]; ok {
			b.WriteString(entity)
		} else {
			b.WriteByte(c)
		}
	}

	return b.String()
}

func entityFragmentation(s string) string {
	var b strings.Builder

	for _, c := range []byte(s) {
		b.WriteString(fmt.Sprintf("&#%d\r;", c))
	}

	return b.String()
}

func encodingWithBase(s string) string {
	var b strings.Builder

	for i, c := range []byte(s) {
		switch i % 3 {
		case 0:
			// Decimal
			b.WriteString(fmt.Sprintf("&#%d;", c))
		case 1:
			// Octal (as decimal)
			octal := fmt.Sprintf("%o", c)
			decimal, _ := parseInt(octal, 8)
			b.WriteString(fmt.Sprintf("&#%d;", decimal))
		case 2:
			// Hexadecimal
			b.WriteString(fmt.Sprintf("&#x%x;", c))
		}
	}

	return b.String()
}

func parseInt(s string, base int) (int, error) {
	result := 0
	for _, c := range s {
		var val int
		if '0' <= c && c <= '9' {
			val = int(c - '0')
		} else if 'a' <= c && c <= 'z' {
			val = int(c - 'a' + 10)
		} else if 'A' <= c && c <= 'Z' {
			val = int(c - 'A' + 10)
		} else {
			return 0, fmt.Errorf("invalid character: %c", c)
		}
		if val >= base {
			return 0, fmt.Errorf("invalid digit for base %d: %c", base, c)
		}
		result = result*base + val
	}
	return result, nil
}

// nonStandardEntityFormats creates non-standard entity formats
func nonStandardEntityFormats(s string) string {
	var b strings.Builder

	for i, c := range []byte(s) {
		switch i % 4 {
		case 0:
			b.WriteString(fmt.Sprintf("&#x%X;", c))
		case 1:
			b.WriteString(fmt.Sprintf("&#x%x;", c))
		case 2:
			b.WriteString(fmt.Sprintf(";&&#%d;", c))
		case 3:
			if c > 127 || c < 32 {
				b.WriteString(fmt.Sprintf("&#%d;", c))
			} else {
				b.WriteByte(c)
			}
		}
	}

	return b.String()
}

func conditionalCommentsBypass(s string) string {
	var b strings.Builder

	b.WriteString("<!--[if gte IE 4]>\n")
	for _, c := range []byte(s) {
		b.WriteString(fmt.Sprintf("&#%d;", c))
	}

	b.WriteString("\n<![endif]-->")
	return b.String()
}

func dataAttributeObfuscation(s string) string {
	var parts []string

	for i, c := range []byte(s) {
		parts = append(parts, fmt.Sprintf("data-%d=\"&#%d;\"", i, c))
	}

	return "<div " + strings.Join(parts, " ") + "></div>"
}

func svgContentEncoding(s string) string {
	var b strings.Builder

	b.WriteString("<svg><script type=\"text/javascript\"><![CDATA[\n")
	b.WriteString("document.write('")

	for _, c := range []byte(s) {
		b.WriteString(fmt.Sprintf("&#%d;", c))
	}

	b.WriteString("');\n]]></script></svg>")
	return b.String()
}

func templateOverrideEncoding(s string) string {
	var parts []string

	for i, c := range []byte(s) {
		parts = append(parts, fmt.Sprintf("${%d:&#%d;}", i, c))
	}

	return strings.Join(parts, "")
}

func javascriptEscapeSequences(s string) string {
	var b strings.Builder

	b.WriteString("<script>var x = '")

	for _, c := range []byte(s) {
		switch rand.Intn(4) {
		case 0:
			b.WriteString(fmt.Sprintf("\\x%02x", c))
		case 1:
			b.WriteString(fmt.Sprintf("\\u00%02x", c))
		case 2:
			b.WriteString(fmt.Sprintf("\\%o", c))
		case 3:
			if c >= 32 && c <= 126 && c != '\'' && c != '\\' {
				b.WriteByte(c)
			} else {
				b.WriteString(fmt.Sprintf("\\x%02x", c))
			}
		}
	}

	b.WriteString("';</script>")
	return b.String()
}

func encodingWithCharacterSets(s string) string {
	var b strings.Builder

	b.WriteString("<meta charset=\"utf-7\"><div>")

	for _, c := range []byte(s) {
		b.WriteString(fmt.Sprintf("+%c-", c))
	}

	b.WriteString("</div>")
	return b.String()
}
