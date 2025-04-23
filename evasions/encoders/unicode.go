package encoders

import (
	"fmt"
	"obfuskit/cmd"
	"strings"
	"unicode"
)

func UnicodeVariants(payload string, level cmd.Level) []string {
	var variants []string
	var (
		jsEscape      strings.Builder // \uXXXX
		jsCurlyEscape strings.Builder // \u{XXXX}
		htmlHexEntity strings.Builder // &#xXXXX;
		htmlDecEntity strings.Builder // &#DDDD;
		legacyEscape  strings.Builder // %uXXXX
		unicodeCodePt strings.Builder // U+XXXX
		// Only encode part of the payload - special characters .. type of an evasion.
		jsEscapePartly      strings.Builder // \uXXXX
		jsCurlyEscapePartly strings.Builder // \u{XXXX}
		htmlHexEntityPartly strings.Builder // &#xXXXX;
		htmlDecEntityPartly strings.Builder // &#DDDD;
		legacyEscapePartly  strings.Builder // %uXXXX
		unicodeCodePtPartly strings.Builder // U+XXXX
	)

	for _, r := range payload {
		code := fmt.Sprintf("%04X", r)

		jsEscape.WriteString(`\u` + code)
		jsCurlyEscape.WriteString(fmt.Sprintf(`\u{%X}`, r))
		htmlHexEntity.WriteString(`&#x` + code + `;`)
		htmlDecEntity.WriteString(fmt.Sprintf("&#%d;", r))
		legacyEscape.WriteString(`%u` + code)
		unicodeCodePt.WriteString(`U+` + code + ` `)
	}

	variants = append(variants,
		jsEscape.String(),
		jsCurlyEscape.String(),
		htmlHexEntity.String(),
		htmlDecEntity.String(),
		legacyEscape.String(),
		strings.TrimSpace(unicodeCodePt.String()),
	)

	if level == cmd.Basic {
		return uniqueStrings(variants)
	}

	for _, r := range payload {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			jsEscapePartly.WriteRune(r)
			jsCurlyEscapePartly.WriteRune(r)
			htmlHexEntityPartly.WriteRune(r)
			htmlDecEntityPartly.WriteRune(r)
			legacyEscapePartly.WriteRune(r)
			unicodeCodePtPartly.WriteRune(r)
			continue
		}

		code := fmt.Sprintf("%04X", r)
		jsEscapePartly.WriteString(`\u` + code)
		jsCurlyEscapePartly.WriteString(fmt.Sprintf(`\u{%X}`, r))
		htmlHexEntityPartly.WriteString(`&#x` + code + `;`)
		htmlDecEntityPartly.WriteString(fmt.Sprintf("&#%d;", r))
		legacyEscapePartly.WriteString(`%u` + code)
		unicodeCodePtPartly.WriteString(`U+` + code + ` `)
	}

	variants = append(variants,
		jsEscapePartly.String(),
		jsCurlyEscapePartly.String(),
		htmlHexEntityPartly.String(),
		htmlDecEntityPartly.String(),
		legacyEscapePartly.String(),
		strings.TrimSpace(unicodeCodePtPartly.String()),
	)

	if level == cmd.Medium {
		return uniqueStrings(variants)
	}

	// Add more bypasses: TODO: ADD ADVANCED BYPASSES FOR UNICODE

	return variants
}
