package encoders

// BestFitsVariants generates various best fit encoded variants of the input payload
import (
	"fmt"
	"obfuskit/types"
	"strings"
	"unicode/utf8"
)

// BestFitVariants generates payloads using best-fit character mappings
// These mappings exploit character normalization and font rendering differences
func BestFitVariants(payload string, level types.EvasionLevel) []string {
	var variants []string

	switch level {
	case types.EvasionLevelBasic:
		// Basic best-fit mappings
		variants = append(variants, basicBestFit(payload)...)
	case types.EvasionLevelMedium:
		// Add more sophisticated mappings
		variants = append(variants, basicBestFit(payload)...)
		variants = append(variants, advancedBestFit(payload)...)
	case types.EvasionLevelAdvanced:
		// Full spectrum of best-fit evasions
		variants = append(variants, basicBestFit(payload)...)
		variants = append(variants, advancedBestFit(payload)...)
		variants = append(variants, expertBestFit(payload)...)
	}

	return variants
}

// basicBestFit applies common best-fit character substitutions
func basicBestFit(payload string) []string {
	var variants []string

	// Common best-fit mappings
	bestFitMappings := map[rune][]string{
		'a': {"à", "á", "â", "ã", "ä", "å", "ā", "ă", "ą", "ǎ", "ǻ", "ά", "α", "а"},
		'A': {"À", "Á", "Â", "Ã", "Ä", "Å", "Ā", "Ă", "Ą", "Ǎ", "Ǻ", "Α", "А"},
		'e': {"è", "é", "ê", "ë", "ē", "ĕ", "ė", "ę", "ě", "έ", "ε", "е"},
		'E': {"È", "É", "Ê", "Ë", "Ē", "Ĕ", "Ė", "Ę", "Ě", "Ε", "Е"},
		'i': {"ì", "í", "î", "ï", "ĩ", "ī", "ĭ", "į", "ǐ", "ί", "ι", "і"},
		'I': {"Ì", "Í", "Î", "Ï", "Ĩ", "Ī", "Ĭ", "Į", "Ǐ", "Ι", "І"},
		'o': {"ò", "ó", "ô", "õ", "ö", "ø", "ō", "ŏ", "ő", "ǒ", "ό", "ο", "о"},
		'O': {"Ò", "Ó", "Ô", "Õ", "Ö", "Ø", "Ō", "Ŏ", "Ő", "Ǒ", "Ο", "О"},
		'u': {"ù", "ú", "û", "ü", "ũ", "ū", "ŭ", "ů", "ű", "ų", "ǔ", "ύ", "υ", "у"},
		'U': {"Ù", "Ú", "Û", "Ü", "Ũ", "Ū", "Ŭ", "Ů", "Ű", "Ų", "Ǔ", "Υ", "У"},
		'n': {"ñ", "ń", "ņ", "ň", "ŉ", "ŋ", "ǹ", "ή", "η", "н"},
		'N': {"Ñ", "Ń", "Ņ", "Ň", "Ŋ", "Ǹ", "Η", "Н"},
		'c': {"ç", "ć", "ĉ", "ċ", "č", "ς", "с"},
		'C': {"Ç", "Ć", "Ĉ", "Ċ", "Č", "Ξ", "С"},
		's': {"ś", "ŝ", "ş", "š", "ς", "σ", "с"},
		'S': {"Ś", "Ŝ", "Ş", "Š", "Σ", "С"},
		'z': {"ź", "ż", "ž", "ζ", "з"},
		'Z': {"Ź", "Ż", "Ž", "Ζ", "З"},
		'y': {"ý", "ÿ", "ŷ", "ύ", "υ", "у"},
		'Y': {"Ý", "Ÿ", "Ŷ", "Υ", "У"},
		'r': {"ŕ", "ŗ", "ř", "ρ", "р"},
		'R': {"Ŕ", "Ŗ", "Ř", "Ρ", "Р"},
		'l': {"ĺ", "ļ", "ľ", "ŀ", "ł", "λ", "л"},
		'L': {"Ĺ", "Ļ", "Ľ", "Ŀ", "Ł", "Λ", "Л"},
		't': {"ţ", "ť", "ŧ", "τ", "т"},
		'T': {"Ţ", "Ť", "Ŧ", "Τ", "Т"},
		'd': {"ď", "đ", "δ", "д"},
		'D': {"Ď", "Đ", "Δ", "Д"},
		'g': {"ĝ", "ğ", "ġ", "ģ", "γ", "г"},
		'G': {"Ĝ", "Ğ", "Ġ", "Ģ", "Γ", "Г"},
		'h': {"ĥ", "ħ", "η", "х"},
		'H': {"Ĥ", "Ħ", "Η", "Х"},
		'j': {"ĵ", "ј"},
		'J': {"Ĵ", "Ј"},
		'k': {"ķ", "ĸ", "κ", "к"},
		'K': {"Ķ", "Κ", "К"},
		'p': {"π", "п"},
		'P': {"Π", "П"},
		'b': {"β", "б"},
		'B': {"Β", "Б"},
		'v': {"ν", "в"},
		'V': {"Ν", "В"},
		'w': {"ŵ", "ω", "в"},
		'W': {"Ŵ", "Ω", "В"},
		'm': {"μ", "м"},
		'M': {"Μ", "М"},
		'f': {"φ", "ф"},
		'F': {"Φ", "Ф"},
		'x': {"χ", "х"},
		'X': {"Χ", "Х"},
		'q': {"θ"},
		'Q': {"Θ"},
	}

	// Generate variants by substituting each character
	for char, substitutes := range bestFitMappings {
		for _, substitute := range substitutes {
			if strings.ContainsRune(payload, char) {
				variant := strings.ReplaceAll(payload, string(char), substitute)
				variants = append(variants, variant)
			}
		}
	}

	return variants
}

// advancedBestFit applies more sophisticated best-fit mappings
func advancedBestFit(payload string) []string {
	var variants []string

	// Homograph attack mappings (visually similar characters)
	homographMappings := map[rune][]string{
		'0': {"О", "Ο", "۰", "०", "੦", "૦", "௦", "೦", "൦", "๐", "໐", "၀", "፰", "០"},
		'1': {"l", "I", "ı", "ɩ", "ɪ", "ʟ", "ᶖ", "ᵢ", "ᶦ", "ᵎ", "ᴉ", "ᴍ", "ľ", "ӏ", "ɾ"},
		'2': {"Ƨ", "ᒿ", "ᒻ", "ᒾ", "ᒽ", "ᒼ", "ᒺ", "ᒹ", "ᒸ", "ᒷ", "ᒶ", "ᒵ", "ᒴ", "ᒳ", "ᒲ"},
		'3': {"Ʒ", "Ȝ", "Ƹ", "Ɜ", "Ɛ", "Ӡ", "Ჳ", "Ȝ", "Ƹ", "Ɜ", "Ɛ", "Ӡ", "Ჳ"},
		'4': {"Ꮞ", "Ꮡ", "Ꮤ", "Ꮥ", "Ꮦ", "Ꮧ", "Ꮨ", "Ꮩ", "Ꮪ", "Ꮫ", "Ꮬ", "Ꮭ", "Ꮮ", "Ꮯ"},
		'5': {"Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ", "Ƽ"},
		'6': {"Ϭ", "б", "Ϲ", "Ϻ", "Ϸ", "Ϸ", "Ϸ", "Ϸ", "Ϸ", "Ϸ", "Ϸ", "Ϸ", "Ϸ", "Ϸ"},
		'7': {"Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ", "Ɂ"},
		'8': {"Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ", "Ȣ"},
		'9': {"Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ", "Ꝯ"},

		// Lookalike ASCII characters
		'a': {"ɑ", "α", "а", "ɐ", "ɒ", "ǝ", "ə", "ɚ", "ɛ", "ɜ", "ɝ", "ɞ", "ɟ", "ɠ"},
		'e': {"ɘ", "ә", "ɚ", "ɛ", "ɜ", "ɝ", "ɞ", "ɟ", "ɠ", "ɡ", "ɢ", "ɣ", "ɤ", "ɥ"},
		'o': {"ο", "σ", "ο", "ο", "ο", "ο", "ο", "ο", "ο", "ο", "ο", "ο", "ο", "ο"},
		'p': {"ρ", "р", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ", "ρ"},
		'y': {"ɣ", "у", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ", "ɣ"},
		'n': {"ո", "ռ", "ո", "ո", "ո", "ո", "ո", "ո", "ո", "ո", "ո", "ո", "ո", "ո"},
		'h': {"հ", "һ", "հ", "հ", "հ", "հ", "հ", "հ", "հ", "հ", "հ", "հ", "հ", "հ"},
		'v': {"ᴠ", "ѵ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ", "ᴠ"},
		'w': {"ԝ", "ω", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ", "ԝ"},
		'x': {"х", "χ", "х", "х", "х", "х", "х", "х", "х", "х", "х", "х", "х", "х"},
		'c': {"ϲ", "с", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ", "ϲ"},
		'd': {"ԁ", "ժ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ", "ԁ"},
		'f': {"ſ", "ք", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ", "ſ"},
		'g': {"ƍ", "ց", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ", "ƍ"},
		'i': {"і", "ı", "і", "і", "і", "і", "і", "і", "і", "і", "і", "і", "і", "і"},
		'j': {"ϳ", "ј", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ", "ϳ"},
		'l': {"ӏ", "ɩ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ", "ӏ"},
		'q': {"ԛ", "ϋ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ", "ԛ"},
		's': {"ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ", "ѕ"},
	}

	// Generate homograph variants
	for char, substitutes := range homographMappings {
		for _, substitute := range substitutes {
			if strings.ContainsRune(payload, char) {
				variant := strings.ReplaceAll(payload, string(char), substitute)
				variants = append(variants, variant)
			}
		}
	}

	return variants
}

// expertBestFit applies expert-level best-fit mappings
func expertBestFit(payload string) []string {
	var variants []string

	// Mixed script variants
	variants = append(variants, mixedScriptVariants(payload)...)

	// Contextual form variants
	variants = append(variants, contextualFormVariants(payload)...)

	// Zero-width and invisible character variants
	variants = append(variants, invisibleCharacterVariants(payload)...)

	// Mathematical and technical symbol variants
	variants = append(variants, mathematicalSymbolVariants(payload)...)

	// Modifier letter variants
	variants = append(variants, modifierLetterVariants(payload)...)

	return variants
}

// mixedScriptVariants creates variants mixing different writing systems
func mixedScriptVariants(payload string) []string {
	var variants []string

	// Latin-Cyrillic mixed scripts
	mixedMappings := map[rune]string{
		'a': "а", 'e': "е", 'o': "о", 'p': "р", 'c': "с", 'y': "у", 'x': "х",
		'A': "А", 'B': "В", 'C': "С", 'E': "Е", 'H': "Н", 'K': "К", 'M': "М",
		'O': "О", 'P': "Р", 'T': "Т", 'X': "Х", 'Y': "У",
	}

	// Apply mixed script substitutions
	for i := 0; i < len(payload); i++ {
		if replacement, exists := mixedMappings[rune(payload[i])]; exists {
			variant := payload[:i] + replacement + payload[i+1:]
			variants = append(variants, variant)
		}
	}

	return variants
}

// contextualFormVariants creates variants using contextual character forms
func contextualFormVariants(payload string) []string {
	var variants []string

	// Arabic contextual forms
	arabicForms := map[rune][]string{
		'ا': {"ﺍ", "ﺎ"},           // Alef
		'ب': {"ﺏ", "ﺐ", "ﺑ", "ﺒ"}, // Beh
		'ت': {"ﺕ", "ﺖ", "ﺗ", "ﺘ"}, // Teh
		'ث': {"ﺙ", "ﺚ", "ﺛ", "ﺜ"}, // Theh
		'ج': {"ﺝ", "ﺞ", "ﺟ", "ﺠ"}, // Jeem
		'ح': {"ﺡ", "ﺢ", "ﺣ", "ﺤ"}, // Hah
		'خ': {"ﺥ", "ﺦ", "ﺧ", "ﺨ"}, // Khah
		'د': {"ﺩ", "ﺪ"},           // Dal
		'ذ': {"ﺫ", "ﺬ"},           // Thal
		'ر': {"ﺭ", "ﺮ"},           // Reh
		'ز': {"ﺯ", "ﺰ"},           // Zain
		'س': {"ﺱ", "ﺲ", "ﺳ", "ﺴ"}, // Seen
		'ش': {"ﺵ", "ﺶ", "ﺷ", "ﺸ"}, // Sheen
		'ص': {"ﺹ", "ﺺ", "ﺻ", "ﺼ"}, // Sad
		'ض': {"ﺽ", "ﺾ", "ﺿ", "ﻀ"}, // Dad
		'ط': {"ﻁ", "ﻂ", "ﻃ", "ﻄ"}, // Tah
		'ظ': {"ﻅ", "ﻆ", "ﻇ", "ﻈ"}, // Zah
		'ع': {"ﻉ", "ﻊ", "ﻋ", "ﻌ"}, // Ain
		'غ': {"ﻍ", "ﻎ", "ﻏ", "ﻐ"}, // Ghain
		'ف': {"ﻑ", "ﻒ", "ﻓ", "ﻔ"}, // Feh
		'ق': {"ﻕ", "ﻖ", "ﻗ", "ﻘ"}, // Qaf
		'ك': {"ﻙ", "ﻚ", "ﻛ", "ﻜ"}, // Kaf
		'ل': {"ﻝ", "ﻞ", "ﻟ", "ﻠ"}, // Lam
		'م': {"ﻡ", "ﻢ", "ﻣ", "ﻤ"}, // Meem
		'ن': {"ﻥ", "ﻦ", "ﻧ", "ﻨ"}, // Noon
		'ه': {"ﻩ", "ﻪ", "ﻫ", "ﻬ"}, // Heh
		'و': {"ﻭ", "ﻮ"},           // Waw
		'ي': {"ﻱ", "ﻲ", "ﻳ", "ﻴ"}, // Yeh
	}

	// Apply contextual form substitutions
	for char, forms := range arabicForms {
		for _, form := range forms {
			if strings.ContainsRune(payload, char) {
				variant := strings.ReplaceAll(payload, string(char), form)
				variants = append(variants, variant)
			}
		}
	}

	return variants
}

// invisibleCharacterVariants creates variants using invisible/zero-width characters
func invisibleCharacterVariants(payload string) []string {
	var variants []string

	// Zero-width characters
	zeroWidthChars := []string{
		"\u200B", // Zero Width Space
		"\u200C", // Zero Width Non-Joiner
		"\u200D", // Zero Width Joiner
		"\u2060", // Word Joiner
		"\uFEFF", // Zero Width No-Break Space
		"\u034F", // Combining Grapheme Joiner
	}

	// Insert zero-width characters between normal characters
	for _, zwChar := range zeroWidthChars {
		// Insert at beginning
		variants = append(variants, zwChar+payload)
		// Insert at end
		variants = append(variants, payload+zwChar)
		// Insert between each character
		var insertedVariant strings.Builder
		for i, char := range payload {
			insertedVariant.WriteRune(char)
			if i < len(payload)-1 {
				insertedVariant.WriteString(zwChar)
			}
		}
		variants = append(variants, insertedVariant.String())
	}

	// Invisible characters that might render as spaces
	invisibleChars := []string{
		"\u00A0", // Non-Breaking Space
		"\u1680", // Ogham Space Mark
		"\u2000", // En Quad
		"\u2001", // Em Quad
		"\u2002", // En Space
		"\u2003", // Em Space
		"\u2004", // Three-Per-Em Space
		"\u2005", // Four-Per-Em Space
		"\u2006", // Six-Per-Em Space
		"\u2007", // Figure Space
		"\u2008", // Punctuation Space
		"\u2009", // Thin Space
		"\u200A", // Hair Space
		"\u202F", // Narrow No-Break Space
		"\u205F", // Medium Mathematical Space
		"\u3000", // Ideographic Space
	}

	// Replace spaces with invisible characters
	for _, invisChar := range invisibleChars {
		if strings.Contains(payload, " ") {
			variant := strings.ReplaceAll(payload, " ", invisChar)
			variants = append(variants, variant)
		}
	}

	return variants
}

// mathematicalSymbolVariants creates variants using mathematical and technical symbols
func mathematicalSymbolVariants(payload string) []string {
	var variants []string

	// Mathematical alphanumeric symbols
	mathMappings := map[rune][]string{
		'A': {"𝐀", "𝐴", "𝑨", "𝒜", "𝓐", "𝔄", "𝔸", "𝖠", "𝗔", "𝘈", "𝙰", "𝚨", "𝛢", "𝜜", "𝝖"},
		'B': {"𝐁", "𝐵", "𝑩", "ℬ", "𝓑", "𝔅", "𝔹", "𝖡", "𝗕", "𝘉", "𝙱", "𝚩", "𝛣", "𝜝", "𝝗"},
		'C': {"𝐂", "𝐶", "𝑪", "𝒞", "𝓒", "ℭ", "ℂ", "𝖢", "𝗖", "𝘊", "𝙲", "𝚪", "𝛤", "𝜞", "𝝘"},
		'D': {"𝐃", "𝐷", "𝑫", "𝒟", "𝓓", "𝔇", "𝔻", "𝖣", "𝗗", "𝘋", "𝙳", "𝚫", "𝛥", "𝜟", "𝝙"},
		'E': {"𝐄", "𝐸", "𝑬", "ℰ", "𝓔", "𝔈", "𝔼", "𝖤", "𝗘", "𝘌", "𝙴", "𝚬", "𝛦", "𝜠", "𝝚"},
		'F': {"𝐅", "𝐹", "𝑭", "ℱ", "𝓕", "𝔉", "𝔽", "𝖥", "𝗙", "𝘍", "𝙵", "𝚭", "𝛧", "𝜡", "𝝛"},
		'G': {"𝐆", "𝐺", "𝑮", "𝒢", "𝓖", "𝔊", "𝔾", "𝖦", "𝗚", "𝘎", "𝙶", "𝚮", "𝛨", "𝜢", "𝝜"},
		'H': {"𝐇", "𝐻", "𝑯", "ℋ", "𝓗", "ℌ", "ℍ", "𝖧", "𝗛", "𝘏", "𝙷", "𝚯", "𝛩", "𝜣", "𝝝"},
		'I': {"𝐈", "𝐼", "𝑰", "ℐ", "𝓘", "ℑ", "𝕀", "𝖨", "𝗜", "𝘐", "𝙸", "𝚰", "𝛪", "𝜤", "𝝞"},
		'J': {"𝐉", "𝐽", "𝑱", "𝒥", "𝓙", "𝔍", "𝕁", "𝖩", "𝗝", "𝘑", "𝙹", "𝚱", "𝛫", "𝜥", "𝝟"},
		'K': {"𝐊", "𝐾", "𝑲", "𝒦", "𝓚", "𝔎", "𝕂", "𝖪", "𝗞", "𝘒", "𝙺", "𝚲", "𝛬", "𝜦", "𝝠"},
		'L': {"𝐋", "𝐿", "𝑳", "ℒ", "𝓛", "𝔏", "𝕃", "𝖫", "𝗟", "𝘓", "𝙻", "𝚳", "𝛭", "𝜧", "𝝡"},
		'M': {"𝐌", "𝑀", "𝑴", "ℳ", "𝓜", "𝔐", "𝕄", "𝖬", "𝗠", "𝘔", "𝙼", "𝚴", "𝛮", "𝜨", "𝝢"},
		'N': {"𝐍", "𝑁", "𝑵", "𝒩", "𝓝", "𝔑", "ℕ", "𝖭", "𝗡", "𝘕", "𝙽", "𝚵", "𝛯", "𝜩", "𝝣"},
		'O': {"𝐎", "𝑂", "𝑶", "𝒪", "𝓞", "𝔒", "𝕆", "𝖮", "𝗢", "𝘖", "𝙾", "𝚶", "𝛰", "𝜪", "𝝤"},
		'P': {"𝐏", "𝑃", "𝑷", "𝒫", "𝓟", "𝔓", "ℙ", "𝖯", "𝗣", "𝘗", "𝙿", "𝚷", "𝛱", "𝜫", "𝝥"},
		'Q': {"𝐐", "𝑄", "𝑸", "𝒬", "𝓠", "𝔔", "ℚ", "𝖰", "𝗤", "𝘘", "𝚀", "𝚸", "𝛲", "𝜬", "𝝦"},
		'R': {"𝐑", "𝑅", "𝑹", "ℛ", "𝓡", "ℜ", "ℝ", "𝖱", "𝗥", "𝘙", "𝚁", "𝚹", "𝛳", "𝜭", "𝝧"},
		'S': {"𝐒", "𝑆", "𝑺", "𝒮", "𝓢", "𝔖", "𝕊", "𝖲", "𝗦", "𝘚", "𝚂", "𝚺", "𝛴", "𝜮", "𝝨"},
		'T': {"𝐓", "𝑇", "𝑻", "𝒯", "𝓣", "𝔗", "𝕋", "𝖳", "𝗧", "𝘛", "𝚃", "𝚻", "𝛵", "𝜯", "𝝩"},
		'U': {"𝐔", "𝑈", "𝑼", "𝒰", "𝓤", "𝔘", "𝕌", "𝖴", "𝗨", "𝘜", "𝚄", "𝚼", "𝛶", "𝜰", "𝝪"},
		'V': {"𝐕", "𝑉", "𝑽", "𝒱", "𝓥", "𝔙", "𝕍", "𝖵", "𝗩", "𝘝", "𝚅", "𝚽", "𝛷", "𝜱", "𝝫"},
		'W': {"𝐖", "𝑊", "𝑾", "𝒲", "𝓦", "𝔚", "𝕎", "𝖶", "𝗪", "𝘞", "𝚆", "𝚾", "𝛸", "𝜲", "𝝬"},
		'X': {"𝐗", "𝑋", "𝑿", "𝒳", "𝓧", "𝔛", "𝕏", "𝖷", "𝗫", "𝘟", "𝚇", "𝚿", "𝛹", "𝜳", "𝝭"},
		'Y': {"𝐘", "𝑌", "𝒀", "𝒴", "𝓨", "𝔜", "𝕐", "𝖸", "𝗬", "𝘠", "𝚈", "𝛀", "𝛺", "𝜴", "𝝮"},
		'Z': {"𝐙", "𝑍", "𝒁", "𝒵", "𝓩", "ℨ", "ℤ", "𝖹", "𝗭", "𝘡", "𝚉", "𝛁", "𝛻", "𝜵", "𝝯"},

		// Lowercase mathematical symbols
		'a': {"𝐚", "𝑎", "𝒂", "𝒶", "𝓪", "𝔞", "𝕒", "𝖺", "𝗮", "𝘢", "𝙖", "𝚊", "𝛂", "𝜶", "𝝰"},
		'b': {"𝐛", "𝑏", "𝒃", "𝒷", "𝓫", "𝔟", "𝕓", "𝖻", "𝗯", "𝘣", "𝙗", "𝚋", "𝛃", "𝜷", "𝝱"},
		'c': {"𝐜", "𝑐", "𝒄", "𝒸", "𝓬", "𝔠", "𝕔", "𝖼", "𝗰", "𝘤", "𝙘", "𝚌", "𝛄", "𝜸", "𝝲"},
		'd': {"𝐝", "𝑑", "𝒅", "𝒹", "𝓭", "𝔡", "𝕕", "𝖽", "𝗱", "𝘥", "𝙙", "𝚍", "𝛅", "𝜹", "𝝳"},
		'e': {"𝐞", "𝑒", "𝒆", "ℯ", "𝓮", "𝔢", "𝕖", "𝖾", "𝗲", "𝘦", "𝙚", "𝚎", "𝛆", "𝜺", "𝝴"},
		'f': {"𝐟", "𝑓", "𝒇", "𝒻", "𝓯", "𝔣", "𝕗", "𝖿", "𝗳", "𝘧", "𝙛", "𝚏", "𝛇", "𝜻", "𝝵"},
		'g': {"𝐠", "𝑔", "𝒈", "ℊ", "𝓰", "𝔤", "𝕘", "𝗀", "𝗴", "𝘨", "𝙜", "𝚐", "𝛈", "𝜼", "𝝶"},
		'h': {"𝐡", "ℎ", "𝒉", "𝒽", "𝓱", "𝔥", "𝕙", "𝗁", "𝗵", "𝘩", "𝙝", "𝚑", "𝛉", "𝜽", "𝝷"},
		'i': {"𝐢", "𝑖", "𝒊", "𝒾", "𝓲", "𝔦", "𝕚", "𝗂", "𝗶", "𝘪", "𝙞", "𝚒", "𝛊", "𝜾", "𝝸"},
		'j': {"𝐣", "𝑗", "𝒋", "𝒿", "𝓳", "𝔧", "𝕛", "𝗃", "𝗷", "𝘫", "𝙟", "𝚓", "𝛋", "𝜿", "𝝹"},
		'k': {"𝐤", "𝑘", "𝒌", "𝓀", "𝓴", "𝔨", "𝕜", "𝗄", "𝗸", "𝘬", "𝙠", "𝚔", "𝛌", "𝝀", "𝝺"},
		'l': {"𝐥", "𝑙", "𝒍", "𝓁", "𝓵", "𝔩", "𝕝", "𝗅", "𝗹", "𝘭", "𝙡", "𝚕", "𝛍", "𝝁", "𝝻"},
		'm': {"𝐦", "𝑚", "𝒎", "𝓂", "𝓶", "𝔪", "𝕞", "𝗆", "𝗺", "𝘮", "𝙢", "𝚖", "𝛎", "𝝂", "𝝼"},
		'n': {"𝐧", "𝑛", "𝒏", "𝓃", "𝓷", "𝔫", "𝕟", "𝗇", "𝗻", "𝘯", "𝙣", "𝚗", "𝛏", "𝝃", "𝝽"},
		'o': {"𝐨", "𝑜", "𝒐", "ℴ", "𝓸", "𝔬", "𝕠", "𝗈", "𝗼", "𝘰", "𝙤", "𝚘", "𝛐", "𝝄", "𝝾"},
		'p': {"𝐩", "𝑝", "𝒑", "𝓅", "𝓹", "𝔭", "𝕡", "𝗉", "𝗽", "𝘱", "𝙥", "𝚙", "𝛑", "𝝅", "𝝿"},
		'q': {"𝐪", "𝑞", "𝒒", "𝓆", "𝓺", "𝔮", "𝕢", "𝗊", "𝗾", "𝘲", "𝙦", "𝚚", "𝛒", "𝝆", "𝞀"},
		'r': {"𝐫", "𝑟", "𝒓", "𝓇", "𝓻", "𝔯", "𝕣", "𝗋", "𝗿", "𝘳", "𝙧", "𝚛", "𝛓", "𝝇", "𝞁"},
		's': {"𝐬", "𝑠", "𝒔", "𝓈", "𝓼", "𝔰", "𝕤", "𝗌", "𝘀", "𝘴", "𝙨", "𝚜", "𝛔", "𝝈", "𝞂"},
		't': {"𝐭", "𝑡", "𝒕", "𝓉", "𝓽", "𝔱", "𝕥", "𝗍", "𝘁", "𝘵", "𝙩", "𝚝", "𝛕", "𝝉", "𝞃"},
		'u': {"𝐮", "𝑢", "𝒖", "𝓊", "𝓾", "𝔲", "𝕦", "𝗎", "𝘂", "𝘶", "𝙪", "𝚞", "𝛖", "𝝊", "𝞄"},
		'v': {"𝐯", "𝑣", "𝒗", "𝓋", "𝓿", "𝔳", "𝕧", "𝗏", "𝘃", "𝘷", "𝙫", "𝚟", "𝛗", "𝝋", "𝞅"},
		'w': {"𝐰", "𝑤", "𝒘", "𝓌", "𝔀", "𝔴", "𝕨", "𝗐", "𝘄", "𝘸", "𝙬", "𝚠", "𝛘", "𝝌", "𝞆"},
		'x': {"𝐱", "𝑥", "𝒙", "𝓍", "𝔁", "𝔵", "𝕩", "𝗑", "𝘅", "𝘹", "𝙭", "𝚡", "𝛙", "𝝍", "𝞇"},
		'y': {"𝐲", "𝑦", "𝒚", "𝓎", "𝔂", "𝔶", "𝕪", "𝗒", "𝘆", "𝘺", "𝙮", "𝚢", "𝛚", "𝝎", "𝞈"},
		'z': {"𝐳", "𝑧", "𝒛", "𝓏", "𝔃", "𝔷", "𝕫", "𝗓", "𝘇", "𝘻", "𝙯", "𝚣", "𝛛", "𝝏", "𝞉"},

		// Numbers
		'0': {"𝟎", "𝟘", "𝟢", "𝟬", "𝟶", "𝟘", "𝟢", "𝟬", "𝟶"},
		'1': {"𝟏", "𝟙", "𝟣", "𝟭", "𝟷", "𝟙", "𝟣", "𝟭", "𝟷"},
		'2': {"𝟐", "𝟚", "𝟤", "𝟮", "𝟸", "𝟚", "𝟤", "𝟮", "𝟸"},
		'3': {"𝟑", "𝟛", "𝟥", "𝟯", "𝟹", "𝟛", "𝟥", "𝟯", "𝟹"},
		'4': {"𝟒", "𝟜", "𝟦", "𝟰", "𝟺", "𝟜", "𝟦", "𝟰", "𝟺"},
		'5': {"𝟓", "𝟝", "𝟧", "𝟱", "𝟻", "𝟝", "𝟧", "𝟱", "𝟻"},
		'6': {"𝟔", "𝟞", "𝟨", "𝟲", "𝟼", "𝟞", "𝟨", "𝟲", "𝟼"},
		'7': {"𝟕", "𝟟", "𝟩", "𝟳", "𝟽", "𝟟", "𝟩", "𝟳", "𝟽"},
		'8': {"𝟖", "𝟠", "𝟪", "𝟴", "𝟾", "𝟠", "𝟪", "𝟴", "𝟾"},
		'9': {"𝟗", "𝟡", "𝟫", "𝟵", "𝟿", "𝟡", "𝟫", "𝟵", "𝟿"},
	}

	// Generate mathematical symbol variants
	for char, symbols := range mathMappings {
		for _, symbol := range symbols {
			if strings.ContainsRune(payload, char) {
				variant := strings.ReplaceAll(payload, string(char), symbol)
				variants = append(variants, variant)
			}
		}
	}

	return variants
}

// modifierLetterVariants creates variants using modifier letters and superscripts
func modifierLetterVariants(payload string) []string {
	var variants []string

	// Modifier letters and superscripts
	modifierMappings := map[rune][]string{
		'a': {"ᵃ", "ᵅ", "ᵆ", "ᵇ", "ᴬ", "ᴀ", "ᴁ", "ᴂ", "ᴃ", "ᴄ", "ᴅ", "ᴆ", "ᴇ", "ᴈ", "ᴉ"},
		'b': {"ᵇ", "ᵈ", "ᵉ", "ᵊ", "ᴮ", "ᴯ", "ᴰ", "ᴱ", "ᴲ", "ᴳ", "ᴴ", "ᴵ", "ᴶ", "ᴷ", "ᴸ"},
		'c': {"ᶜ", "ᶝ", "ᶞ", "ᶟ", "ᶠ", "ᶡ", "ᶢ", "ᶣ", "ᶤ", "ᶥ", "ᶦ", "ᶧ", "ᶨ", "ᶩ", "ᶪ"},
		'd': {"ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ", "ᵈ"},
		'e': {"ᵉ", "ᵋ", "ᵌ", "ᵍ", "ᵎ", "ᵏ", "ᵐ", "ᵑ", "ᵒ", "ᵓ", "ᵔ", "ᵕ", "ᵖ", "ᵗ", "ᵘ"},
		'f': {"ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ", "ᶠ"},
		'g': {"ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ", "ᵍ"},
		'h': {"ʰ", "ʱ", "ʲ", "ʳ", "ʴ", "ʵ", "ʶ", "ʷ", "ʸ", "ʹ", "ʺ", "ʻ", "ʼ", "ʽ", "ʾ"},
		'i': {"ⁱ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ", "ᵢ"},
		'j': {"ʲ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ", "ⱼ"},
		'k': {"ᵏ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ", "ₖ"},
		'l': {"ˡ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ", "ₗ"},
		'm': {"ᵐ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ", "ₘ"},
		'n': {"ⁿ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ", "ₙ"},
		'o': {"ᵒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ", "ₒ"},
		'p': {"ᵖ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ", "ₚ"},
		'r': {"ʳ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ", "ᵣ"},
		's': {"ˢ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ", "ₛ"},
		't': {"ᵗ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ", "ₜ"},
		'u': {"ᵘ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ", "ᵤ"},
		'v': {"ᵛ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ", "ᵥ"},
		'w': {"ʷ", "w", "w", "w", "w", "w", "w", "w", "w", "w", "w", "w", "w", "w", "w"},
		'x': {"ˣ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ", "ₓ"},
		'y': {"ʸ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ", "ᵧ"},
		'z': {"ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ", "ᶻ"},

		// Uppercase modifier letters
		'A': {"ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ", "ᴬ"},
		'B': {"ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ", "ᴮ"},
		'D': {"ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ", "ᴰ"},
		'E': {"ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ", "ᴱ"},
		'G': {"ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ", "ᴳ"},
		'H': {"ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ", "ᴴ"},
		'I': {"ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ", "ᴵ"},
		'J': {"ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ", "ᴶ"},
		'K': {"ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ", "ᴷ"},
		'L': {"ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ", "ᴸ"},
		'M': {"ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ", "ᴹ"},
		'N': {"ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ", "ᴺ"},
		'O': {"ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ", "ᴼ"},
		'P': {"ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ", "ᴾ"},
		'R': {"ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ", "ᴿ"},
		'T': {"ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ", "ᵀ"},
		'U': {"ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ", "ᵁ"},
		'V': {"ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ", "ⱽ"},
		'W': {"ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ", "ᵂ"},

		// Numbers as superscripts
		'0': {"⁰", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀", "₀"},
		'1': {"¹", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁", "₁"},
		'2': {"²", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂", "₂"},
		'3': {"³", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃", "₃"},
		'4': {"⁴", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄", "₄"},
		'5': {"⁵", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅", "₅"},
		'6': {"⁶", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆", "₆"},
		'7': {"⁷", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇", "₇"},
		'8': {"⁸", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈", "₈"},
		'9': {"⁹", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉", "₉"},

		// Common punctuation
		'+': {"⁺", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊", "₊"},
		'-': {"⁻", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋", "₋"},
		'=': {"⁼", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌", "₌"},
		'(': {"⁽", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍", "₍"},
		')': {"⁾", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎", "₎"},
	}

	// Generate modifier letter variants
	for char, modifiers := range modifierMappings {
		for _, modifier := range modifiers {
			if strings.ContainsRune(payload, char) {
				variant := strings.ReplaceAll(payload, string(char), modifier)
				variants = append(variants, variant)
			}
		}
	}

	return variants
}

// Helper function to validate UTF-8 and remove invalid sequences
func validateAndSanitizeVariants(variants []string) []string {
	var sanitized []string

	for _, variant := range variants {
		if utf8.ValidString(variant) && len(variant) > 0 {
			sanitized = append(sanitized, variant)
		}
	}

	return sanitized
}

// Helper function to deduplicate variants
func deduplicateVariants(variants []string) []string {
	seen := make(map[string]bool)
	var deduped []string

	for _, variant := range variants {
		if !seen[variant] {
			seen[variant] = true
			deduped = append(deduped, variant)
		}
	}

	return deduped
}

// Helper function to limit the number of variants returned
func limitVariants(variants []string, maxCount int) []string {
	if len(variants) <= maxCount {
		return variants
	}
	return variants[:maxCount]
}

// GenerateAllVariants is a convenience function that generates all possible variants
// with proper validation and deduplication
func GenerateAllVariants(payload string, level types.EvasionLevel, maxVariants int) []string {
	if payload == "" {
		return []string{}
	}

	// Generate variants based on level
	variants := BestFitVariants(payload, level)

	// Validate UTF-8 sequences
	variants = validateAndSanitizeVariants(variants)

	// Remove duplicates
	variants = deduplicateVariants(variants)

	// Limit the number of variants if specified
	if maxVariants > 0 {
		variants = limitVariants(variants, maxVariants)
	}

	return variants
}

// PrintVariants is a utility function for debugging/testing
func PrintVariants(payload string, level types.EvasionLevel, maxVariants int) {
	variants := GenerateAllVariants(payload, level, maxVariants)

	fmt.Printf("Original payload: %s\n", payload)
	fmt.Printf("Level: %s\n", level)
	fmt.Printf("Generated %d variants:\n", len(variants))

	for i, variant := range variants {
		fmt.Printf("%d: %s\n", i+1, variant)
	}
}

// GetVariantStats returns statistics about the generated variants
func GetVariantStats(payload string, level types.EvasionLevel) map[string]int {
	stats := make(map[string]int)

	// Count variants by type
	switch level {
	case types.EvasionLevelBasic:
		basic := basicBestFit(payload)
		stats["basic"] = len(deduplicateVariants(basic))
	case types.EvasionLevelMedium:
		basic := basicBestFit(payload)
		advanced := advancedBestFit(payload)
		stats["basic"] = len(deduplicateVariants(basic))
		stats["advanced"] = len(deduplicateVariants(advanced))
	case types.EvasionLevelAdvanced:
		basic := basicBestFit(payload)
		advanced := advancedBestFit(payload)
		expert := expertBestFit(payload)
		stats["basic"] = len(deduplicateVariants(basic))
		stats["advanced"] = len(deduplicateVariants(advanced))
		stats["expert"] = len(deduplicateVariants(expert))
	}

	// Total count
	allVariants := BestFitVariants(payload, level)
	stats["total_raw"] = len(allVariants)
	stats["total_unique"] = len(deduplicateVariants(allVariants))

	return stats
}
