package util

import (
	"fmt"
	"strings"

	"obfuskit/internal/constants"
)

// DetectAttackType uses heuristics to guess the attack type from a payload
func DetectAttackType(payload string) string {
	payload = strings.ToLower(payload)
	if strings.Contains(payload, "<script") || strings.Contains(payload, "javascript:") ||
		strings.Contains(payload, "onerror") || strings.Contains(payload, "onload") {
		return "xss"
	}
	if strings.Contains(payload, "union") || strings.Contains(payload, "select") ||
		strings.Contains(payload, "' or ") || strings.Contains(payload, "1=1") {
		return "sqli"
	}
	if strings.Contains(payload, "../") || strings.Contains(payload, "..\\") ||
		strings.Contains(payload, "/etc/passwd") || strings.Contains(payload, "c:\\windows") {
		return "path"
	}
	if strings.Contains(payload, "cmd") || strings.Contains(payload, "bash") ||
		strings.Contains(payload, "powershell") || strings.Contains(payload, "wget") {
		return "unixcmdi"
	}
	return "generic"
}

// ParseEvasionLevel converts a string to a constants.Level
func ParseEvasionLevel(level string) constants.Level {
	switch strings.ToLower(level) {
	case "basic":
		return constants.Basic
	case "medium":
		return constants.Medium
	case "advanced":
		return constants.Advanced
	default:
		fmt.Printf("Warning: Unknown evasion level '%s', using 'medium' as default\n", level)
		return constants.Medium
	}
}
