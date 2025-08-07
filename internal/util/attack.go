package util

import (
	"fmt"
	"strings"

	"obfuskit/types"
)

// DetectAttackType uses heuristics to guess the attack type from a payload
func DetectAttackType(payload string) types.AttackType {
	payload = strings.ToLower(payload)
	if strings.Contains(payload, "<script") || strings.Contains(payload, "javascript:") ||
		strings.Contains(payload, "onerror") || strings.Contains(payload, "onload") {
		return types.AttackTypeXSS
	}
	if strings.Contains(payload, "union") || strings.Contains(payload, "select") ||
		strings.Contains(payload, "' or ") || strings.Contains(payload, "1=1") {
		return types.AttackTypeSQLI
	}
	if strings.Contains(payload, "../") || strings.Contains(payload, "..\\") ||
		strings.Contains(payload, "/etc/passwd") || strings.Contains(payload, "c:\\windows") {
		return types.AttackTypePath
	}
	if strings.Contains(payload, "cmd") || strings.Contains(payload, "bash") ||
		strings.Contains(payload, "powershell") || strings.Contains(payload, "wget") {
		return types.AttackTypeUnixCMDI
	}
	return types.AttackTypeGeneric
}

// ParseEvasionLevel converts a string to a constants.Level
func ParseEvasionLevel(level string) types.EvasionLevel {
	switch strings.ToLower(level) {
	case "basic":
		return types.EvasionLevelBasic
	case "medium":
		return types.EvasionLevelMedium
	case "advanced":
		return types.EvasionLevelAdvanced
	default:
		fmt.Printf("Warning: Unknown evasion level '%s', using 'medium' as default\n", level)
		return types.EvasionLevelMedium
	}
}
