package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var attackType string
var payloadStr string
var outputFile string
var evasionLevel string
var encoding string

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate evasive payloads for a given attack (simple command)",
	Long: `Generate evasive payloads for a given attack type and payload.
This command is deprecated. Please use the simplified CLI flags instead.

Instead of:
  obfuskit generate -t xss -p '<script>alert(1)</script>'

Use:
  obfuskit -attack xss -payload '<script>alert(1)</script>'

Examples:
  obfuskit -attack xss -payload '<script>alert(1)</script>'
  obfuskit -attack sqli -payload "' OR 1=1 --" -level advanced
  obfuskit -attack xss -payload '<script>alert(1)</script>' -encoding unicode -output output.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("⚠️  This command is deprecated!")
		fmt.Println()
		fmt.Println("Please use the simplified CLI flags instead:")
		fmt.Println()

		if attackType != "" && payloadStr != "" {
			fmt.Printf("  obfuskit -attack %s -payload '%s'", attackType, payloadStr)
			if evasionLevel != "" && evasionLevel != "medium" {
				fmt.Printf(" -level %s", evasionLevel)
			}
			if encoding != "" {
				fmt.Printf(" -encoding %s", encoding)
			}
			if outputFile != "" {
				fmt.Printf(" -output %s", outputFile)
			}
			fmt.Println()
		} else {
			fmt.Println("  obfuskit -attack <type> -payload '<your-payload>'")
		}

		fmt.Println()
		fmt.Println("For help with the new CLI:")
		fmt.Println("  obfuskit -help")
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVarP(&attackType, "type", "t", "", "Attack type (xss, sqli, unixcmdi, wincmdi, path, fileaccess, ldapi)")
	generateCmd.Flags().StringVarP(&payloadStr, "payload", "p", "", "Payload to mutate")
	generateCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: console)")
	generateCmd.Flags().StringVarP(&evasionLevel, "level", "l", "medium", "Evasion level (basic, medium, advanced)")
	generateCmd.Flags().StringVarP(&encoding, "encoding", "e", "", "Specific encoding (url, html, unicode, base64, hex)")
}
