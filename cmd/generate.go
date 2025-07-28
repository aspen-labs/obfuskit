package cmd

import (
	"fmt"
	"obfuskit/internal/evasions"

	"github.com/spf13/cobra"
)

var attackType string
var payload string

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate evasive payloads for a given attack",
	Run: func(cmd *cobra.Command, args []string) {
		var evasive []string
		switch attackType {
		case "xss":
			evasive = evasions.EvadeXSS(payload)
		// case "sql":
		// 	evasive = evasions.EvadeSQL(payload)
		default:
			fmt.Println("Unsupported attack type")
			return
		}

		for _, ev := range evasive {
			fmt.Println(ev)
		}
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVarP(&attackType, "type", "t", "", "Attack type (e.g. xss, sql)")
	generateCmd.Flags().StringVarP(&payload, "payload", "p", "", "Payload to mutate")
}
