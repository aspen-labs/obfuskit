package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "evasor",
	Short: "Evasor - Evasion Payload Generator for WAF Testing",
	Long:  `Evasor generates evasive variants of known attack payloads to test Web Application Firewalls (WAFs).`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
