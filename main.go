package main

import (
	"fmt"
	"obfuskit/cmd"
	"obfuskit/evasions/command"
)

func main() {
	// cmd.Execute()
	// rand.Seed(time.Now().UnixNano())

	// variants := encoders.HexVariants("test 123 test : talkdjf", cmd.Medium)
	// variants = append(variants, encoders.Base64Variants("test", cmd.Medium)...)
	// variants := command.UnixCmdVariants("cat /etc/passwd", cmd.Medium)
	variants := command.WindowsCmdVariants("dir dir C:\\Windows\\System32", cmd.Medium)
	// Print variants one by one
	for _, variant := range variants {
		fmt.Println(variant)
	}
}
