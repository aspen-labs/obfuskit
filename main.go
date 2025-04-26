package main

import (
	"fmt"
	"math/rand"
	"obfuskit/cmd"
	"obfuskit/evasions/command"
	"time"
)

func main() {
	// cmd.Execute()
	rand.Seed(time.Now().UnixNano())

	// variants := encoders.HexVariants("test 123 test : talkdjf", cmd.Medium)
	// variants = append(variants, encoders.Base64Variants("test", cmd.Medium)...)
	variants := command.UnixCmdVariants("cat /etc/passwd", cmd.Medium)

	// Print variants one by one
	for _, variant := range variants {
		fmt.Println(variant)
	}
}
