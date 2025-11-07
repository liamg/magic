package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/liamg/magic"
)

func main() {
	if len(os.Args) != 2 {
		showUsageAndExit()
	}

	filename := os.Args[1]

	ft, err := magic.IdentifyPath(filename)
	if err != nil {
		fmt.Printf("\x1b[31mError identifying file: %s\x1b[0m\n", err)
		os.Exit(1)
	}

	fmt.Printf("File         \x1b[33m%s\x1b[0m\n", filepath.Base(filename))
	fmt.Printf("Description  \x1b[33m%s\x1b[0m\n", ft.Description)
	fmt.Printf("MIME         \x1b[33m%s\x1b[0m\n", ft.MIME)
	fmt.Printf("Icon         \x1b[33m%s\x1b[0m\n", ft.Icon)
}

func showUsageAndExit() {
	fmt.Println("Usage: magic <filename>")
	os.Exit(1)
}
