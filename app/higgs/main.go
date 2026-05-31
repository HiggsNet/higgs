package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	cmd := rootCommand()
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
