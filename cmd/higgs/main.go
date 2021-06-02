package main

import (
	"os"

	"go.uber.org/zap"
)

//Version should be set at build.
var Version string

func main() {
	app := getApp()
	if err := app.Run(os.Args); err != nil {
		zap.S().Error(err)
		os.Exit(1)
	}
}
