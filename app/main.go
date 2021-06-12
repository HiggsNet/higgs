package main

import (
	"flag"

	higgs "github.com/Catofes/higgs/src"
)

func main() {
	configPath := flag.String("c", "higgs.hcl", "config path")
	flag.Parse()

	higgs.Run(*configPath)
}
